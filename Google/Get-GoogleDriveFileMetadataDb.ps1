<#
.SYNOPSIS
    - Stores/references Google .JSON keyfile from SecretStore vault
    - Generates access token & gets each user from Google Admin SDK Directory API
    - Get each user's drive file metadata from Google Drive API via parallel runspaces
    - Export all users' drive file metadata to SQLite database

.NOTES
    Name: Get-GoogleDriveFileMetadataDb.ps1
    Author: Payton Flint
    Version: 1.5
    DateCreated: 2024-Dec
    LastModified: 2025-Mar

.LINK
    https://github.com/p8nflnt/Cloud-Toolbox/blob/main/Google/Get-GoogleDriveFileMetadataDb.ps1
    https://paytonflint.com/cloud-return-enterprise-wide-google-drive-file-metadata-as-sql-database/
#>

# test if PowerShell version is 7 or greater (for ForEach-Object -Parallel support)
function Check-PsVersion {
    if ($psVersionTable.PSVersion.Major -ge 7) {
        Write-Host "PowerShell major version is 7 or greater."
        return $true
    } else {
        Write-Warning "PowerShell major version is less than 7."
        return $false
    }
}

# test if current session is running in elevated security context
Function Test-ElevatedShell {
    # Check if the current user has administrative privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Write-Host "Current session is running in elevated security context."
        return $true 
    } else {
        Write-Warning "Current session is not running in elevated security context."
        return $false
    }
}

# add NuGet as trusted package source
Function Add-NuGet {
    $package = Get-PackageSource -Name 'Nuget' -ErrorAction SilentlyContinue

    if ($package.IsTrusted -eq $False) {
        Write-Host "NuGet is installed, but is not trusted."
        Write-Host "Setting NuGet as trusted source."
        Set-PackageSource -Name 'Nuget' -Trusted -Force
    }
    elseif ($package -eq $null) {
        Write-Host "NuGet is not currently a registered source."
        Write-Host "Registering NuGet as trusted source."
        Register-PackageSource -Name Nuget -Location "https://www.nuget.org/api/v2" -ProviderName Nuget -Trusted -Force
    }
    else {
        Write-Host "NuGet is currently registered as a trusted source."
    }
}

# install SQLite executable using choco if not already
# return exe path
function Ensure-SQLite {
    param (
        [switch]$returnPath
    )
    # Check if SQLite is already installed
    $sqliteInstalled = (Get-Command sqlite3 -ErrorAction SilentlyContinue)
    if ($sqliteInstalled) {
        Write-Host "SQLite installed."
        if ($returnPath) { Write-Output $sqliteInstalled.Source }
        return
    } else {
        # Ensure Chocolatey is installed
        $chocoInstalled = (Get-Command choco -ErrorAction SilentlyContinue) -ne $null
        if (-not $chocoInstalled) {
            Write-Host "Installing Chocolatey..."
            Invoke-Expression (New-Object Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')
        }
        # Install SQLite using Chocolatey
        Write-Host "Installing SQLite..."
        choco install sqlite -y
        Write-Host "Setup complete. SQLite version: $(sqlite3 --version)" -ForegroundColor Cyan
    }
}

# ingests array of package names as strings
# finds .DLL file for a given package by name and loads assembly into current session
# note: assumes Win-x64 OS/architecture
Function Ensure-Assemblies {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$packageNames
    )

    # ingests package source parent path & outputs $true if assembly was loaded into current session
    # checks for runtimes and copies to lib dll parent folder
    function Handle-Package {
        param (
            $packageSource # ingests package source parent path
        )

        Write-Verbose "Checking for lib directory in $packageSource."

        # find package lib dir
        $libPath = Get-ChildItem -Path $packageSource -Directory -Filter 'lib*' | Select-Object -First 1

        if ($libPath) {

            Write-Verbose "Lib directory located at $libPath, searching for .DLL files."

            # search package source directory recursively for first *.DLL match
            $dllPath = $(Get-ChildItem -Path $libPath -Recurse -Filter '*.dll' | Where-Object { $_.FullName -notlike "*interop*" } | Select-Object -First 1).FullName
            
            # if .DLL is found...
            if ($dllPath) {

                Write-Verbose ".DLL found at $dllPath"

                # break out file name & parent directory
                $dllFileName = $dllPath | Split-Path -Leaf
                $dllParent = $dllPath | Split-Path

                # check for loaded assembly by file name
                $assemblies = [System.AppDomain]::CurrentDomain.GetAssemblies() # return all loaded assemblies
                $assembly = $assemblies.Where({$_.Location -and $_.Location -match $dllFileName}) # query assemblies for matches

                if (-not $assembly) {

                    Write-Verbose "Assembly not previously loaded into current session."

                    # check for runtimes directory
                    $runtimes = Get-ChildItem -Path $packageSource -Directory -Filter 'runtime?' | Select-Object -First 1

                    if ($runtimes) {

                        Write-Verbose "Runtimes directory found, searching for Windows x64 .DLL"
                        $runtimesChild = Get-ChildItem -Path $runtimes -Directory -Filter "Win*64" | Select-Object -First 1
                                
                        if ($runtimesChild) {

                            Write-Verbose "Windows x64 runtimes directory located at $runtimesChild, checking for .DLL file."
                            $runtimesDll = Get-ChildItem -Path $runtimesChild -Recurse -Filter *.dll | Select-Object -First 1

                            if ($runtimesDll) {

                                # get runtimes interoperability .DLL file name & build destination path to search
                                $runtimesDllName = $runtimesDll | Split-Path -Leaf
                                $runtimesDllTestPath = Join-Path $dllParent $runtimesDllName

                                Write-Verbose "Windows x64 interoperability .DLL located at $runtimesDll. Checking for .DLL at $runtimesDllTestPath"

                                # if runtimes interoperability .DLL is not at destination path, copy it to there
                                if (-not (Test-Path $runtimesDllTestPath)) {
                                    Write-Verbose "Windows x64 interoperability .DLL not located at $runtimesDllTestPath. Copying from $runtimesDll."
                                    Copy-Item -Path $runtimesDll -Destination $dllParent
                                }
                                else {
                                    Write-Verbose "Windows x64 interoperability .DLL located at $runtimesDllTestPath."
                                }
                            
                            }
                            else {
                                Write-Verbose "Windows x64 interoperability .DLL not found."
                            }

                        }
                        else {
                            Write-Verbose "Windows x64 runtime directory not found."
                        }

                    }
                    else {
                        Write-Verbose "No runtimes directory found."
                    }

                    # load assembly into current session
                    Write-Verbose "Loading assembly into current session."

                    try {
                        Add-Type -Path $dllPath -ErrorAction Stop
                        return $true
                    }
                    catch {
                        # support for core assemblies to be loaded
                        Import-Module $dllPath -ErrorAction Stop
                        return $true
                    }
                }
            }
            else {
                Write-Verbose "No .DLL files found in $packageSource."
            }
        }
    }
    
    # loop through packages in array
    forEach ($packageName in $packageNames) {

        # get package information
        $package = Get-Package $packageName -ErrorAction SilentlyContinue

        # if package not present, install- avoid dependency loops, if necessary.
        if (-not $package) {
            Write-Verbose "Package not found, downloading/installing."
            # install package
            try {
                Install-Package $packageName
            }
            catch {
                Install-Package $packageName -SkipDependencies
            }
            # get package information
            $package = Get-Package $packageName -ErrorAction SilentlyContinue
        } 
        
        # if package is installed...
        if ($package) {

            # get package source parent path
            $packageSource = $package.Source | Split-Path
            
            # attempt to load assembly from current package
            $assemblyInstalled = Handle-Package -packageSource $packageSource
            
            # if assembly was not loaded, check stub packages
            if (-not $assemblyInstalled) {

                # get nuget packages path to search for stub packages
                $nugetPackagesPath = Split-Path (Split-Path $package.Source -Parent) -Parent # get NuGet Packages path

                Write-Verbose "No .DLL file found in $($package.Source), checking for stub packages in $nugetPackagesPath."

                $stubPackages = (Get-ChildItem -Path $nugetPackagesPath -Directory -Filter "Stub.*$packageName*").FullName

                if ($stubPackages) {

                    Write-Verbose "Stub package(s) located."
                
                    # get appropriate stub package for PowerShell/.NET version
                    if ($psVersionTable.PsVersion.Major -ge 6) {
                        Write-Verbose "PowerShell version greater than 6, checking for appropriate stub package."
                        $versionStubPackage = $stubPackages | Where-Object { $_ -like "*NetStandard*" } | Select-Object -First 1
                    }
                    else {
                        Write-Verbose "PowerShell version less than 6, checking for appropriate stub package."
                        $versionStubPackage = $stubPackages | Where-Object { $_ -like "*NetFramework*" } | Select-Object -First 1
                    }
                    
                    # if version-appropriate stub package found...
                    if ($versionStubPackage) {
                        Write-Verbose "Stub package found at $versionStubPackage."
                        Handle-Package -packageSource $versionStubPackage | Out-Null
                    }
                    else {
                        Write-Verbose "No stub package found for current PowerShell version."
                    }
                }
            }
        }
        else {
            Write-Verbose "Package not found."
        }
        Write-Output "Assembly loaded for package: $packageName."
    }
}

# ingests array of module names as strings & installs if not already
Function Ensure-Modules {
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$moduleNames # names of modules to ensure as strings in array
    )

    foreach ($module in $moduleNames) {
        # Check if the module is already installed
        if (-not (Get-InstalledModule -Name $module -ErrorAction SilentlyContinue)) {
            Write-Host "Installing module: $module..."
            Install-Module -Name $module -Force -ErrorAction Stop
            Write-Host "$module module installed successfully."
        }
        else {
            Write-Host "$module module is already installed."
        }
    }
}

# ensure secret is present in secretStore vault & configuration for automated retrieval
Function Ensure-SecretStoreConfig { 
    param (
        [Parameter(Mandatory = $true)]
        [string]$secretName
    )

    # Register SecretStore vault if not already
    if (-not (Get-SecretVault | Where-Object { $_.Name -eq 'SecretStore' })) {
        Write-Host "SecretStore vault not found, registering..."
        Register-SecretVault -Name 'SecretStore' -ModuleName 'Microsoft.PowerShell.SecretStore' -DefaultVault
    }

    # Set SecretStore configuration for passwordless access if not already
    $secretStoreConfig = Get-SecretStoreConfiguration
    if ($secretStoreConfig.Authentication -ne 'None' -or $secretStoreConfig.Interaction -ne 'None') {
        Write-Host "Applying SecretStore configuration for passwordless access..."
        Set-SecretStoreConfiguration -Scope CurrentUser -Authentication None -Interaction None -Confirm:$false
    }
    
    # Check if the secret exists in the SecretStore
    if (Get-SecretInfo -Name $secretName -ErrorAction SilentlyContinue) {
        Write-Host "Secret '$secretName' found in SecretStore."
    }
    else {
        Write-Host "Secret '$secretName' not found in SecretStore."
        
        # Prompt user for JSON keyfile path
        $keyFilePath = Read-Host "Please enter the path to your Google JSON keyfile"

        if (Test-Path $keyFilePath) {
            # Read keyfile content and store it directly as a secret
            $keyfileContent = Get-Content -Path $keyFilePath -Raw

            # Store the JSON content in SecretStore
            Set-Secret -Name $secretName -Secret $keyfileContent

            Write-Host "Secret '$secretName' has been securely stored in SecretStore."
        }
        else {
            Write-Error "Invalid path provided. Please ensure the file exists and try again."
        }
    }
}

# retrieves token for user by email address
# security note: key file contents are unencrypted in memory temporarily during token generation
function Get-GoogleAccessToken {
    param (
        [Parameter(Mandatory = $true)]
        [string]$scope,                 # OAuth permission scope(s) - multiple scopes should be space-separated

        [Parameter(Mandatory = $true)]
        [secureString]$key,             # Key file contents from secureStore vault as SecureString

        [Parameter(Mandatory = $true)]
        [string]$user,                  # Subject - Email of the user to impersonate

        [int]$ttl = 3600                # Token time-to-live in seconds (3600 default)
    )

    # Function for Base64 URL-safe encoding
    function Encode-UrlBase64 {
        param([byte[]]$inputBytes)
        $base64 = [Convert]::ToBase64String($inputBytes).TrimEnd('=')
        $base64 = $base64.Replace('+', '-').Replace('/', '_')
        return $base64
    }

    try {
        # JWT Header
        $header = @{
            alg = "RS256"
            typ = "JWT"
        } | ConvertTo-Json -Compress

        # Get current & expiration times
        $now = [datetimeOffset]::UtcNow.ToUnixTimeSeconds()
        $exp = $now + $ttl

        # Convert SecureString to plaintext
        $keyPlainText = [System.Net.NetworkCredential]::new("", $key).Password
        $jsonContent = $keyPlainText | ConvertFrom-Json

        # Validate required fields in JSON
        if (-not $jsonContent.client_email -or -not $jsonContent.private_key) {
            throw "Invalid key file: Missing required fields."
        }

        $svcAcct = $jsonContent.client_email

        # JWT Payload
        $payload = @{
            iss   = $svcAcct
            scope = $scope
            aud   = "https://oauth2.googleapis.com/token"
            sub   = $user
            iat   = $now
            exp   = $exp
        } | ConvertTo-Json -Compress

        # Convert header & payload to Base64
        $headerBase64 = Encode-UrlBase64 -inputBytes ([System.Text.Encoding]::UTF8.GetBytes($header))
        $payloadBase64 = Encode-UrlBase64 -inputBytes ([System.Text.Encoding]::UTF8.GetBytes($payload))

        # Extract and clean private key
        $pvtKeyString = $jsonContent.private_key -replace "-----BEGIN PRIVATE KEY-----", "" -replace "-----END PRIVATE KEY-----", "" -replace "\s+", ""
        
        # Securely overwrite and clear sensitive variables
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($key))
        $keyPlainText = $null
        $jsonContent = $null

        # Convert private key to RSA format
        $pvtKeyBytes = [Convert]::FromBase64String($pvtKeyString)
        $pvtKeyString = $null # Clear after conversion

        # Load RSA private key using .NET RSA crypto
        $rsa = [System.Security.Cryptography.RSA]::Create()
        $rsa.ImportPkcs8PrivateKey($pvtKeyBytes, [ref]$null)
        $pvtKeyBytes = $null

        # Create unsigned JWT
        $unsignedJwt = "$headerBase64.$payloadBase64"

        # Sign JWT using RSA-SHA256
        $unsignedJwtBytes = [System.Text.Encoding]::UTF8.GetBytes($unsignedJwt)
        $signature = $rsa.SignData($unsignedJwtBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

        # Convert signature to URL-safe base64
        $signatureBase64 = Encode-UrlBase64 -inputBytes $signature
        $jwt = "$unsignedJwt.$signatureBase64"

        # Exchange JWT for access token
        $requestUri = "https://oauth2.googleapis.com/token"
        $body = @{
            grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"
            assertion  = $jwt
        }

        # POST JWT for access token
        $response = Invoke-RestMethod -Uri $requestUri -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"
        
        # Validate response
        if (-not $response.access_token) {
            throw "Failed to obtain access token."
        }

        return $response.access_token
    } catch {
        Write-Error "Error in Get-GoogleAccessToken: $_"
        return $null
    }
}


# Retrieve all users from Admin SDK, with an option to filter suspended users or orgUnits
Function Get-Users {
    param (
        [Parameter(Mandatory = $true)]
        [string]$user,                   # user to generate token for, impersonate, and retrieve user data

        [Parameter(Mandatory = $true)]
        [secureString]$key,              # key file contents from secureStore vault as secureString

        [switch]$Suspended,              # gets suspended users only
        [switch]$IgnoreNeverSignedIn,    # ignore users that have never signed into the platform
        [string[]]$IgnoreOrgUnits        # Accepts an array of Org Units to ignore
    )

    Write-Host "Retrieving user list from Google."

    # Provide oauth scope for token creation
    $tokenScope = "https://www.googleapis.com/auth/admin.directory.user.readonly"

    # Get new access token from Google for user
    $accessToken = Get-GoogleAccessToken -scope $tokenScope -key $key -user $user

    do {
        # build & append query to url
        $url = "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=500&projection=full"
        if ($Suspended) { 
            $query = "&query=isSuspended=true"
            $url += $query
        }

        # append next page token if present
        if ($nextPageToken) { $url += "&pageToken=$nextPageToken" }

        $response = Invoke-RestMethod -Uri $url -Headers @{
            Authorization = "Bearer $accessToken"
            Accept        = "application/json"
        } -Method Get

        # Apply filtering
        $filteredUsers = $response.users
        # Filter out users who have never signed in if the switch is specified
        if ($IgnoreNeverSignedIn) { $filteredUsers = $filteredUsers.Where({ $_.lastLoginTime -and $_.lastLoginTime -ne "1/1/1970 12:00:00 AM"}) }
        # Filter out users belonging to specified Org Units
        if ($IgnoreOrgUnits) { $filteredUsers = $filteredUsers.Where({ $_.orgUnitPath -notin $IgnoreOrgUnits }) }

        # handle nextPage token from response
        $nextPageToken = $response.nextPageToken

        # output filtered users
        Write-Output $filteredUsers

    } while ($nextPageToken)
}

# converts datetimes to SQLite-friendly ISO8601 standard
function ConvertTo-ISO8601 {
    param (
        [Parameter(Mandatory = $true)]
        [string]$date
    )
    # trim whitespace
    $date = $date.Trim()

    if ($date -and $date -match '/') {

        # split date using forward slashes
        $splitDate = $date -split '/', 3

        # get day & month length by index
        $monthLength = $($splitDate[0]).Length
        $dayLength = $($splitDate[1]).Length

        # build month, day, & format
        $i = 0; while ($i -lt $monthLength) { $i++; $month += 'M' }; $i = $null
        $i = 0; while ($i -lt $dayLength) { $i++; $day += 'd'; }; $i = $null

        # detect am/pm & build format accordingly for 12 or 24 hr time support
        if ($date -match "AM|PM") {
            $format = "$month`/$day`/yyyy h:mm:ss tt"  # 12-hour format
        }
        else {
            $format = "$month`/$day`/yyyy H:mm:ss"  # 24-hour format
        }

        # Convert the date string to a DateTime object
        $dateTime = [DateTime]::ParseExact($date, $format, $null)

        # Convert to ISO 8601 format: YYYY-MM-DD HH:MM:SS
        return $dateTime.ToString("yyyy-MM-ddTHH:mm:ss")
    }
}

# Query Google for user-owned drive files
function Get-UserOwnedDriveFileMetadata {
    param (
        [Parameter(Mandatory = $true)]
        $user,                          # user returned from Get-Users function

        [Parameter(Mandatory = $true)]
        [secureString]$key,             # key file contents from secureStore vault as secureString

        [string]$ModifiedAfter,         # DateTime in format "yyyy-MM-ddTHH:mm:ssZ"
        [string]$ModifiedBefore,        # DateTime in format "yyyy-MM-ddTHH:mm:ssZ"
        [bool]$Shared,                  # Return shared files
        [bool]$lastModifiedByOwner      # Return files last modified by owner (impersonated user)
    )

    # oauth token scope for access token generation
    $tokenScope = "https://www.googleapis.com/auth/drive.metadata.readonly"

    # generate access token for user
    $accessToken = Get-GoogleAccessToken -scope $tokenScope -key $key -user $user.primaryEmail

    # Build query
    $query = "'me' in owners" # Add ownership filter
    # Convert dates and build query components only if parameters are specified
    if ($ModifiedAfter)  { $query += " and modifiedTime > '$ModifiedAfter'"  }
    if ($ModifiedBefore) { $query += " and modifiedTime < '$ModifiedBefore'" }
    $query = "q=" + [System.Uri]::EscapeDataString($query) # construct URL-safe encoded query

    # Construct the base URI
    $baseUri = "https://www.googleapis.com/drive/v3/files"
    $pageSizeParam = "pageSize=1000"
    $fieldsParam = "fields=nextPageToken,files(id,name,owners,size,lastModifyingUser,modifiedTime,shared)"
    $files = New-Object 'System.Collections.Generic.List[object]'
    $pageToken = $null

    do {
        # Construct URI for this iteration
        $uri = "$baseUri`?$query`&$fieldsParam`&$pageSizeParam"
        if ($pageToken) {
            $uri += "&pageToken=$pageToken"
        }

        # Make the API call
        try {
            $response = Invoke-RestMethod -Uri $uri `
                -Headers @{ "Authorization" = "Bearer $AccessToken" } `
                -Method Get
            $files.AddRange($response.files)
        
            $pageToken = $response.nextPageToken
        }
        catch {
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        
            # Check if Response exists and try to capture the content early
            if ($_.Exception.Response -is [System.Net.Http.HttpResponseMessage]) {
                $responseObject = $_.Exception.Response
                try {
                    $responseBody = $responseObject.Content.ReadAsStringAsync().Result
                    Write-Host "Response Body: $responseBody" -ForegroundColor Red
                }
                catch {
                    Write-Host "Unable to read response content." -ForegroundColor Yellow
                }
            }
            else {
                Write-Host "No response content available." -ForegroundColor Yellow
            }
            break
        }        
    } while ($pageToken)

    ForEach ($file in $files) {
        # Extract usable information from nested properties and write as single property
        $file | Add-Member -MemberType NoteProperty -Name Owner -Value $file.Owners[0].EmailAddress -Force
        $file | Add-Member -MemberType NoteProperty -Name LastModifiedByOwner -Value $file.lastModifyingUser.me -Force
        
        # add ownerLastLogin to files
        $file | Add-Member -MemberType NoteProperty -Name ownerLastLogin -Value $user.lastLoginTime -Force

        # convert datetimes to ISO8601 standard (sqlite-friendly)
        $file.modifiedTime = ConvertTo-ISO8601 -date $file.modifiedTime
        $file.ownerLastLogin = ConvertTo-ISO8601 -date $file.ownerLastLogin
    }

    # Filter for shared files
    if    ($Shared -eq $false) { $files = $files.Where({ $_.shared -eq $false}) }
    elseif ($Shared -eq $true) { $files = $files.Where({ $_.shared -eq $true})  }

    # Filter for lastModifiedByOwner
    if     ($lastModifiedByOwner -eq $false) { $files = $files.Where({ $_.LastModifiedByOwner -eq $false}) }
    elseif ($lastModifiedByOwner -eq $true)  { $files = $files.Where({ $_.LastModifiedByOwner -eq $true)}  }

    # Return results
    return $files | Select-Object -Property Id, Name, Size, Owner, OwnerLastLogin, LastModifiedByOwner, ModifiedTime, Shared
}

# Import array of objects into SQLite database, using WAL journal_mode
# Requires 'System.Data.Sqlite.Core' NuGet package
function Import-SQLiteData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$dbPath,

        [Parameter(Mandatory = $true)]
        [string]$tableName,

        [Parameter(Mandatory = $true)]
        [object[]]$data,

        [int]$BusyTimeout = 1800000 # Default timeout
    )

    if (-not $data -or $data.Count -eq 0) {
        Write-Error "Error: No data provided for import."
        return
    }

    # Handle null values when determining column types
    $columns = $data[0].PSObject.Properties.Name
    $columnDefs = @{}

    foreach ($col in $columns) {
        $value = $data[0].$col
        $colType = if ($value -eq $null) { 
            "TEXT"  # Default to TEXT if the first value is null
        } else {
            switch ($value.GetType().Name) {
                "Int32" { "INTEGER" }
                "Int64" { "INTEGER" }
                "Double" { "REAL" }
                "Decimal" { "REAL" }
                "Boolean" { "INTEGER" }
                "DateTime" { "TEXT" }
                "String" { if ($value -match '^(TRUE|FALSE)$') { "INTEGER" } else { "TEXT" } }
                default { "TEXT" }
            }
        }
        $columnDefs[$col] = $colType
    }

    $columnsSql = ($columns | ForEach-Object { "`"$_`"" }) -join ", "
    $columnDefsSql = ($columnDefs.GetEnumerator() | ForEach-Object { "`"$($_.Key)`" $($_.Value)" }) -join ", "

    # Open SQLite connection
    Write-Verbose "Opening SQLite connection..."
    $connectionString = "Data Source=$dbPath;Version=3;"
    $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)

    if (-not $connection) {
        Write-Error "Error: SQLite connection could not be created."
        return
    }

    try {
        $connection.Open()
        if (-not $connection.State -eq "Open") {
            Write-Error "Error: SQLite connection failed to open."
            return
        }
        Write-Verbose "SQLite connection opened successfully."

        # Set WAL mode first
        Write-Verbose "Enabling WAL mode..."
        $walCmd = $connection.CreateCommand()
        $walCmd.CommandText = "PRAGMA journal_mode=WAL;"
        $walCmd.ExecuteNonQuery() | Out-Null
        $walCmd.Dispose()

        # Set busy_timeout
        Write-Verbose "Setting busy timeout to $BusyTimeout ms..."
        $timeoutCmd = $connection.CreateCommand()
        $timeoutCmd.CommandText = "PRAGMA busy_timeout = $BusyTimeout;"
        $timeoutCmd.ExecuteNonQuery() | Out-Null
        $timeoutCmd.Dispose()

        # Set SQLite to use OFF sync mode to reduce lock contention
        Write-Verbose "Setting synchronous mode to OFF..."
        $syncCmd = $connection.CreateCommand()
        $syncCmd.CommandText = "PRAGMA synchronous = OFF;"
        $syncCmd.ExecuteNonQuery() | Out-Null
        $syncCmd.Dispose()

        # Create table if it doesn't exist
        Write-Verbose "Checking table existence..."
        $createTableCmd = $connection.CreateCommand()
        if ($createTableCmd) {
            $createTableCmd.CommandText = "CREATE TABLE IF NOT EXISTS [$tableName] ($columnDefsSql);"
            $createTableCmd.ExecuteNonQuery() | Out-Null
            $createTableCmd.Dispose()
        }

        # Prepare insert command BEFORE opening transaction
        Write-Verbose "Preparing insert command..."
        $insertCmd = $connection.CreateCommand()
        if (-not $insertCmd) {
            Write-Error "Error: insertCmd is null." 
            return
        }
        $placeholders = ($columns | ForEach-Object { "@" + $_ }) -join ", "
        $insertCmd.CommandText = "INSERT INTO [$tableName] ($columnsSql) VALUES ($placeholders);"

        foreach ($col in $columns) {
            $param = $insertCmd.CreateParameter()
            $param.ParameterName = "@$col"
            $insertCmd.Parameters.Add($param) | Out-Null
        }
        Write-Verbose "Insert command prepared successfully."

        # Start transaction AFTER insert command is built
        Write-Verbose "Starting transaction..."
        $transaction = $connection.BeginTransaction()
        if (-not $transaction) {
            Write-Error "Error: Failed to start transaction."
            return
        }
        Write-Verbose "Transaction started successfully."

        # Ensure `null` values do not cause errors during insertion
        Write-Verbose "Starting data insertion..."
        foreach ($row in $data) {
            foreach ($col in $columns) {
                $insertCmd.Parameters["@${col}"].Value = if ($row.$col -eq $null) { 
                    [DBNull]::Value  # Ensure SQLite understands nulls
                } else {
                    switch ($row.$col) {
                        { $_ -is [bool] } { if ($_) { 1 } else { 0 } }
                        { $_ -is [string] -and $_ -match '^(TRUE|FALSE)$' } { if ($_ -eq "TRUE") { 1 } else { 0 } }
                        { $_ -is [string] -and $_ -eq "" } { 0 }
                        default { $_ }
                    }
                }
            }

            try {
                if ($insertCmd) {
                    $insertCmd.ExecuteNonQuery() | Out-Null
                } else {
                    Write-Error "Error: insertCmd is null during execution."
                    return
                }
            } catch {
                Write-Error "Error during data insertion: $_"
                return
            }
        }
        Write-Verbose "Data insertion complete."

        # Commit transaction
        Write-Verbose "Committing transaction..."
        if ($transaction) {
            $transaction.Commit()
            Write-Verbose "Transaction committed successfully."
        } else {
            Write-Error "Error: transaction is null before commit."
            return
        }
    } catch {
        Write-Error "Error importing data: $_. Exception Message: $($_.Exception.Message)"
    } finally {
        # clean up
        Write-Verbose "Cleaning up resources..."
        if ($insertCmd) { 
            $insertCmd.Dispose() 
        }
        if ($transaction) { 
            $transaction.Dispose() 
        }
        if ($connection) { 
            $connection.Close()
            $connection.Dispose()
        }
        Write-Verbose "Cleanup completed."
    }
}

# get function definitions to pass to scriptblock isolated sessionState
$ensureAssembliesFunc              = ${function:Ensure-Assemblies}.ToString()
$getGoogleAccessTokenFunc          = ${function:Get-GoogleAccessToken}.ToString()
$convertToIso8601Func              = ${function:ConvertTo-ISO8601}.ToString()
$getUserOwnedDriveFileMetadataFunc = ${function:Get-UserOwnedDriveFileMetadata}.ToString()
$importSqliteDataFunc              = ${function:Import-SQLiteData}.ToString()

# scriptBlock for invocation with ForEach-Object -Parallel
$scriptBlock = {
    # invoke functions within isolated sessionState
    ${function:Ensure-Assemblies}              = $using:ensureAssembliesFunc
    ${function:Get-GoogleAccessToken}          = $using:getGoogleAccessTokenFunc
    ${function:ConvertTo-ISO8601}              = $using:convertToIso8601Func
    ${function:Get-UserOwnedDriveFileMetadata} = $using:getUserOwnedDriveFileMetadataFunc
    ${function:Import-SQLiteData}              = $using:importSqliteDataFunc

    # load req assemblies
    Ensure-Assemblies -packageNames $using:reqAssemblies | Out-Null

    # get user file metadata via Google API call
    $files = Get-UserOwnedDriveFileMetadata -user $_ -key $using:key -Shared:$false -LastModifiedByOwner:$true

    # if files are found, chunk and write to db
    $fileCount = 0
    if ($files) { 
        $fileCount = $files.Count
                
        # chunk files into batches <= 10000 (prevents prolonged db table locks halting runspace queue)
        $chunkMax = 10000
        for ($i = 0; $i -lt $files.Count; $i += $chunkMax) {
            $chunk = $files[$i..([math]::Min($i + $chunkMax - 1, $files.Count - 1))]

            if ($chunk) {
                Write-Host "Writing metadata for $($chunk.count) files to $using:dbPath at $(Get-Date)" -ForegroundColor Cyan
                # write chunk to db
                Import-SQLiteData -dbPath $using:dbPath -tableName 'data' -data $chunk
            }
        }
    }
    Write-Host "Retrieved metadata for $fileCount files for user: $($_.primaryEmail) at $(Get-Date)"
}

$keySecretName  = '<SecretName>'     # secret name in SecretStore vault which contains Google service acct .json key
$initUser       = '<EmailAddress>'   # User for retrieving user data
$ignoreOrgUnits = @('</OrgUnit>')    # org units to exclude in user query
$dbPath         = '<FilePath>'       # .db out file path (sqlite)
$throttleLimit  = 16                 # Set max # of concurrent runspaces

# only proceed if >= pwsh v7 (ForEach-Object -Parallel support)
if (Check-PsVersion) {

    # only proceed if executed with elevated privileges (req by SQLite)
    if (Test-ElevatedShell) {

        # Capture start time
        $startTime = Get-Date

        # Add NuGet as trusted repository if not already
        Add-NuGet

        # Install SQLite if not already
        Ensure-SQLite

        # ensure required assemblies are loaded into current session
        $reqAssemblies = @('System.Data.Sqlite.Core')
        Ensure-Assemblies -packageNames $reqAssemblies

        # ensure module dependencies are present
        $reqModules = @('Microsoft.PowerShell.SecretManagement', 'Microsoft.PowerShell.SecretStore')
        Ensure-Modules -moduleNames $reqModules

        # ensure key file contents are present in secretStore vault & configured for automated retrieval
        Ensure-SecretStoreConfig -secretName $keySecretName

        # retrieve secret from vault as secure string
        $key = Get-Secret -Name $keySecretName

        # Retrieve all suspended users who have signed in previously, ignoring those who have never signed in & specified OU
        Get-Users -key $key -user $initUser -Suspended -IgnoreNeverSignedIn -IgnoreOrgUnits $ignoreOrgUnits `
        | ForEach-Object -Parallel $scriptBlock -ThrottleLimit $throttleLimit # invoke scriptblock with parallel runspaces

        # Capture end time and calculate duration
        $endTime = Get-Date
        $duration = $endTime - $startTime
        Write-Host "Total execution time: $($duration.Hours)h $($duration.Minutes)m $($duration.Seconds)s"
    }
}
