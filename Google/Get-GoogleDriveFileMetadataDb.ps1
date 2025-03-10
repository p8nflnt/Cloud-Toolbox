<#
.SYNOPSIS
    - Get each user from Google Workspace via API
    - Get each user's drive file metadata from Google via API
    - Export all users' drive file metadata to SQLite database

.NOTES
    Name: Get-GoogleDriveFileMetadataDb.ps1
    Author: Payton Flint
    Version: 1.4
    DateCreated: 2024-Dec
    LastModified: 2025-Mar

.LINK
    https://github.com/p8nflnt/Cloud-Toolbox/blob/main/Google/Get-GoogleDriveFileMetadataDb.ps1
    https://paytonflint.com/cloud-return-enterprise-wide-google-drive-file-metadata-as-sql-database/
#>

# test if current session is running in elevated security context
Function Test-ElevatedShell {
    # Check if the current user has administrative privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Warning "Current session is not running in elevated security context."
        return $false
    } else {
        Write-Host "Current session is running in elevated security context."
        return $true 
    }
}

# add NuGet as trusted package source
Function Add-NuGet {
    $package = Get-PackageSource -Name 'Nuget' -ErrorAction SilentlyContinue

    if ($package.IsTrusted -eq $False) {
        Write-Host "NuGet is installed, but is not trusted."
        Write-Host "Setting NuGet as trusted source."
        Set-PackageSource -Name 'Nuget' -Trusted -Force
    } elseif ($package -eq $null) {
        Write-Host "NuGet is not currently a registered source."
        Write-Host "Registering NuGet as trusted source."
        Register-PackageSource -Name Nuget -Location "https://www.nuget.org/api/v2" -ProviderName Nuget -Trusted -Force
    } else {
        Write-Host "NuGet is currently registered as a trusted source."
    }
}

# install SQLite executable using Chocolatey
function Install-SQLite {
    # Check if SQLite is already installed
    $sqliteInstalled = (Get-Command sqlite3 -ErrorAction SilentlyContinue) -ne $null
    if (-not $sqliteInstalled) {
        # Ensure script is run as admin
        if (Test-ElevatedShell) {
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
            $dllPath = $(Get-ChildItem -Path $libPath -Recurse -Filter '*.dll' | Where-Object {$_.FullName -notlike "*interop*"} | Select-Object -First 1).FullName
            
            # if .DLL is found...
            if ($dllPath) {

                Write-Verbose ".DLL found at $dllPath"

                # break out file name & parent directory
                $dllFileName = $dllPath | Split-Path -Leaf
                $dllParent = $dllPath | Split-Path

                # check for loaded assembly by file name
                $assemblies = [System.AppDomain]::CurrentDomain.GetAssemblies() # return all loaded assemblies
                $assembly = $assemblies | Where-Object { $_.Location -and $_.Location -match $dllFileName } # query assemblies for matches

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
                                if (-not (Test-Path $runtimesDllTestPath)){
                                    Write-Verbose "Windows x64 interoperability .DLL not located at $runtimesDllTestPath. Copying from $runtimesDll."
                                    Copy-Item -Path $runtimesDll -Destination $dllParent
                                } else {
                                    Write-Verbose "Windows x64 interoperability .DLL located at $runtimesDllTestPath."
                                }
                            
                            } else {
                                Write-Verbose "Windows x64 interoperability .DLL not found."
                            }

                        } else {
                            Write-Verbose "Windows x64 runtime directory not found."
                        }

                    } else {
                        Write-Verbose "No runtimes directory found."
                    }

                    # load assembly into current session
                    Write-Verbose "Loading assembly into current session."

                    try {
                        Add-Type -Path $dllPath -ErrorAction Stop
                        return $true
                    } catch {
                        # support for core assemblies to be loaded
                        Import-Module $dllPath -ErrorAction Stop
                        return $true
                    }
                }
            } else {
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
            } catch {
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
                        $versionStubPackage = $stubPackages | Where-Object {$_ -like "*NetStandard*"} | Select-Object -First 1
                    } else {
                        Write-Verbose "PowerShell version less than 6, checking for appropriate stub package."
                        $versionStubPackage = $stubPackages | Where-Object {$_ -like "*NetFramework*"} | Select-Object -First 1
                    }
                    
                    # if version-appropriate stub package found...
                    if ($versionStubPackage) {
                        Write-Verbose "Stub package found at $versionStubPackage."
                        Handle-Package -packageSource $versionStubPackage | Out-Null
                    } else {
                        Write-Verbose "No stub package found for current PowerShell version."
                    }
                }
            }
        } else {
            Write-Verbose "Package not found."
        }
        Write-Host "Assembly loaded for package $packageName."
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
        } else {
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
    } else {
        Write-Host "Secret '$secretName' not found in SecretStore."
        
        # Prompt user for JSON keyfile path
        $keyFilePath = Read-Host "Please enter the path to your Google JSON keyfile"

        if (Test-Path $keyFilePath) {
            # Read keyfile content and store it directly as a secret
            $keyfileContent = Get-Content -Path $keyFilePath -Raw

            # Store the JSON content in SecretStore
            Set-Secret -Name $secretName -Secret $keyfileContent

            Write-Host "Secret '$secretName' has been securely stored in SecretStore."
        } else {
            Write-Error "Invalid path provided. Please ensure the file exists and try again."
        }
    }
}

# retrieves token for user by email address
# requires BouncyCastle for crypto
# requires SecretStore/SecretManagement modules
# security note: key file contents are unencrypted in memory temporarily during token generation
function Get-GoogleAccessToken {
    param (
        [Parameter(Mandatory = $true)]
        [string]$scope,                # OAuth permission scope(s) - multiple scopes should be space-separated

        [Parameter(Mandatory = $true)]
        [string]$keySecretName,        # Secret name which contains the the Google service account key file content

        [Parameter(Mandatory = $true)]
        [string]$user,                 # Subject - Email of the user to impersonate

        [int]$ttl = 3600               # Token time-to-live in seconds (3600 default)
    )

    # Retrieve JSON keyfile content from SecretManagement as SecureString
    $secureKeyFileContent = Get-Secret -Name $keySecretName

    if (-not $secureKeyFileContent) {
        Write-Error "Error: Failed to retrieve keyfile content from secret store."
        return
    }

    # Convert SecureString to plain text JSON
    $plainKeyFileContent = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKeyFileContent)
    )

    # Parse JSON to extract necessary information
    $jsonContent = $plainKeyFileContent | ConvertFrom-Json
    $svcAcct = $jsonContent.client_email

    # JWT Header
    $header = @{
        alg = "RS256"
        typ = "JWT"
    } | ConvertTo-Json | Out-String

    # JWT Payload
    $now = [int](Get-Date -Date (Get-Date).ToUniversalTime() -UFormat %s)
    $exp = $now + $ttl # Token expiration
    $payload = @{
        iss   = $svcAcct 
        scope = $scope # OAuth permission scope(s)
        aud   = "https://oauth2.googleapis.com/token" # Audience
        sub   = $user # Email of the user to impersonate
        iat   = [math]::floor((Get-Date).ToUniversalTime().Subtract([datetime]'1970-01-01').TotalSeconds)
        exp   = [math]::floor((Get-Date).ToUniversalTime().AddSeconds($ttl).Subtract([datetime]'1970-01-01').TotalSeconds)
    } | ConvertTo-Json -Compress

    # Function for Base64 URL-safe encoding
    function Encode-UrlBase64 {
        param([byte[]]$inputBytes)
        $base64 = [Convert]::ToBase64String($inputBytes).TrimEnd('=')
        $base64 = $base64.Replace('+', '-').Replace('/', '_')
        return $base64
    }

    # Convert Header and Payload to Base64
    $headerBase64 = Encode-UrlBase64 -inputBytes ([System.Text.Encoding]::UTF8.GetBytes($header))
    $payloadBase64 = Encode-UrlBase64 -inputBytes ([System.Text.Encoding]::UTF8.GetBytes($payload))

    # Extract private key from JSON file
    $pvtKeyString = $jsonContent.private_key -replace "-----BEGIN PRIVATE KEY-----", "" -replace "-----END PRIVATE KEY-----", "" -replace "\s+", ""
    $pvtKeyBytes = [Convert]::FromBase64String($pvtKeyString)

    # Convert the private key into an RSA key using BouncyCastle's PrivateKeyFactory
    $pvtKeyInfo = [Org.BouncyCastle.Asn1.Pkcs.PrivateKeyInfo]::GetInstance($pvtKeyBytes)
    $pvtKey = [Org.BouncyCastle.Security.PrivateKeyFactory]::CreateKey($pvtKeyInfo)

    # Create the signer object for RSA/SHA256
    $signer = New-Object Org.BouncyCastle.Crypto.Signers.RsaDigestSigner ([Org.BouncyCastle.Crypto.Digests.Sha256Digest]::new())
    $signer.Init($true, $pvtKey)

    # Create the unsigned JWT
    $unsignedJwt = "$headerBase64.$payloadBase64"

    # Sign the JWT
    $signer.BlockUpdate([System.Text.Encoding]::UTF8.GetBytes($unsignedJwt), 0, $unsignedJwt.Length)
    $signature = $signer.GenerateSignature()

    # Convert signature to URL-safe base64
    $signatureBase64 = Encode-UrlBase64 -inputBytes $signature
    $jwt = "$unsignedJwt.$signatureBase64"

    # Exchange the JWT for an access token
    $requestUri = "https://oauth2.googleapis.com/token"
    $body = @{
        grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"
        assertion  = $jwt
    }

    # POST JWT for access token
    $response = Invoke-RestMethod -Uri $requestUri -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"

    # Output the access token
    return $response.access_token  
}

# Retrieve all users from Admin SDK, with an option to filter suspended users or orgUnits
Function Get-Users {
    param (
        [Parameter(Mandatory = $true)]
        [string]$user,                 # user to generate token for, impersonate, and retrieve user data

        [Parameter(Mandatory = $true)]
        [string]$keySecretName,        # Secret name which contains the the Google service account key file content

        [switch]$Suspended,
        [switch]$IgnoreNeverSignedIn,
        [string[]]$IgnoreOrgUnits  # Accepts an array of Org Units to ignore
    )

    Write-Host "Retrieving user list from Google."

    # Provide oauth scope for token creation
    $tokenScope = "https://www.googleapis.com/auth/admin.directory.user.readonly"

    # Get new access token from Google for user
    $accessToken = Get-GoogleAccessToken -scope $tokenScope -keySecretName $keySecretName -user $user

    #initialization
    $users = @()

    do {
        $url = "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=500&projection=full"

        # Add query filter for suspended users if the switch is specified
        if ($Suspended) {
            $url += "&query=isSuspended=true"
        }

        if ($nextPageToken) {
            $url += "&pageToken=$nextPageToken"
        }

        $response = Invoke-RestMethod -Uri $url -Headers @{
            Authorization = "Bearer $accessToken"
            Accept        = "application/json"
        } -Method Get

        # Apply filtering
        $filteredUsers = $response.users

        # Filter out users who have never signed in if the switch is specified
        if ($IgnoreNeverSignedIn) {
            $filteredUsers = $filteredUsers | Where-Object { $_.lastLoginTime -and $_.lastLoginTime -ne "1/1/1970 12:00:00 AM" }
        }

        # Filter out users belonging to specified Org Units
        if ($IgnoreOrgUnits) {
            $filteredUsers = $filteredUsers | Where-Object { $_.orgUnitPath -notin $IgnoreOrgUnits }
        }

        $users += $filteredUsers
        $nextPageToken = $response.nextPageToken

    } while ($nextPageToken)

    return $users
}

# converts datetimes to SQLite-friendly ISO8601 standard
function Convert-ToISO8601 {
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
        $dayLength   = $($splitDate[1]).Length

        # build month, day, & format
        $i = 0; while ($i -lt $monthLength) { $i++; $month += 'M' };  $i = $null
        $i = 0; while ($i -lt $dayLength)   { $i++; $day += 'd'; };   $i = $null

        # detect am/pm & build format accordingly for 12 or 24 hr time support
        if ($date -match "AM|PM") {
            $format = "$month`/$day`/yyyy h:mm:ss tt"  # 12-hour format
        } else {
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
        [string]$keySecretName,         # Secret name which contains the the Google service account key file content

        [string]$ModifiedAfter,         # DateTime in format "yyyy-MM-ddTHH:mm:ssZ"
        [string]$ModifiedBefore,        # DateTime in format "yyyy-MM-ddTHH:mm:ssZ"
        [bool]$Shared,                  # Return shared files
        [bool]$lastModifiedByOwner      # Return files last modified by owner (impersonated user)
    )

    # oauth token scope for access token generation
    $tokenScope = "https://www.googleapis.com/auth/drive.metadata.readonly"

    # generate access token for user
    $accessToken = Get-GoogleAccessToken -scope $tokenScope -keySecretName $keySecretName -user $user.primaryEmail

    # Initialize query components
    $query = @()

    # Add ownership filter
    $query += "'me' in owners"

    # Convert dates and build query components only if parameters are specified
    if ($ModifiedAfter) {
        $query += "modifiedTime > '$ModifiedAfter'"
    }
    if ($ModifiedBefore) {
        $query += "modifiedTime < '$ModifiedBefore'"
    }

    # Determine if a query is needed
    $queryString = if ($query.Count -gt 0) {
        "q=" + [System.Uri]::EscapeDataString($query -join " and ")
    } else { "" }

    # Construct the base URI
    $baseUri     = "https://www.googleapis.com/drive/v3/files"
    $fieldsParam = "fields=nextPageToken,files(id,name,owners,size,lastModifyingUser,modifiedTime,shared)"
    $files       = @()
    $pageToken   = $null

    do {
        # Construct URI for this iteration
        $uri = if ($queryString -ne "") {
            "$baseUri`?$queryString`&$fieldsParam"
        } else {
            "$baseUri`?$fieldsParam"
        }
        if ($pageToken) {
            $uri += "&pageToken=$pageToken"
        }

        # Make the API call
        try {
            $response = Invoke-RestMethod -Uri $uri `
                                          -Headers @{ "Authorization" = "Bearer $AccessToken" } `
                                          -Method Get
            $files += $response.files
        
            $pageToken = $response.nextPageToken
        } catch {
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        
            # Check if Response exists and try to capture the content early
            if ($_.Exception.Response -is [System.Net.Http.HttpResponseMessage]) {
                $responseObject = $_.Exception.Response
                try {
                    $responseBody = $responseObject.Content.ReadAsStringAsync().Result
                    Write-Host "Response Body: $responseBody" -ForegroundColor Red
                } catch {
                    Write-Host "Unable to read response content." -ForegroundColor Yellow
                }
            } else {
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
        $file.modifiedTime   = Convert-ToISO8601 -date $file.modifiedTime
        $file.ownerLastLogin = Convert-ToISO8601 -date $file.ownerLastLogin
    }

    # Filter for shared files
    if ($Shared -eq $false) {
        $files = $files | Where-Object { $_.shared -eq $false }
    } elseif ($Shared -eq $true) {
        $files = $files | Where-Object { $_.shared -eq $true }
    }

    # Filter for lastModifiedByOwner
    if ($lastModifiedByOwner -eq $false) {
        $files = $files | Where-Object { $_.LastModifiedByOwner -eq $false }
    } elseif ($lastModifiedByOwner -eq $true) {
        $files = $files | Where-Object { $_.LastModifiedByOwner -eq $true }
    }

    # Return results
    return $files | Select-Object -Property Id, Name, Size, Owner, OwnerLastLogin, LastModifiedByOwner, ModifiedTime, Shared
}

# import array of objects to sqlite database, minding data types
# requires 'System.Data.Sqlite.Core' NuGet package
function Import-SQLiteData {
    param (
        [Parameter(Mandatory = $true)]
        [string]$dbPath,                     # Path to the SQLite database file

        [Parameter(Mandatory = $true)]
        [string]$tableName,                  # Table name to insert data into

        [Parameter(Mandatory = $true)]
        [object[]]$data                      # Array of objects to import
    )

    # Create and open SQLite connection
    $connectionString = "Data Source=$dbPath;Version=3;"
    $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)

    if (-not $connection) {
        Write-Error "Error: Failed to create SQLite connection (null)."
        return
    }

    try {
        $connection.Open()
    } catch {
        Write-Error "Error: Failed to open SQLite connection. $_"
        return
    }

    try {
        # Extract properties from the first object to define columns
        $columns = $data[0].PSObject.Properties.Name
        $columnDefs = @()

        foreach ($col in $columns) {
            # Handle null values in the first row by defaulting to TEXT type
            $value = $data[0].$col
            if ($value -eq $null) {
                $colType = "TEXT"
            } else {
                $colType = switch ($value.GetType().Name) {
                    "Int32" { "INTEGER" }
                    "Int64" { "INTEGER" }
                    "Double" { "REAL" }
                    "Decimal" { "REAL" }
                    "Boolean" { "INTEGER" }
                    "DateTime" { "TEXT" }
                    "String" {
                        if ($value -match '^(TRUE|FALSE)$') { "INTEGER" } # Convert TRUE/FALSE strings to INTEGER
                        elseif ($value -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$') { "TEXT" } # ISO 8601 date
                        else { "TEXT" }
                    }
                    default { "TEXT" }
                }
            }
            $columnDefs += "`"$col`" $colType"
        }

        $columnsSql = ($columns | ForEach-Object { "`"$_`"" }) -join ", "
        $columnDefsSql = $columnDefs -join ", "

        # Create the table if it doesn't exist
        $createTableCmd = "CREATE TABLE IF NOT EXISTS [$tableName] ($columnDefsSql);"
        $createTable = $connection.CreateCommand()
        $createTable.CommandText = $createTableCmd
        $createTable.ExecuteNonQuery() | Out-Null

        # Begin transaction for efficiency
        $transaction = $connection.BeginTransaction()

        if (-not $transaction) {
            Write-Error "Error: Failed to create transaction (null)."
            return
        }

        # Prepare the insert command
        $insertCmd = $connection.CreateCommand()

        if (-not $insertCmd) {
            Write-Error "Error: Failed to create insert command (null)."
            return
        }

        $placeholders = ($columns | ForEach-Object { "@" + $_ }) -join ", "
        $insertCmd.CommandText = "INSERT INTO [$tableName] ($columnsSql) VALUES ($placeholders);"

        # Define parameters for the insert command
        foreach ($col in $columns) {
            $param = $insertCmd.CreateParameter()
            $param.ParameterName = "@$col"
            $insertCmd.Parameters.Add($param) | Out-Null
        }

        # Insert data into the table
        foreach ($row in $data) {
            foreach ($col in $columns) {
                # Force booleans and handle nulls correctly
                $valueToInsert = if ($row.$col -eq $null) { 
                    [DBNull]::Value  # Only convert true nulls to DBNull
                } elseif ($row.$col -is [bool]) { 
                    if ($row.$col) { 1 } else { 0 }  # Explicit boolean conversion
                } elseif ($row.$col -is [string] -and $row.$col -match '^(TRUE|FALSE)$') {
                    if ($row.$col -eq "TRUE") { 1 } else { 0 }  # Handle TRUE/FALSE strings
                } elseif ($row.$col -is [string] -and $row.$col -eq "") {
                    0  # Treat empty strings explicitly as 0 for booleans
                } else { 
                    $row.$col  # Pass other values as-is
                }

                # Log what’s being assigned to parameters for debugging
                Write-Verbose "Assigning value to @$col`: $valueToInsert"

                $insertCmd.Parameters["@${col}"].Value = $valueToInsert
            }

            try {
                $insertCmd.ExecuteNonQuery() | Out-Null
            } catch {
                Write-Error "Error during data insertion:"
                Write-Error "SQL Command: $($insertCmd.CommandText)"
                Write-Error "Parameter Values:"
                foreach ($param in $insertCmd.Parameters) {
                    Write-Error "  $($param.ParameterName) = $($param.Value)"
                }
                Write-Error "Exception Message: $($_.Exception.Message)"
                Write-Error "Stack Trace: $($_.Exception.StackTrace)"
                throw  # Re-throw to outer catch for handling
            }
        }

        # Commit transaction and clean up
        $transaction.Commit()
    } catch {
        Write-Error "Error importing data: $_. Exception Message: $($_.Exception.Message)"
        Write-Error "Stack Trace: $($_.Exception.StackTrace)"
    } finally {
        # Ensure cleanup even if errors occur
        $connection.Close()
        $connection.Dispose()
    }
}

$keySecretName   = 'GoogleKey2'                               # secret name in SecretStore vault which contains Google service acct .json key
$initUser        = 'pflint@missouriwestern.edu'               # User for retrieving user data
$ignoreOrgUnits  = @('/UnenrolledStudents')                   # org units to exclude in user query
$dbPath          = 'C:\GoogleTest5.db'                        # .db out file path (sqlite)

# Only proceed if executed with elevated privileges
if (Test-ElevatedShell) {

    # Add NuGet as trusted repository if not already
    Add-NuGet

    # Install SQLite if not already
    Install-SQLite

    # ensure required assemblies are loaded into current session
    $reqAssemblies = @('BouncyCastle', 'System.Data.Sqlite.Core')
    Ensure-Assemblies -packageNames $reqAssemblies

    # ensure module dependencies are present
    $reqModules = @('Microsoft.PowerShell.SecretManagement', 'Microsoft.PowerShell.SecretStore')
    Ensure-Modules -moduleNames $reqModules

    # ensure key file contents are present in secretStore vault & configured for automated retrieval
    Ensure-SecretStoreConfig -secretName $keySecretName

    # Retrieve all suspended users who have signed in previously, ignoring those who have never signed in & specified OU
    $users = Get-Users -keySecretName $keySecretName -user $initUser -Suspended -IgnoreNeverSignedIn -IgnoreOrgUnits $ignoreOrgUnits

    # Initialize array & counter for loop
    $report = @()
    $i = 0

    # Loop through each user to get their Drive usage
    foreach ($user in $users) {

        # Increment counter & print info to console
        $i++
        Write-Host "User Number: $i of $($users.count)" -ForegroundColor Cyan
        Write-Host "Username: $($user.primaryEmail)"        

        # Initialize & get user's drive file metadata
        $files = $null
        $files = Get-UserOwnedDriveFileMetadata -user $user -keySecretName $keySecretName -Shared:$false -LastModifiedByOwner:$true

        # If file metadata is found, insert into SQLite db
        if ($files) { 
            Import-SQLiteData -dbPath $dbPath -tableName 'data' -data $files 
        }

        # Print user's file count to console
        Write-Host "File Count: $($files.Count)" -ForegroundColor Green
    }
}
