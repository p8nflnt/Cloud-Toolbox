<#
.SYNOPSIS
    - Get each user from Google Workspace via API
    - Get each user's drive file metadata from Google via API
    - Export all users' drive file metadata to .csv
    - Convert .csv to SQLite database for querying

.NOTES
    Name: Get-GoogleDriveFileMetadataDb.ps1
    Author: Payton Flint
    Version: 1.0
    DateCreated: 2024-Dec

.LINK
    https://github.com/p8nflnt/Cloud-Toolbox/blob/main/Google/Get-GoogleDriveFileMetadataDb.ps1
    https://paytonflint.com/cloud-return-enterprise-wide-google-drive-file-metadata-as-sql-database/
#>

Function Test-ElevatedShell {
    # Check if the current user has administrative privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Warning "You are not running this script with administrator privileges. Please restart the script as an administrator."
        return $false
    }
}

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

Function Install-BouncyCastle {
    # Retrieve installed package information
    $bouncyCastle = Get-Package BouncyCastle -ErrorAction SilentlyContinue

    # If BouncyCastle package is not present...
    If (!($bouncyCastle)) {
        Write-Host "BouncyCastle not found, downloading..."

        # Install BouncyCastle package for cryptographic processing
        Install-Package BouncyCastle -ErrorAction SilentlyContinue
    } Else {
        # Locate BouncyCastle .DLL file 
        $bouncyCastle = $bouncyCastle.Source | Split-Path
        $bouncyCastle = $(Get-ChildItem -Path $bouncyCastle -Recurse -Filter *.dll | Select-Object -First 1).FullName
    }

    # If BouncyCastle .DLL was found...
    If ($bouncyCastle) {
        Write-Host "BouncyCastle present, loading assembly to current session..."
        Add-Type -Path $bouncyCastle -ErrorAction Stop
        Write-Host "BouncyCastle assembly loaded into the current session successfully."
    } Else {
        Write-Host "No BouncyCastle .DLL file found."
    }
    # Return .DLL file path for reference post-install
    #return $bouncyCastle
}

Function Get-GoogleAccessToken {
    param (
        [string]$scope,       # OAuth permission scope(s) - multiple scopes should be space-separated
        [string]$keyFilePath, # Path to service account key file path
        [string]$user,        # Subject - Email of the user to impersonate
        [int]$ttl             # Token time-to-live in seconds (3600 default)
    )
  
    # If expiration not specified, set default
    If (!($ttl)) {
        [int]$ttl = 3600
    }
  
    # Get client_email from JSON key file
    $jsonContent = Get-Content -Raw -Path $keyFilePath | ConvertFrom-Json
    $svcAcct     = $jsonContent.client_email
  
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
        exp   = [math]::floor((Get-Date).ToUniversalTime().AddHours(1).Subtract([datetime]'1970-01-01').TotalSeconds)
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

# Retrieve all users from Admin SDK
Function Get-AllUsers {
    param (
        [string]$accessToken
    )

    $users = @()
    $nextPageToken = $null
    do {
        $url = "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=500"
        if ($nextPageToken) {
            $url += "&pageToken=$nextPageToken"
        }

        $response = Invoke-RestMethod -Uri $url -Headers @{
            Authorization = "Bearer $accessToken"
            Accept        = "application/json"
        } -Method Get

        $users += $response.users
        $nextPageToken = $response.nextPageToken
    } while ($nextPageToken)

    return $users
}

# Query Google for user-owned drive files
function Get-UserOwnedDriveFiles {
    param (
        [string]$AccessToken,         # Access token passed as a parameter
        [string]$ModifiedAfter,       # DateTime in format '1/1/1970 00:00:00 AM'
        [string]$ModifiedBefore       # DateTime in format '1/1/1970 00:00:00 AM'
    )

    # Ensure only one of ModifiedAfter or ModifiedBefore is provided
    if ($ModifiedAfter -and $ModifiedBefore) {
        throw "You cannot specify both -ModifiedAfter and -ModifiedBefore. Please provide only one of these parameters."
    }

    # Nested helper function for ISO 8601 conversion
    function ConvertToISO8601 {
        param ([string]$DateTimeString)
        return ([datetime]::Parse($DateTimeString)).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }

    # Initialize query components
    $query = @()

    # Add ownership filter
    $query += "'me' in owners"

    # Convert dates and build query components only if parameters are specified
    if ($ModifiedAfter) {
        $ModifiedAfterISO = ConvertToISO8601 -DateTimeString $ModifiedAfter
        $query += "modifiedTime > '$ModifiedAfterISO'"
    }
    if ($ModifiedBefore) {
        $ModifiedBeforeISO = ConvertToISO8601 -DateTimeString $ModifiedBefore
        $query += "modifiedTime < '$ModifiedBeforeISO'"
    }

    # Determine if a query is needed
    $queryString = if ($query.Count -gt 0) {
        "q=" + [System.Uri]::EscapeDataString($query -join " and ")
    } else { "" }

    # Construct the base URI
    $baseUri = "https://www.googleapis.com/drive/v3/files"
    $fieldsParam = "fields=nextPageToken,files(id,modifiedTime,name,owners,size)"
    $files = @()
    $pageToken = $null

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

    # Get owner email address from $_.owners and write as single user/property
    ForEach ($file in $files) {
        $file | Add-Member -MemberType NoteProperty -Name owner -Value $file.Owners[0].EmailAddress -Force
    }

    # Return results
    return $files | Select-Object -Property ID, ModifiedTime, Name, Owner, Size
}

function Install-SQLite {
    # Check if the current user has administrative privileges
    Function Test-ElevatedShell {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-Warning "You are not running this script with administrator privileges. Please restart the script as an administrator."
            return $false
        }
    }

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

function Convert-CsvToSQLite {
    param (
        [Parameter(Mandatory = $true)]
        [string]$csvPath,              # Mandatory path to csv file
        [Parameter(Mandatory = $true)]
        [string]$dbPath,               # Mandatory path for db export
        [string]$tableName = "Data"    # Table name
    )

    # Validate filename/extension
    $fileName = [System.IO.Path]::GetFileName($dbPath)
    $extension = [System.IO.Path]::GetExtension($dbPath)
    if (-not $fileName -or $extension -ne ".db") {
        Write-Error "The specified file path does not include a file name with an extension."
    }

    # Get columns/schema from .csv
    Write-Host "Analyzing CSV file to generate schema..."
    $csvData = Import-Csv -Path $csvPath
    $columns = $csvData[0].PSObject.Properties.Name
    $columnDefinitions = $columns | ForEach-Object { "[$_] TEXT" }
    $columnDefinitions = $columnDefinitions -join ", "
    Write-Host "Detected columns: $($columns -join ', ')"

    # Create sqlite db & table
    Write-Host "Creating SQLite database, `"$dbPath`" and table, `"Data`""
    $tableCreationCommand = "CREATE TABLE IF NOT EXISTS $tableName ($columnDefinitions);"
    sqlite3 $dbPath $tableCreationCommand

    # Import data into the database using .import
    Write-Host "Populating SQLite database with data from CSV..."
    $importScript = @"
.mode csv
.import '$csvPath' $tableName
"@

    # Execute the script using the SQLite command-line tool
    $tempFile = [System.IO.Path]::GetTempFileName()
    Set-Content -Path $tempFile -Value $importScript
    sqlite3 $dbPath ".read $tempFile"

    # Remove the temporary file
    Remove-Item -Path $tempFile -Force

    Write-Host "CSV data successfully imported into SQLite database: $dbPath"
}

$keyFilePath     = <KEY FILE PATH>  # .json key file path
$initUser        = <USERNAME>       #  User for generating the token to retrieve all users
$csvReportPath   = <CSV FILE PATH>  # .csv out file path
$dbPath          = <SQLITE DB PATH> # .db out file path (sqlite)

# Only proceed if executed with elevated privileges
if (Test-ElevatedShell) {

    # Add NuGet repository if it is not already configured
    Add-NuGet

    # Install BouncyCastle .DLL for cryptographic processing
    Install-Package BouncyCastle

    # Install BouncyCastle .DLL and get path for reference
    Install-BouncyCastle

    # Provide scope for initial token creation
    $tokenScope = "https://www.googleapis.com/auth/admin.directory.user.readonly"

    # Get new access token from Google for user
    $accessToken = Get-GoogleAccessToken -scope $tokenScope -keyFilePath $keyFilePath -user $initUser

    # Retrieve all users
    $users = Get-AllUsers -accessToken $accessToken

    # Initialize array, counter, adjust token scope for loop
    $report = @()
    $i = 0
    $tokenScope = "https://www.googleapis.com/auth/drive.metadata.readonly"

    # Loop through each user to get their Drive usage
    foreach ($user in $users) {

        # Increment counter & print info to console
        $i++
        Write-Host "User Number: $i of $($users.count)" -ForegroundColor Cyan
        Write-Host "Username: $user.primaryEmail" -ForegroundColor Cyan

        # Get new access token from Google for user
        $accessToken = $null
        $accessToken = Get-GoogleAccessToken -scope $tokenScope -keyFilePath $keyFilePath -user $user.primaryEmail

        # Initialize & get user's drive files
        $files = $null
        $files = Get-UserOwnedDriveFiles -AccessToken $AccessToken

        # If files are found, append to .csv
        if ($files.Count -gt 0) {
            $files | Export-Csv -Path $csvReportPath -Append -NoTypeInformation
        }
        # Print user's file count to console
        Write-Host "File Count: $($files.Count)" -ForegroundColor Green
    }

    # Install sqlite
    Install-SQLite

    # Convert .csv file to sqlite db
    Convert-CsvToSQLite -csvPath $csvReportPath -dbPath $dbPath
}
