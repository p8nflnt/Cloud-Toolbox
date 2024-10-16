# specify variables
$from        = "<SENDER EMAIL>"    # Sender of email - Ex. no-reply@example.com
$to          = "<RECIPIENT EMAIL>" # Recipient of email
$subject     = "<EMAIL SUBJECT>"   # Email subject line
$htmlMsgBody = "<EMAIL BODY HTML>" # Path to file containing HTML message body
$keyFilePath = "<JSON KEY FILE>"   # Path to service account .JSON key file
$userListCsv = "<USER LIST CSV>"   # Path to file containing list of userList

Function Test-ElevatedShell {
    # Check if the current user has administrative privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if ($isAdmin) {
        Write-Host "You are running this script with administrator privileges."
        return $true
    } else {
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
        Register-PackageSource -Name Nuget -Location "https://www.nuget.org/api/v2" –ProviderName Nuget -Trusted -Force
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

# Insert an unread email into user's Gmail inbox
Function Insert-GmailMessage {
    param (
        [string]$token,      # Google access token
        [string]$from,       # Sender of email
        [string]$to,         # Recipient of email
        [string]$subject,    # Email subject line
        [string]$htmlMsgBody # Path to file containing HTML message body
    )

    # Get HTML message body contents
    $htmlMsgBody = Get-Content -Path $htmlMsgBody

    # Derive the email domain
    $emailDomain = '@' + ($from -split "@")[1]
    # Build Message-ID
    $newGuid = $(New-Guid).ToString()  # Convert GUID to string
    # Concatenate GUID and email domain
    $messageId = '<' + $newGuid + $emailDomain + '>'

    # Create the email message (RFC 5322 format)
    $emailContent = 
@"
From: $from
To: $to
Subject: $subject
Date: $(Get-Date -Format "ddd, dd MMM yyyy HH:mm:ss zzz")
Message-ID: $messageId
Content-Type: text/html; charset="UTF-8"

$htmlMsgBody
"@


    # Encode the email message in Base64 URL-safe format
    $emailBytes = [System.Text.Encoding]::UTF8.GetBytes($emailContent)
    $encodedEmail = [Convert]::ToBase64String($emailBytes)
    $encodedEmail = $encodedEmail -replace '\+', '-' -replace '\/', '_' -replace '=', ''

    # Insert the message into Gmail using the Gmail API (using URI for without media upload)
    $insertUri = "https://gmail.googleapis.com/gmail/v1/users/me/messages"

    # Define the JSON message body
    $body = @{
        raw = $encodedEmail
        labelIds = @("INBOX", "UNREAD")  # Adds the message as unread to the inbox
    } | ConvertTo-Json

    # Send POST to API to add message to user's inbox
    $response = Invoke-RestMethod -Uri $insertUri -Method POST -Body $body -ContentType "application/json" -Headers @{
        Authorization = "Bearer $accessToken"
    }

    # Output result
    if ($response.id) {
        Write-Host "Message inserted with ID: $($response.id)"
        return $response.id
    } else {
        Write-Host "Failed to insert message."
    }
}

# Only proceed if executed with elevated privileges
if (Test-ElevatedShell) {

    # Add NuGet repository if it is not already configured
    Add-NuGet

    # Install BouncyCastle .DLL for cryptographic processing
    Install-Package BouncyCastle

    # Install BouncyCastle .DLL and get path for reference
    Install-BouncyCastle

    # Provide scope for token creation in Get-GoogleAccessToken function
    $scope = "https://www.googleapis.com/auth/gmail.insert"

    # Retrieve user list contents
    $userList = Import-Csv -Path $userListCsv

    # Get each user in list
    ForEach ($user in $userList) {

        # Initialize variables for loop
        $accessToken = $null
        $messageId   = $null

        # Get access token from Google
        $accessToken = Get-GoogleAccessToken -scope $scope -keyFilePath $keyFilePath -user $user.email

        # Insert unread email into user's Gmail inbox
        $messageId = Insert-GmailMessage -token $accessToken -from $from -to $user.email -subject $subject -htmlMsgBody $htmlMsgBody
        
        # Add message id to .CSV
        $user | Add-Member -MemberType NoteProperty -Name "MessageId" -Value $messageId -Force
    }

    # Export the updated list back to the CSV (overwrite the original file)
    $userList | Export-Csv -Path $userListCsv -NoTypeInformation
}
