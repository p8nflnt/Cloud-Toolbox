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

# retrieves token for user by email address
# security note: key file contents are unencrypted in memory temporarily during token generation
function Get-GoogleAccessToken {
    param (
        [Parameter(Mandatory = $true)]
        [string]$scope, # OAuth permission scope(s) - multiple scopes should be space-separated

        [Parameter(Mandatory = $true)]
        [secureString]$key, # Key file contents from secureStore vault as SecureString

        [Parameter(Mandatory = $true)]
        [string]$user, # Subject - Email of the user to impersonate

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
    }
    catch {
        Write-Error "Error in Get-GoogleAccessToken: $_"
        return $null
    }
}

# remove forwarding address from user via gmail api
Function Remove-UserForwardingAddress {
    param (
        [Parameter(Mandatory = $true)]
        [string]$user, # user to generate token for, impersonate, and retrieve user data

        [Parameter(Mandatory = $true)]
        [secureString]$key, # key file contents from secureStore vault as secureString

        [Parameter(Mandatory = $true)]
        [string]$forwardingAddress    # target forwarding address to remove 
    )

    Write-Host "User: $user"
    Write-Host "ForwardingAddress: $forwardingAddress"

    # Provide oauth scope for token creation
    $tokenScope = "https://www.googleapis.com/auth/gmail.settings.sharing"

    # Get new access token from Google for user
    $accessToken = Get-GoogleAccessToken -scope $tokenScope -key $key -user $user

    try {
        # build & append query to url
        $url = ("https://gmail.googleapis.com/gmail/v1/users/$user/settings/forwardingAddresses/$forwardingAddress").Replace('@', '%40')

        $response = Invoke-RestMethod -Uri $url -Headers @{
            Authorization = "Bearer $accessToken"
            Accept        = "application/json"
        } -Method Delete

    }
    catch {
        Write-Error $_
    }
}

$keySecretName     = <SecretName>   # secret store vault secret name to store Google .json key file
$user              = <EmailAddress> # target user with forwarding 
$forwardingAddress = <EmailAddress> # forwarding address to remove from user

# ensure module dependencies are present
$reqModules = @('Microsoft.PowerShell.SecretManagement', 'Microsoft.PowerShell.SecretStore')
Ensure-Modules -moduleNames $reqModules

# ensure key file contents are present in secretStore vault & configured for automated retrieval
Ensure-SecretStoreConfig -secretName $keySecretName

# retrieve key from secret store vault
$key = Get-Secret -Name $keySecretName

# remove forwarding address from user via gmail api
Remove-UserForwardingAddress -User $user -key $key -forwardingAddress $forwardingAddress
