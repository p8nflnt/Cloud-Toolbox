<#
.SYNOPSIS
    Force an Entra Connect Sync delta sync with integrity check.

.NOTES
    Name: Sync-AD2Entra.ps1
    Author: Payton Flint
    Version: 1.0
    DateCreated: 2024-Mar

.LINK
    https://youtu.be/dQw4w9WgXcQ?si=mFplzW-sd_qkIEB1
#>

# original hash string for integrity check
$ogHash = "<Initial Run $freshHash>"

# body of script within scriptblock (for integrity check)
$scriptBlock = {
    # fqdn of AAD/Entra Connect Server
    $connectSrv = "<Entra Connect Server>"

    # nested scriptblock for invocation
    $nestedBlock = { Start-ADSyncSyncCycle -PolicyType Delta } # execute delta sync to Azure/Entra

    # prompt for creds & invoke nested scriptblock on AAD/Entra Connect Server
    Invoke-Command -ComputerName $connectSrv -ScriptBlock $nestedBlock -Credential (Get-Credential)
}
# convert scriptblock to string
$scriptString = $scriptBlock.ToString()

# create a SHA256 object from .NET
$sha256 = [System.Security.Cryptography.SHA256]::Create()

# convert string to a byte array & compute hash
$bytes = [System.Text.Encoding]::UTF8.GetBytes($scriptString)
$hashBytes = $sha256.ComputeHash($bytes)

# convert hash bytes to a hexadecimal string
$freshHash = [BitConverter]::ToString($hashBytes) -replace '-'

# clean up the SHA256 object
$sha256.Dispose()

# if script body is unmodified, execute
if ($ogHash -eq $freshHash) {
    $scriptBlock.Invoke()
} else {
    clear
    Write-Host -ForegroundColor Red "INTEGRITY CHECK FAILURE`r`nCONTACT SYSADMIN"
}
