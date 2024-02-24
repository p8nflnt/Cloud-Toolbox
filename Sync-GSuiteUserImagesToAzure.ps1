<#
.SYNOPSIS
    Synchronize user profile photos from GSuite to Azure. Requires PSGSuite/Microsoft.Graph

.NOTES
    Name: Sync-GSuiteUserImagesToAzure
    Author: Payton Flint
    Version: 1.0
    DateCreated: 2024-February

.LINK
    https://github.com/p8nflnt/Cloud-Toolbox/blob/main/Sync-GSuiteUserImagesToAzure.ps1
    https://paytonflint.com/cloud-synchronize-profile-photos-between-federated-domains-google-azure/
#>

# clear variables for repeatability
Get-Variable -Exclude PWD,*Preference | Remove-Variable -EA 0

# identify location of script
$scriptPath = Split-Path ($MyInvocation.MyCommand.Source) -Parent
#===================================================================================================================================
# specify domain portion found in target user principal names
$upnDomain = "example@domain.com"

# connect to ms graph w/ appropriate permissions
Connect-MgGraph -Scopes 'User.ReadWrite.All' -NoWelcome
#===================================================================================================================================
# set inbound image cache path
$inboundImgCache = Join-Path $scriptPath "inboundImgCache"

# remove inbound image cache directory if it exists
If (Test-Path $inboundImgCache) {
    Remove-Item -Path $inboundImgCache -Recurse -Force -ErrorAction SilentlyContinue
}

# create inbound image cache directory
New-Item -Path $inboundImgCache -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

# set image repository path
$imgRepo = Join-Path $ScriptPath "imgRepo"

# create image repository directory if it does not exist
If (!(Test-Path $imgRepo)) {
    New-Item -Path $imgRepo -ItemType Directory -Force -ErrorAction SilentlyContinue
}
#===================================================================================================================================
# function to compare image hashes
function Compare-ImageHash {
    param (
        [string]$ImagePath1,
        [string]$ImagePath2,
        [string]$Algorithm = "SHA256"
    )
    $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
    
    $hash1Bytes = $hasher.ComputeHash([System.IO.File]::ReadAllBytes($ImagePath1))
    $hash1 = -join ($hash1Bytes | ForEach-Object { $_.ToString("x2") })
    
    $hash2Bytes = $hasher.ComputeHash([System.IO.File]::ReadAllBytes($ImagePath2))
    $hash2 = -join ($hash2Bytes | ForEach-Object { $_.ToString("x2") })
    
    # directly returns true if the hashes match (images are identical), false otherwise
    return $hash1 -eq $hash2
} # end Compare-ImageHash function

# function to handle updated images
function HandleImageUpdate {
    param (
        [Parameter(Mandatory=$true)]
        [string]$cachedImgPath,          # Path to the cached image
        [Parameter(Mandatory=$true)]
        [string]$cachedImgRepoPath,      # Destination path in the image repository
        [Parameter(Mandatory=$true)]
        [string]$userUPN,                # user principal name
        [Parameter(Mandatory=$true)]
        [string]$fileExt                 # image format file extension
    )
    # prod ms graph url
    $graphUrl = "https://graph.microsoft.com/v1.0"
    
    # get entra user id via ms graph, silence errors
    $userId = (Get-MgUser -UserId $userUPN 2>$null) | Select-Object -ExpandProperty Id

    # if userId found in destination domain...
    if ($userId -ne $null) {

        # copy image from inbound cache to image repository, overwriting it if present
        Copy-Item -Path $cachedImgPath -Destination $cachedImgRepoPath -Force -ErrorAction SilentlyContinue

        # upload cached image as user profile photo via ms graph
        Invoke-MgGraphRequest -Method "PUT" -Uri $graphUrl/users/$userId/photo/`$value -InputFilePath $cachedImgPath -ContentType "image/$fileExt"

        # remove cached image
        Remove-Item -Path $cachedImgPath -Force -ErrorAction SilentlyContinue

    # if no user id found in destination domain...
    } else {

        # remove cached image
        Remove-Item -Path $cachedImgPath -Force -ErrorAction SilentlyContinue
    }
} # end HandleImageUpdate function

#===================================================================================================================================
# get UPNs from source domain
$srcUPNs = Get-GSUserList | Select-Object -ExpandProperty User

# percentage calculation variables
$total =     $srcUPNs.Count
$processed = 0

# for each UPN...
$srcUPNs | ForEach-Object {

    # Increment the processed count
    $processed++

    # Calculate the percentage of completion
    $percentage = ($processed / $total) * 100

    # Update the progress bar using Write-Progress
    Write-Progress -Activity "Processing Users" -Status "$($percentage.ToString("0.00"))% Complete" -PercentComplete $percentage

    # get image for UPN and place in inbound image cache
    Get-GSUserPhoto -User $_ -OutFilePath $inboundImgCache -ErrorAction SilentlyContinue

    # get cached image filename (if any)
    $cachedImgName = (Get-ChildItem -Path $inboundImgCache).Name

    # if a user photo is returned to the cache...
    if ($cachedImgName -ne $null) {

        # get file extension
        $cachedImgExt      = [System.IO.Path]::GetExtension($cachedImgName).TrimStart('.')

        # build cached image file path
        $cachedImgPath     = Join-Path $inboundImgCache $cachedImgName

        # build file path to check image repository for cached image filename
        $cachedImgRepoPath = Join-Path $imgRepo $cachedImgName

        # check if cached image filename exists in image repository
        if (Test-Path $cachedImgRepoPath) {

            # compare cached image to repository image
            $imgCompareResult = Compare-ImageHash -ImagePath1 $cachedImgPath -ImagePath2 $cachedImgRepoPath

            # if cached image is identical to the repository image...
            if ($imgCompareResult -eq $true) {

                # remove cached image
                Remove-Item -Path $cachedImgPath -Force -ErrorAction SilentlyContinue

            # if cached image is not identical to the repository image...
            } else {

                # copy image to repository (potentially overwriting existing files by the same name), upload photo via ms graph, and clear the inbound cache
                HandleImageUpdate -cachedImgPath $cachedImgPath -cachedImgRepoPath $cachedImgRepoPath -userUPN $_ -fileExt $cachedImgExt
            }
        # if cached image does not exist in image repository
        } else {

            # copy image to repository (potentially overwriting existing files by the same name), upload photo via ms graph, and clear the inbound cache
            HandleImageUpdate -cachedImgPath $cachedImgPath -cachedImgRepoPath $cachedImgRepoPath -userUPN $_ -fileExt $cachedImgExt
        }
    }
}
