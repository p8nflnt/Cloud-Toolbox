<#
.SYNOPSIS
    Retrieve Google Drive contents by userPrincipalName or driveId 
    and places them in a local reconstruction of their directory structure

.NOTES
    Name: Get-GSDriveContents
    Author: Payton Flint
    Version: 1.0
    DateCreated: 2024-May

.LINK
    https://github.com/p8nflnt/Cloud-Toolbox/blob/main/psgsuite/Get-GSDriveContents.ps1
#>

# Clear variables for repeatability
Get-Variable -Exclude PWD,*Preference | Remove-Variable -EA 0

# retrieve user's Google Drive contents in locally reconstructed directory structure
function Get-GSUserDriveContents {
    param (
        [string]$user,
        [string]$driveId,
        [string]$outFileRoot,
        $updateFreq,
        $throttleLimit,
        $allDirs,
        $allFiles
    )

    # get the size of the target directory in bytes
    function Get-DirSize {
        param (
            $target
        )

        # get target directory
        $dir = New-Object System.IO.DirectoryInfo($target)

        # retrieve all files recursively
        $files = $dir.GetFiles("*", [System.IO.SearchOption]::AllDirectories)

        # total file sizes
        $totalSize = ($files | Measure-Object -Property Length -Sum).Sum

        # return the sum of all file sizes in bytes
        return $totalSize
    }

    # scrub name of invalid characters, trailing spaces
    function Clean-Name {
        param (
            [string]$name
        )
        # remove trailing spaces
        $cleanName = $name -replace '\s+$', ''

        # remove invalid characters
        $invalidChars = '[\\\/:*?"<>|]'

        # replace invalid characters with -
        $cleanName = $cleanName -replace $invalidChars, '-'

        # return cleaned name
        return $cleanName
    }

    # display progress bar with detailed progress information
    function Update-Progress {
    param (
        [int64]$totalBytes,
        [int64]$initCurrentBytes,
        $stopwatch,
        $updateTimer,
        $updateFreq
    )
        # conversion of bytes to KB, MB, GB, TB
        function Convert-Bytes {
            param ([int64]$bytes)
            if ($bytes -ge 1TB) {
                return "{0:N2} TB" -f ($bytes / 1TB)
            } elseif ($bytes -ge 1GB) {
                return "{0:N2} GB" -f ($bytes / 1GB)
            } elseif ($bytes -ge 1MB) {
                return "{0:N2} MB" -f ($bytes / 1MB)
            } elseif ($bytes -ge 1KB) {
                return "{0:N2} KB" -f ($bytes / 1KB)
            } else {
                return "{0} bytes" -f $bytes
            }
        }

        # get directory size and update progress at specified interval
        if ($updateTimer.Elapsed.TotalSeconds -ge $updateFreq) {
            
            # get total size of root directory
            $dirSize = Get-DirSize -target $outFileRoot

            # subtract initial root directory size from current size
            # derives progress until current point
            $currentBytes = $dirSize - $initCurrentBytes

            # if any progress...
            if ($currentBytes -gt 0) {
                
                # get the elapsed time in seconds from the stopwatch parameter
                $elapsed = $stopwatch.Elapsed.TotalSeconds

                # calculate the ratio of total bytes to be downloaded
                # by the total bytes downloaded until current point
                $ratio = ($currentBytes / $totalBytes)

                # ensure percentage can't exceed 100%
                if ($ratio -ge 1) {$ratio = 1}

                # multiply ratio by 100 to calculate percentage
                $percentComplete = ($ratio) * 100

                # calculate the rate until current point in bytes per second
                $rateBytesPerSecond = $currentBytes / $elapsed

                # convert bps rate to Mbps
                $rateMbps = $rateBytesPerSecond * 8 / 1MB
                # text formatting
                $formattedRate = "{0:N2} Mbps" -f $rateMbps

                # calculate estimated time to completion
                $remainingTime = ($totalBytes - $currentBytes) / $rateBytesPerSecond
                $remainingTimeSpan = [timespan]::FromSeconds($remainingTime)
                $formattedTime = $remainingTimeSpan.ToString("hh\:mm\:ss")

                # format percentage
                $formattedPercent = "{0:N2} % Complete" -f $percentComplete

                # convert bytes to readable format
                $formattedCurrentBytes = Convert-Bytes -bytes $currentBytes
                $formattedTotalBytes = Convert-Bytes -bytes $totalBytes

                # format the output string with detailed progress information
                $outputStatus = "$formattedPercent - $formattedCurrentBytes / $formattedTotalBytes @ $formattedRate - Est. Time Remaining: $formattedTime"

                # display progress bar with additional information
                Write-Progress -Activity "Downloading files from Google Drive" -Status $outputStatus -PercentComplete $percentComplete
            }
                
            # reset the timer and the counter after updating
            $updateTimer.Restart()
        }

    }

     function Build-DirStructure {
        param (
            [string]$parentId,
            [hashtable]$dirMap,
            [hashtable]$allDirsHT
        )

        # get parent folder path from $dirMap hashtable
        $parentPath = $dirMap[$parentId]

        # if parent directory does not already exist, create it and print to console
        if (-not (Test-Path -Path $parentPath)) {
            New-Item -Path $parentPath -ItemType Directory -ErrorAction SilentlyContinue| Out-Null
            Write-Host "Creating directory: $parentPath"
        }

        # Check if there are any child directories for the current parent ID
        if ($allDirsHT.ContainsKey($parentId)) {
            
            # Get the list of child directory names directly from the hashtable
            $childDirs = $allDirsHT[$parentId]  

            # for each child key/value pair...
            foreach ($child in $childDirs) {
                
                # get ID and name for child from key/value pair
                $childId   = $child | Select-Object -ExpandProperty keys
                $childName = $child | Select-Object -ExpandProperty values

                # build child directory full path
                $childPath = Join-Path -Path $parentPath -ChildPath $childName

                # add ID and full path to $dirMap hashtable
                $dirMap[$childId] = $childPath
                
                # recursive invocation of this function using child directory id as parent id
                Build-DirStructure -parentId $childId -dirMap $dirMap -allDirsHT $allDirsHT   
            }
        }
    }

    function Get-Files {
        param (
            [string]$outFileRoot,
            $allFiles,
            [hashtable]$dirMap,
            [string]$user,
            [int]$throttleLimit,
            $updateFreq
        )

        # initialize total bytes
        [int64]$totalBytes = 0

        # get initial current bytes from directory current size
        [int64]$initCurrentBytes = Get-DirSize -target $outFileRoot

        # initialize all files hashtable
        $allFilesHT = @{}

        # use all files to perform initial actions and build hashtable
        foreach ($file in $allFiles) {
            
            # get parent id from file object
            $parentId = $file | Select-Object -ExpandProperty Parents

            # ignore files without a parent ID value
            if ($parentId -ne $null) {

                # if $dirMap hashtable contains file's parent ID value
                if ($dirMap.ContainsKey($parentId)) {

                    # increment the total number of bytes for progress calculation
                    $totalBytes += $file.Size
                    
                    # get file ID and name properties respectively
                    $fileId   = $file | Select-Object -ExpandProperty Id
                    $fileName = $file | Select-Object -ExpandProperty Name

                    # get filepath associated with file's parent ID value in $dirMap hashtable
                    $filePath = $dirMap[$parentId]
                    
                    # build full path from parent's path and child's name
                    $fullPath = Join-Path -Path $filePath -ChildPath $fileName
                    
                    # if file does not already exist... 
                    if (-not (Test-Path -Path $fullPath)) {

                        # add $fileID and its full path to $allFilesHT hashtable
                        $allFilesHT[$fileId] = $fullPath           
                    }
                }
            }
        }
        # subtract current bytes from total bytes
        $totalBytes = $totalBytes - $initCurrentBytes

        # define scriptblock for execution in runspace
        $scriptBlock = {
            param(
                $file,
                $user
            )
            # get file ID & path from key/value pair
            $fileId   = $file.Key
            $filePath = $file.Value

            # get file from Google
            Get-GSDriveFile -FileId $fileId -OutFilePath $filePath -user $user -ErrorAction SilentlyContinue
        } 

        # initialize runspace pool with throttle limit
        $runspacePool = [runspacefactory]::CreateRunspacePool(1, $throttleLimit)
        $runspacePool.Open()

        # initialize runspaces array
        $runspaces = @()

        # initialize and start stopwatch for progress prediction
        $progStopwatch = New-Object System.Diagnostics.Stopwatch
        $progStopwatch.Start()

        # initialize and start a stopwatch for the update frequency
        $updateTimer = New-Object System.Diagnostics.Stopwatch
        $updateTimer.Start()

        # start all runspaces
        foreach ($file in $allFilesHT.GetEnumerator()) {

            # runspace w/ scriptblock & arguments specified
            $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($file).AddArgument($user)
            $runspace.RunspacePool = $runspacePool
            $runspaces += [PSCustomObject]@{ Pipe = $runspace; Status = $runspace.BeginInvoke() }
            
            # print full file path
            Write-Host "Queuing download for: " $file.Value
            
            # run update progress function
            Update-Progress -totalBytes $totalBytes -initCurrentBytes $initCurrentBytes -stopwatch $progStopwatch -updateTimer $updateTimer -updateFreq $updateFreq
        }

        # initialize completed runspaces array
        $completedRunspaces = @()

        # after queuing all downloads in runspaces, clean up completed runspaces and update progress
        do {
         
            # run update progress function
            Update-Progress -totalBytes $totalBytes -initCurrentBytes $initCurrentBytes -stopwatch $progStopwatch -updateTimer $updateTimer -updateFreq $updateFreq

            # clean up/dispose runspaces as they complete
            foreach ($runspace in $runspaces) {
                if ($runspace.Status.IsCompleted) {
                    $result = $runspace.Pipe.EndInvoke($runspace.Status)
                    $runspace.Pipe.Dispose()
                    $completedRunspaces += $runspace
                }
            }

            # remove completed runspaces from the array
            $runspaces = $runspaces | Where-Object { $_ -notin $completedRunspaces }

            # optionally add a sleep to reduce CPU usage while waiting
            Start-Sleep -Milliseconds 100
        } while ($runspaces.Count -gt 0)

        # close out and dispose runspace pool
        $runspacePool.Close()
        $runspacePool.Dispose()

        # stop prediction stopwatch
        $progStopwatch.Stop()
    }

    # initialize and start stopwatch for measuring total function runtime
    $totalRuntimeStopwatch = New-Object System.Diagnostics.Stopwatch
    $totalRuntimeStopwatch.Start()
    
    # if retrieving drive contents for user...
    if (-not($driveId)) {

        # get root drive ID
        $driveId  = (Get-GSDriveFileList -User $user -ParentFolderId 'root' -Limit 1) | Select-Object -ExpandProperty Parents

        # get all dir info by userPrincipalName if not already available
        if ($allDirs -eq $null) {
            $allDirs  = Get-GSDriveFileList -User $user -Filter "mimeType = 'application/vnd.google-apps.folder'" -ErrorAction SilentlyContinue
        }

        # get all file info by userPrincipalName if not already available
        if ($allFiles -eq $null) {
            $allFiles = Get-GSDriveFileList -User $user -Filter "mimeType != 'application/vnd.google-apps.folder'" -ErrorAction SilentlyContinue
        }

    # if retrieving drive contents by drive id...
    } else {

        # get all dir info by drive id if not already available
        if ($allDirs -eq $null) {
            $allDirs  = Get-GSDriveFileList -TeamDriveId $driveId -IncludeTeamDriveItems -Filter "mimeType = 'application/vnd.google-apps.folder'" -ErrorAction SilentlyContinue
        }

        # get all file info by drive id if not already available
        if ($allFiles -eq $null) {
            $allFiles = Get-GSDriveFileList -TeamDriveId $driveId -IncludeTeamDriveItems -Filter "mimeType != 'application/vnd.google-apps.folder'" -ErrorAction SilentlyContinue
        }
    }

    # set parameter defaults for optional parameters
    # default time interval in seconds to update progress
    if ($updateFreq -eq $null) {
        $updateFreq = 10
    }

    # default number of concurrent downloads/runspaces
    if ($throttleLimit -eq $null) {
        $throttleLimit = 50
    }

    # initialize $allDirs hashtable
    $allDirsHT = @{}

    # for each directory in $allDirs...
    foreach ($dir in $allDirs) {

        # if the dir object has a parent ID present
        if ($dir.Parents -ne $null) {
              
            # get the directory object's parent ID
            $parentId = $dir | Select-Object -ExpandProperty Parents

            # get the directory object's ID 
            $dirId = $dir | Select-Object -ExpandProperty Id

            # clean the directory name (invalid characters, trailing spaces)
            $cleanName = Clean-Name -name $dir.name
                
            # check if the parent ID entry already exists; if not, create a new array
            if (-not $allDirsHT.ContainsKey($parentId)) {
                $allDirsHT[$parentId] = @()
            }

            # create a child hashtable to be nested
            # contains directory ID and child folder's cleaned name
            $childHashtable = @{
                $dirId = $cleanName;
            }

            # add the child hashtable to the array of children for this parent ID
            $allDirsHT.$parentId += $childHashtable
        }
    }

    # initialize $dirMap hashtable
    $dirMap = @{}

    # add $driveId/$outFileRoot pair to $dirMap hashtable
    $dirMap[$driveId] = $outFileRoot

    # build out directory structure in the outfile root directory
    Build-DirStructure -parentId $driveId -dirMap $dirMap -allDirsHT $allDirsHT

    # get all files from Google with specified parameters for concurrent downloads using runspaces
    Get-Files -outFileRoot $outFileRoot -allFiles $allFiles -dirMap $dirMap -user $user -throttleLimit $throttleLimit -updateFreq $updateFreq

    # run garbage colletion to free RAM after closing out runspaces
    [System.GC]::Collect()

    # calculate and print the total runtime
    $totalRuntime = $totalRuntimeStopwatch.Elapsed
    Write-Host "Total runtime: $($totalRuntime.ToString())"
    $totalRuntimeStopwatch.Stop()
}

# parameters for function execution
$user = "<UserPrincipalName>"
$driveId = "<DriveId>"
$outFileRoot = "<FilePath>"
$updateFreq = 10  # time interval in seconds to update progress
$throttleLimit = 50 # desired number of concurrent downloads

# execute function
Get-GSUserDriveContents -user $user -driveId $driveId -outFileRoot $outFileRoot -updateFreq $updateFreq -throttleLimit $throttleLimit
