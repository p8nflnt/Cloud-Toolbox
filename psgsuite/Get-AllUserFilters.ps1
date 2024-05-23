# generate a .json report of all filters for all users in g-suite environment

# specify file path for output
$outfilePath = "<FILEPATH>"

# retrieve all users
$users = Get-GSUserList | Select-Object -ExpandProperty User

# get all filters for each user
$filters = $users | ForEach-Object {
    Get-GSGmailFilterList -User $_
}

# output .json report to specified outfile path
$filters | ConvertTo-Json -depth 100 | Out-File "$outfilePath" -Force
