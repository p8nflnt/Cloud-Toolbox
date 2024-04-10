<#
.SYNOPSIS
     ingest the auto-generated .CSV file from a G-Suite Email Log Search
     & permanently delete those specified emails from end users' mailboxes

.NOTES
    Name: PSG-SearchAndDestroy
    Author: Payton Flint
    Version: 1.0
    DateCreated: 2024-Apr

.LINK
    https://youtu.be/dQw4w9WgXcQ?si=mFplzW-sd_qkIEB1
#>

# import message events from .CSV file
$messageEvents = Import-Csv "<FILEPATH>"

# get messages where event status is 'INSERTED'
$messageEvents= $messageEvents | Where-Object {$_."Event Status" -eq 'INSERTED'}

# add Rfc822MsgId property to each object
$messageEvents | ForEach-Object {

    # initialize variable and modify Id to remove < > characters
    $rfc822MsgId = $null
    $rfc822MsgId = ($_."Message ID".Replace('<', '').Replace('>', ''))

    # add Rfc822MsgId property to object containing the modified Id
    $_ | Add-Member -Name 'Rfc822MsgId' -Type NoteProperty -Value $rfc822MsgId -Force
}

# get each message's Google id
$messageEvents | ForEach-Object {

    # initialize variable
    $message = $null
    # get additional message information
    $message = Get-GSGmailMessageList -User $_."Recipient address" -Rfc822MsgId $_.Rfc822MsgId -IncludeSpamTrash
    # add message's Google id to messageEvent object
    $_ | Add-Member -Name 'Id' -Type NoteProperty -Value $message.Id -Force
}

# permanently delete target messages by id (if present)
$messageEvents | ForEach-Object {

    # if messageEvent's id property is present...
    if ($_.Id -ne $null) {
        # permanently delete target message by id
        Remove-GSGmailMessage -User $_."Recipient address" -Id $_.Id -Method Delete
    }
}
