<#
.SYNOPSIS
    Use the Microsoft Graph beta endpoint to generate a hashtable 
    of userPrincipalNames within a group and a boolean value for 
    whether they have the "microsoftAuthenticator" auth method specified.

.NOTES
    Name: Get-AzGroupAuthMethodHT
    Author: Payton Flint
    Version: 1.0
    DateCreated: 2024-Nov

.LINK
    https://github.com/p8nflnt/Cloud-Toolbox/blob/main/azure/Get-AzGroupAuthMethodsHT.ps1
#>

function Get-AzGroupAuthMethodsHT {
    param (
        [string]$GroupName
    )

    # connect to microsoft graph with required scopes
    Connect-MgGraph -Scopes "Group.Read.All", "User.Read.All" -ErrorAction Stop

    # get group ID by name
    $group = Get-MgGroup -Filter "displayName eq '$GroupName'"
    if (-not $group) {
        Write-Output "Group '$GroupName' not found."
        return $null
    }

    # get all group members
    $groupMembers = Get-MgGroupMember -GroupId $Group.Id -All

    # initialization for loop
    $userDetails = @{}
    $i = 0

    foreach ($user in $groupMembers) {
        # define uri for the beta endpoint
        $uri = "https://graph.microsoft.com/beta/users/$($user.Id)/authentication/methods"

        # increment count
        $i++

        try {
            # get user auth methods via beta endpoint
            $authUser = Invoke-MgGraphRequest -Uri $uri -Method GET

            # print status to console
            Write-Host "$i of $($groupMembers.count) - Retrieved authentication methods - $($user.AdditionalProperties['userPrincipalName'])"

            # detect if "microsoftAuthenticator" is in the authentication methods
            $authMethod = $authUser.Values.Values -contains "microsoftAuthenticator"

            # add upn as key & bool authMethod to hashtable
            $userDetails[$user.AdditionalProperties["userPrincipalName"]] = $authMethod
        } catch {
            Write-Host "Failed to retrieve authentication methods for user $($user.Id)"
        }
    }

    # return hashtable
    return $userDetails
}

# specify group name and invoke function
$groupName = "<GROUP NAME>"
$groupAuthHT = Get-AzGroupAuthMethodsHT -GroupName $groupName

# calculate percentage from hashtable
if ($groupAuthHT) {
    $mfaUsersCount = ($groupAuthHT.Values | Where-Object { $_ -eq $True }).Count
    $percentage = "{0:N2}" -f (($mfaUsersCount / $groupAuthHT.Keys.Count) * 100) + '%'
    Write-Host "$mfaUsersCount out of $($groupAuthHT.Keys.Count), or $percentage of users in $groupName have an authentication method specified."
}
