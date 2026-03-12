# Get Microsoft Graph group members - outputs CSV to console (redirect to save)
# Usage: .\Get-GroupMembers.ps1 -GroupName "GroupName" > members.csv

param([Parameter(Mandatory=$true)]$GroupName)

# Connect (read-only scopes)
Connect-MgGraph -Scopes "GroupMember.Read.All","User.Read.All" -NoWelcome

# Get group and members
$group = Get-MgGroup -Filter "displayName eq '$GroupName'"
if (-not $group) { Write-Error "Group not found"; exit 1 }

# Output CSV header
"DisplayName,Mail"

# Get members and output CSV rows
Get-MgGroupMember -GroupId $group.Id -All | 
    Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' } |
    ForEach-Object { 
        $user = Get-MgUser -UserId $_.Id -Property DisplayName,Mail
        "`"{0}`",`"{1}`"" -f $user.DisplayName, $user.Mail 
    }
