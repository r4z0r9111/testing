# Get group members with Directory.Read.All (no GroupMember.Read.All)
# Usage: .\Get-GroupMembers.ps1 -GroupName "GroupName" > members.csv

param([Parameter(Mandatory=$true)]$GroupName)

Connect-MgGraph -Scopes "Directory.Read.All" -NoWelcome

$group = Get-MgGroup -Filter "displayName eq '$GroupName'"
if (-not $group) { throw "Group not found" }

"DisplayName,Mail"
Get-MgGroupMember -GroupId $group.Id -All | 
   Where-Object { $_.'@odata.type' -match 'user' } |
   ForEach-Object { 
       $u = Get-MgUser -UserId $_.Id -Property DisplayName,Mail
       "`"{0}`",`"{1}`"" -f $u.DisplayName, $u.Mail 
   }
