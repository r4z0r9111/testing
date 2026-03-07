Connect-MgGraph -Scopes User.Read.All,AuditLog.Read.All,Directory.Read.All -NoWelcome | Out-Null
$groups = Get-MgUserMemberOf -UserId (Get-MgUser -UserId "").Id -All |
    Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' -and 
                   $_.AdditionalProperties.groupTypes -notcontains 'DynamicMembership'} |
    Select-Object Id, @{N='MailEnabled';E={$_.AdditionalProperties.mailEnabled}}

$targetID = (Get-MgUser -UserId "").Id

# Separate groups
$graphGroups = $groups | Where-Object { -not $_.MailEnabled }
$mailGroups = $groups | Where-Object { $_.MailEnabled }

# Graph groups
$graphGroups | ForEach-Object { New-MgGroupMember -GroupId $_.Id -DirectoryObjectId $targetID }

# Mail-enabled groups via Exchange
if ($mailGroups) {
    Connect-ExchangeOnline -ShowBanner:$false
    $mailGroups | ForEach-Object { Add-DistributionGroupMember -Identity $_.Id -Member $targetID -BypassSecurityGroupManagerCheck -Confirm:$false }
    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
}

Disconnect-MgGraph | Out-Null
