# Compact version with Exchange Online integration
Connect-MgGraph -Scopes User.Read.All,Group.Read.All -NoWelcome | Out-Null
$targetId = (Get-MgUser -UserId "target@domain.com").Id
$sourceId = (Get-MgUser -UserId "source@domain.com").Id

# Get groups and separate them
$groups = Get-MgUserMemberOf -UserId $sourceId -All | Where-Object { 
    $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' -and 
    $_.AdditionalProperties.groupTypes -notcontains 'DynamicMembership'
}

$graphGroups = $groups | Where-Object { $_.AdditionalProperties.mailEnabled -eq $false }
$mailGroups = $groups | Where-Object { $_.AdditionalProperties.mailEnabled -eq $true }

# Process Graph groups
$graphGroups | ForEach-Object { 
    try { New-MgGroupMember -GroupId $_.Id -DirectoryObjectId $targetId } catch { Write-Warning "Graph: $($_.AdditionalProperties.displayName) - $_" }
}

# Process Exchange groups
if ($mailGroups) {
    Connect-ExchangeOnline -ShowBanner:$false
    $mailGroups | ForEach-Object {
        try { Add-DistributionGroupMember -Identity $_.AdditionalProperties.mail -Member $targetId -BypassSecurityGroupManagerCheck -Confirm:$false } 
        catch { Write-Warning "Exchange: $($_.AdditionalProperties.displayName) - $_" }
    }
    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
}
Disconnect-MgGraph | Out-Null
