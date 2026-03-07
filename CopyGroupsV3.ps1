Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Groups
Import-Module Microsoft.Graph.Authentication

Connect-MgGraph -Scopes User.Read.All,AuditLog.Read.All,Directory.Read.All -NoWelcome | Out-Null

$groups = Get-MgUserMemberOf -UserId (Get-MgUser -UserId "").Id -All |
    Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' -and 
                   $_.AdditionalProperties.groupTypes -notcontains 'DynamicMembership' } |
    Select-Object Id, @{N='MailEnabled';E={$_.AdditionalProperties.mailEnabled}}

$targetID = (Get-MgUser -UserId "").Id

Connect-ExchangeOnline -ShowBanner:$false

$groups | ForEach-Object { 
    if ($_.MailEnabled) {
        try {
            Add-DistributionGroupMember -Identity $_.Id -Member $targetID -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction Stop
        } catch {
            if ($_.Exception.Message -notmatch "groupMailbox|already exist") {
                Write-Warning $_.Exception.Message
            }
        }
    } else {
        New-MgGroupMember -GroupId $_.Id -DirectoryObjectId $targetID
    }
}

Disconnect-ExchangeOnline -Confirm:$false | Out-Null
Disconnect-MgGraph | Out-Null
