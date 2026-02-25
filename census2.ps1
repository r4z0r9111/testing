param(
    [Parameter(Mandatory=$true)]$Department
)

Connect-MgGraph -Scopes User.Read.All,AuditLog.Read.All,Directory.Read.All -NoWelcome | Out-Null

$users = Get-MgUser -Filter "department eq '$Department'" -All -Property mail,displayName,accountEnabled,userPrincipalName

if($users){
    foreach($u in $users){
        # Get last sign-in using Get-MgAuditLogSignIn (same as your working script)
        $lastSignIn = Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$($u.userPrincipalName)'" -Top 1 -Property createdDateTime -ErrorAction SilentlyContinue | Select-Object -ExpandProperty createdDateTime
        
        [PSCustomObject]@{
            Name = $u.displayName
            Email = $u.mail
            Status = if($u.accountEnabled){"Active"}else{"Disabled"}
            LastSignIn = if($lastSignIn){$lastSignIn}else{"Never"}
        }
    } | Sort-Object Name
} else {
    Write-Host "No users found in department: $Department"
}

Disconnect-MgGraph | Out-Null
