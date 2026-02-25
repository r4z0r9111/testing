param(
    [Parameter(Mandatory=$true)]$Department
)

Connect-MgGraph -Scopes User.Read.All,AuditLog.Read.All,Directory.Read.All -NoWelcome | Out-Null

$users = Get-MgUser -Filter "department eq '$Department'" -All -Property mail,displayName,accountEnabled,userPrincipalName

if($users){
    $results = @()
    foreach($u in $users){
        $lastSignIn = Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$($u.userPrincipalName)'" -Top 1 -Property createdDateTime -ErrorAction SilentlyContinue | Select-Object -ExpandProperty createdDateTime -First 1
        
        $results += [PSCustomObject]@{
            Name = $u.displayName
            Email = $u.mail
            Status = if($u.accountEnabled){"Active"}else{"Disabled"}
            LastSignIn = if($lastSignIn){$lastSignIn}else{"Never"}
        }
    }
    $results | Sort-Object Name | Format-Table -AutoSize
} else {
    Write-Host "No users found in department: $Department"
}

Disconnect-MgGraph | Out-Null
