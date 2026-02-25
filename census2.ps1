param(
    [Parameter(Mandatory=$true)]$Department
)

Connect-MgGraph -Scopes User.Read.All,AuditLog.Read.All,Directory.Read.All -NoWelcome | Out-Null

$users = Get-MgUser -Filter "department eq '$Department'" -All -Property mail,displayName,accountEnabled,signInActivity

if($users){
    $users | ForEach-Object {
        $lastSignIn = if($_.signInActivity.lastSignInDateTime){$_.signInActivity.lastSignInDateTime}else{"Never"}
        [PSCustomObject]@{
            Name = $_.displayName
            Email = $_.mail
            Status = if($_.accountEnabled){"Active"}else{"Disabled"}
            LastSignIn = $lastSignIn
        }
    } | Sort-Object Name
} else {
    Write-Host "No users found in department: $Department"
}

Disconnect-MgGraph | Out-Null
