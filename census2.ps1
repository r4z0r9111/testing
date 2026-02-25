param(
    [Parameter(Mandatory=$true)]$Department
)

Connect-MgGraph -Scopes User.Read.All,AuditLog.Read.All,Directory.Read.All -NoWelcome | Out-Null

$users = Get-MgUser -Filter "department eq '$Department'" -All -Property displayName,mail,accountEnabled,SignInActivity

if($users){
    $users | Select-Object displayName,
                          mail,
                          @{N='AccountStatus';E={if($_.accountEnabled){'Active'}else{'Disabled'}}},
                          @{N='LastSignIn';E={if($_.SignInActivity.LastSignInDateTime){([datetime]$_.SignInActivity.LastSignInDateTime).ToString('yyyy-MM-dd')}else{'Never'}}} |
             Sort-Object displayName
} else {
    Write-Host "No users found in department: $Department"
}

Disconnect-MgGraph | Out-Null
