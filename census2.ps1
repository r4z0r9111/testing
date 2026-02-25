param(
    [Parameter(Mandatory=$true)]$Department
)

Connect-MgGraph -Scopes User.Read.All,Directory.Read.All -NoWelcome | Out-Null

$users = Get-MgUser -Filter "department eq '$Department'" -All -Property mail,displayName

if($users){
    $users | Select-Object displayName,mail | Sort-Object displayName
} else {
    Write-Host "No users found in department: $Department"
}

Disconnect-MgGraph | Out-Null
