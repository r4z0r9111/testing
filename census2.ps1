param(
    [Parameter(Mandatory=$true)][string]$Department,
    [string]$OutputPath
)

Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All" -NoWarning

$users = Get-MgUser -Filter "department eq '$Department'" -All

$results = foreach ($user in $users) {
    $lastSignIn = Get-MgAuditLogSignIn -Filter "userId eq '$($user.Id)'" -Top 1 | Select-Object -ExpandProperty CreatedDateTime
    $days = if($lastSignIn) { (New-TimeSpan -Start $lastSignIn -End (Get-Date)).Days } else { $null }
    
    [PSCustomObject]@{
        Name = $user.DisplayName
        UPN = $user.UserPrincipalName
        Enabled = $user.AccountEnabled
        Created = $user.CreatedDateTime
        LastSignIn = $lastSignIn
        DaysSinceSignIn = $days
        Status = if(-not $user.AccountEnabled) { "TERMINATED" }
                 elseif(-not $days) { "NO SIGNIN" }
                 elseif($days -gt 30) { "INACTIVE" }
                 else { "ACTIVE" }
    }
}

$results | Where-Object Status -eq "ACTIVE" | Format-Table Name, LastSignIn, DaysSinceSignIn -AutoSize
$results | Where-Object Status -ne "ACTIVE" | Format-Table Name, Status, LastSignIn, DaysSinceSignIn -AutoSize

if ($OutputPath) { $results | Export-Csv $OutputPath -NoTypeInformation }
