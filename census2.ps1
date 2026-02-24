param(
    [Parameter(Mandatory=$true)][string]$Department,
    [string]$OutputPath
)

Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All" -NoWarning

$users = Get-MgUser -Filter "department eq '$Department'" -All -Property "id","displayName","userPrincipalName","department","jobTitle","accountEnabled","createdDateTime"

$results = foreach ($user in $users) {
    $lastSignIn = (Get-MgAuditLogSignIn -Filter "userId eq '$($user.Id)'" -Top 1).CreatedDateTime
    $days = if($lastSignIn) { [math]::Floor(((Get-Date) - $lastSignIn).TotalDays) } else { $null }
    
    [PSCustomObject]@{
        Name = $user.DisplayName
        UPN = $user.UserPrincipalName
        JobTitle = $user.JobTitle
        Enabled = $user.AccountEnabled
        Created = $user.CreatedDateTime
        LastSignIn = $lastSignIn
        DaysSinceSignIn = $days
        Status = if(-not $user.AccountEnabled) { "TERMINATED - Disabled" }
                 elseif(-not $days) { "TERMINATED - No Sign-in" }
                 elseif($days -gt 30) { "INACTIVE - $days days" }
                 else { "ACTIVE" }
    }
}

$active = $results | Where-Object { $_.Status -eq "ACTIVE" }
$inactive = $results | Where-Object { $_.Status -ne "ACTIVE" }

Write-Host "`n=== ACTIVE ($($active.Count)) ===" -ForegroundColor Green
$active | Format-Table Name, LastSignIn, DaysSinceSignIn -AutoSize

Write-Host "`n=== INACTIVE/TERMINATED ($($inactive.Count)) ===" -ForegroundColor Red
$inactive | Format-Table Name, Status, LastSignIn, DaysSinceSignIn -AutoSize

if ($OutputPath) {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation
    Write-Host "`nExported to: $OutputPath" -ForegroundColor Cyan
}
