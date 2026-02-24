param(
    [Parameter(Mandatory=$true)][string]$Department,
    [Parameter(Mandatory=$false)][string]$OutputPath = "C:\temp\dept_$Department.csv"
)

Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All" -NoWarning
Select-MgProfile beta

$users = Get-MgBetaUser -Filter "department eq '$Department'" -All -Property "displayName","userPrincipalName","department","jobTitle","accountEnabled","createdDateTime","signInActivity"

$results = $users | ForEach-Object {
    $days = if($_.SignInActivity.LastSuccessfulSignInDateTime) { 
        [math]::Floor(((Get-Date) - $_.SignInActivity.LastSuccessfulSignInDateTime).TotalDays) 
    } else { $null }
    
    [PSCustomObject]@{
        Name = $_.DisplayName
        UPN = $_.UserPrincipalName
        JobTitle = $_.JobTitle
        Enabled = $_.AccountEnabled
        Created = $_.CreatedDateTime
        LastSignIn = $_.SignInActivity.LastSuccessfulSignInDateTime
        DaysSinceSignIn = $days
        Status = if(-not $_.AccountEnabled) { "TERMINATED - Disabled" }
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

$results | Export-Csv -Path $OutputPath -NoTypeInformation
Write-Host "`nExported to: $OutputPath" -ForegroundColor Cyan
