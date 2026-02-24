param([Parameter(Mandatory=$true)][string]$Department)

Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All" -NoWarning
Select-MgProfile beta  # REQUIRED - signInActivity is beta only

$users = Get-MgBetaUser -Filter "department eq '$Department'" -All -Property @(
    "displayName","userPrincipalName","department","jobTitle",
    "accountEnabled","createdDateTime","signInActivity"
)

$results = $users | Select-Object `
    @{N="Name";E={$_.DisplayName}},
    @{N="UPN";E={$_.UserPrincipalName}},
    @{N="JobTitle";E={$_.JobTitle}},
    @{N="Enabled";E={$_.AccountEnabled}},
    @{N="Created";E={$_.CreatedDateTime}},
    @{N="LastSignIn";E={$_.SignInActivity.LastSignInDateTime}},
    @{N="LastSuccessfulSignIn";E={$_.SignInActivity.LastSuccessfulSignInDateTime}},
    @{N="DaysSinceSignIn";E={
        if($_.SignInActivity.LastSuccessfulSignInDateTime) {
            [math]::Floor(((Get-Date) - $_.SignInActivity.LastSuccessfulSignInDateTime).TotalDays)
        } else { "Never/N/A" }
    }},
    @{N="Status";E={
        if(-not $_.AccountEnabled) { "Disabled" }
        elseif($_.SignInActivity.LastSuccessfulSignInDateTime -eq $null) { "No Sign-in Data" }
        elseif(([math]::Floor(((Get-Date) - $_.SignInActivity.LastSuccessfulSignInDateTime).TotalDays)) -gt 30) { "Inactive 30+ days" }
        else { "Active" }
    }}

$results | Sort-Object DaysSinceSignIn -Descending | Format-Table -AutoSize
$results | Export-Csv -Path "C:\temp\dept_$Department.csv" -NoTypeInformation
