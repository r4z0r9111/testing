<#
.SYNOPSIS
    Finance Department User Census with Offboarding Metrics
.DESCRIPTION
    Scans Finance department for active/offboarded users.
    Offboarding criteria: Account disabled OR no sign-in for 90+ days
.PARAMETER DepartmentName
    Department to scan (default: Finance)
.PARAMETER InactivityThresholdDays
    Days without sign-in to consider offboarded (default: 90)
.PARAMETER ExportPath
    Path for output files
#>

[CmdletBinding()]
param(
    [string]$DepartmentName = "Finance",
    [int]$InactivityThresholdDays = 90,
    [string]$ExportPath = ".\FinanceCensus_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

#Requires -Modules Microsoft.Graph.Users

function Connect-GraphEnvironment {
    $scopes = @(
        "User.Read.All",
        "Directory.Read.All",
        "AuditLog.Read.All"
    )
    
    Connect-MgGraph -Scopes $scopes -NoWelcome
    Write-Host "Connected to Microsoft Graph" -ForegroundColor Green
}

function Get-FinanceUsers {
    Write-Host "Scanning $DepartmentName department" -ForegroundColor Cyan
    Write-Host "Offboarding criteria: Account disabled OR no sign-in for $InactivityThresholdDays days" -ForegroundColor Gray
    
    $properties = @(
        'Id',
        'DisplayName',
        'UserPrincipalName',
        'Mail',
        'JobTitle',
        'Department',
        'AccountEnabled',
        'CreatedDateTime',
        'OfficeLocation',
        'CompanyName',
        'EmployeeType',
        'SignInActivity'
    )
    
    $filter = "department eq '$DepartmentName'"
    $users = Get-MgUser -Filter $filter -Property $properties -All
    
    $results = foreach ($user in $users) {
        $lastSignIn = $null
        $daysSinceSignIn = $null
        $signInStatus = "Unknown"
        
        if ($user.SignInActivity.LastSignInDateTime) {
            $lastSignIn = [datetime]$user.SignInActivity.LastSignInDateTime
            $daysSinceSignIn = ((Get-Date) - $lastSignIn).Days
            $signInStatus = "$daysSinceSignIn days ago"
        }
        else {
            $signInStatus = "Never"
            $daysSinceSignIn = 9999
        }
        
        $isDisabled = -not $user.AccountEnabled
        $isInactive = $daysSinceSignIn -ge $InactivityThresholdDays
        
        $offboardReason = @()
        if ($isDisabled) { $offboardReason += "Account Disabled" }
        if ($isInactive) { $offboardReason += "Inactive $daysSinceSignIn days" }
        
        $status = if ($isDisabled -or $isInactive) { "Offboarded" } else { "Active" }
        $offboardDetails = if ($offboardReason.Count -gt 0) { $offboardReason -join "; " } else { "N/A" }
        
        [PSCustomObject]@{
            Id = $user.Id
            DisplayName = $user.DisplayName
            UserPrincipalName = $user.UserPrincipalName
            Email = $user.Mail
            JobTitle = $user.JobTitle
            Department = $user.Department
            CompanyName = $user.CompanyName
            OfficeLocation = $user.OfficeLocation
            EmployeeType = $user.EmployeeType
            Status = $status
            IsActive = -not ($isDisabled -or $isInactive)
            AccountEnabled = $user.AccountEnabled
            AccountStatus = if ($user.AccountEnabled) { "Enabled" } else { "Disabled" }
            LastSignInDateTime = $lastSignIn
            DaysSinceLastSignIn = $daysSinceSignIn
            SignInStatus = $signInStatus
            OffboardReason = $offboardDetails
            IsOffboardedByDisable = $isDisabled
            IsOffboardedByInactivity = $isInactive
            CreatedDate = $user.CreatedDateTime
        }
    }
    
    $activeCount = ($results | Where-Object { $_.IsActive }).Count
    $offboardedCount = ($results | Where-Object { -not $_.IsActive }).Count
    
    Write-Host "Found $($results.Count) users" -ForegroundColor Green
    Write-Host "Active: $activeCount | Offboarded: $offboardedCount" -ForegroundColor White
    
    return $results
}

function Export-Results {
    param(
        [array]$AllUsers
    )
    
    New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
    
    $allPath = Join-Path $ExportPath "All_Finance_Users.csv"
    $AllUsers | Select-Object @(
        'DisplayName',
        'UserPrincipalName',
        'Email',
        'JobTitle',
        'Department',
        'CompanyName',
        'OfficeLocation',
        'EmployeeType',
        'Status',
        'AccountStatus',
        'OffboardReason',
        @{N='LastSignInDate'; E={if ($_.LastSignInDateTime) { $_.LastSignInDateTime.ToString("yyyy-MM-dd HH:mm") } else { "Never" }}},
        'DaysSinceLastSignIn',
        'SignInStatus',
        'CreatedDate'
    ) | Export-Csv -Path $allPath -NoTypeInformation
    
    $activePath = Join-Path $ExportPath "Active_Users.csv"
    $AllUsers | Where-Object { $_.IsActive } | Select-Object @(
        'DisplayName',
        'UserPrincipalName',
        'Email',
        'JobTitle',
        'Department',
        'OfficeLocation',
        @{N='LastSignIn'; E={$_.SignInStatus}},
        @{N='DaysSinceSignIn'; E={$_.DaysSinceLastSignIn}}
    ) | Export-Csv -Path $activePath -NoTypeInformation
    
    $offPath = Join-Path $ExportPath "Offboarded_Users.csv"
    $AllUsers | Where-Object { -not $_.IsActive } | Select-Object @(
        'DisplayName',
        'UserPrincipalName',
        'Email',
        'JobTitle',
        'Department',
        'OfficeLocation',
        'AccountStatus',
        'OffboardReason',
        @{N='LastSignInDate'; E={if ($_.LastSignInDateTime) { $_.LastSignInDateTime.ToString("yyyy-MM-dd HH:mm") } else { "Never" }}},
        'DaysSinceLastSignIn'
    ) | Export-Csv -Path $offPath -NoTypeInformation
    
    $inactivePath = Join-Path $ExportPath "Inactive_But_Enabled.csv"
    $AllUsers | Where-Object { $_.IsOffboardedByInactivity -and $_.AccountEnabled } | Select-Object @(
        'DisplayName',
        'UserPrincipalName',
        'Email',
        'JobTitle',
        'Department',
        @{N='LastSignInDate'; E={if ($_.LastSignInDateTime) { $_.LastSignInDateTime.ToString("yyyy-MM-dd HH:mm") } else { "Never" }}},
        'DaysSinceLastSignIn',
        @{N='Recommendation'; E={"Disable account or verify employment status"}}
    ) | Export-Csv -Path $inactivePath -NoTypeInformation
    
    $stats = [PSCustomObject]@{
        ReportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Department = $DepartmentName
        InactivityThreshold = $InactivityThresholdDays
        TotalUsers = $AllUsers.Count
        ActiveUsers = ($AllUsers | Where-Object { $_.IsActive }).Count
        OffboardedTotal = ($AllUsers | Where-Object { -not $_.IsActive }).Count
        OffboardedByDisable = ($AllUsers | Where-Object { $_.IsOffboardedByDisable }).Count
        OffboardedByInactivity = ($AllUsers | Where-Object { $_.IsOffboardedByInactivity }).Count
        InactiveButEnabled = ($AllUsers | Where-Object { $_.IsOffboardedByInactivity -and $_.AccountEnabled }).Count
    }
    
    $stats | ConvertTo-Json | Out-File -FilePath (Join-Path $ExportPath "Summary.json")
    
    Write-Host "Reports saved to: $ExportPath" -ForegroundColor Green
}

Write-Host "Finance Department Census Tool" -ForegroundColor Cyan

Connect-GraphEnvironment

$financeUsers = Get-FinanceUsers

Export-Results -AllUsers $financeUsers

Write-Host "Census Complete" -ForegroundColor Green
Write-Host "Total Users: $($financeUsers.Count)" -ForegroundColor White
Write-Host "Active: $(($financeUsers | Where-Object { $_.IsActive }).Count)" -ForegroundColor Green
Write-Host "Offboarded: $(($financeUsers | Where-Object { -not $_.IsActive }).Count)" -ForegroundColor Red

Disconnect-MgGraph
