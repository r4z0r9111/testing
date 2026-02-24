<#
.SYNOPSIS
    Finance Department User Census
.DESCRIPTION
    Scans Finance department and analyzes specified groups/DLs for active/offboarded users
.PARAMETER DepartmentName
    Department to scan (default: Finance)
.PARAMETER GroupIds
    Array of group object IDs to analyze
.PARAMETER InactivityThresholdDays
    Days without sign-in to consider offboarded (default: 90)
.PARAMETER ExportPath
    Path for output files
#>

[CmdletBinding()]
param(
    [string]$DepartmentName = "Finance",
    [string[]]$GroupIds = @(),
    [int]$InactivityThresholdDays = 90,
    [string]$ExportPath = ".\FinanceCensus_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

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
    Write-Host ""
    Write-Host "Scanning $DepartmentName department..." -ForegroundColor Cyan
    Write-Host "Offboarding criteria: Account disabled OR no sign-in for $InactivityThresholdDays days or more" -ForegroundColor Gray
    
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
            Groups = @()
        }
    }
    
    $activeCount = ($results | Where-Object { $_.IsActive }).Count
    $offboardedCount = ($results | Where-Object { -not $_.IsActive }).Count
    
    Write-Host "Found $($results.Count) users" -ForegroundColor Green
    Write-Host "  Active: $activeCount | Offboarded: $offboardedCount" -ForegroundColor White
    
    return $results
}

function Get-GroupAnalysis {
    param(
        [array]$FinanceUsers,
        [array]$TargetGroups
    )
    
    if ($TargetGroups.Count -eq 0) {
        Write-Host "No groups specified for analysis" -ForegroundColor Yellow
        return @()
    }
    
    Write-Host ""
    Write-Host "Analyzing $($TargetGroups.Count) groups..." -ForegroundColor Cyan
    
    $results = @()
    
    foreach ($group in $TargetGroups) {
        Write-Host "Processing: $($group.DisplayName)" -ForegroundColor Gray
        
        try {
            $members = Get-MgGroupMember -GroupId $group.Id -All
            
            $groupFinanceUsers = @()
            foreach ($member in $members) {
                if ($member.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
                    $match = $FinanceUsers | Where-Object { $_.Id -eq $member.Id }
                    if ($match) {
                        $groupFinanceUsers += $match
                        $match.Groups += $group.DisplayName
                    }
                }
            }
            
            $active = $groupFinanceUsers | Where-Object { $_.IsActive }
            $offboarded = $groupFinanceUsers | Where-Object { -not $_.IsActive }
            
            $disabledInGroup = $offboarded | Where-Object { $_.IsOffboardedByDisable }
            $inactiveInGroup = $offboarded | Where-Object { $_.IsOffboardedByInactivity }
            
            $result = [PSCustomObject]@{
                GroupId = $group.Id
                GroupName = $group.DisplayName
                Total = $groupFinanceUsers.Count
                Active = $active.Count
                Offboarded = $offboarded.Count
                OffboardedDisabled = $disabledInGroup.Count
                OffboardedInactive = $inactiveInGroup.Count
                ActiveUsers = $active
                OffboardedUsers = $offboarded
            }
            
            $results += $result
            
            Write-Host "  Total: $($result.Total) | Active: $($result.Active) | Offboarded: $($result.Offboarded)" -ForegroundColor White
            
            if ($result.Offboarded -gt 0) {
                Write-Host "  WARNING: $($result.Offboarded) offboarded users in group!" -ForegroundColor Red
            }
        }
        catch {
            Write-Warning "Error analyzing group '$($group.DisplayName)': $_"
        }
    }
    
    return $results
}

function Export-Results {
    param(
        [array]$AllUsers,
        [array]$GroupResults
    )
    
    New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
    
    $allPath = Join-Path $ExportPath "All_Finance_Users_Detailed.csv"
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
        'CreatedDate',
        @{N='GroupMemberships'; E={$_.Groups -join ';'}}
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
    
    $offPath = Join-Path $ExportPath "Offboarded_Users_Detailed.csv"
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
        'DaysSinceLastSignIn',
        @{N='GroupMemberships'; E={$_.Groups -join ';'}}
    ) | Export-Csv -Path $offPath -NoTypeInformation
    
    $inactivePath = Join-Path $ExportPath "CRITICAL_Inactive_But_Enabled.csv"
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
    
    foreach ($group in $GroupResults) {
        $safeName = $group.GroupName -replace '[\\/:*?"<>|]', '_'
        
        if ($group.ActiveUsers.Count -gt 0) {
            $group.ActiveUsers | Select-Object @(
                'DisplayName',
                'UserPrincipalName',
                'Email',
                'JobTitle',
                'Department',
                'LastSignInDateTime',
                'SignInStatus'
            ) | Export-Csv -Path (Join-Path $ExportPath "$($safeName)_Active.csv") -NoTypeInformation
        }
        
        if ($group.OffboardedUsers.Count -gt 0) {
            $group.OffboardedUsers | Select-Object @(
                'DisplayName',
                'UserPrincipalName',
                'Email',
                'JobTitle',
                'Department',
                'AccountStatus',
                'OffboardReason',
                'LastSignInDateTime',
                'DaysSinceLastSignIn'
            ) | Export-Csv -Path (Join-Path $ExportPath "$($safeName)_Offboarded_RISK.csv") -NoTypeInformation
        }
    }
    
    $risks = $AllUsers | Where-Object { -not $_.IsActive -and $_.Groups.Count -gt 0 }
    if ($risks.Count -gt 0) {
        $riskPath = Join-Path $ExportPath "SECURITY_RISK_Offboarded_With_Group_Access.csv"
        $risks | Select-Object @(
            'DisplayName',
            'UserPrincipalName',
            'Email',
            'JobTitle',
            'Department',
            'OffboardReason',
            @{N='DaysSinceLastSignIn'; E={$_.DaysSinceLastSignIn}},
            @{N='GroupMemberships'; E={$_.Groups -join ';'}},
            @{N='ActionRequired'; E={"Remove from groups immediately"}}
        ) | Export-Csv -Path $riskPath -NoTypeInformation
    }
    
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
        GroupsAnalyzed = $GroupResults.Count
        SecurityRisks = $risks.Count
    }
    
    $stats | ConvertTo-Json | Out-File -FilePath (Join-Path $ExportPath "Census_Summary.json")
    $stats | Export-Csv -Path (Join-Path $ExportPath "Census_Summary.csv") -NoTypeInformation
    
    Write-Host ""
    Write-Host "Reports saved to: $ExportPath" -ForegroundColor Green
}

function Show-Dashboard {
    param(
        [array]$AllUsers,
        [array]$GroupResults
    )
    
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "  FINANCE DEPARTMENT CENSUS DASHBOARD" -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    
    Write-Host ""
    Write-Host "DEPARTMENT OVERVIEW" -ForegroundColor Yellow
    Write-Host "  Department: $DepartmentName" -ForegroundColor White
    Write-Host "  Total Users: $($AllUsers.Count)" -ForegroundColor White
    
    $active = $AllUsers | Where-Object { $_.IsActive }
    $offboarded = $AllUsers | Where-Object { -not $_.IsActive }
    
    Write-Host "  Active: $($active.Count)" -ForegroundColor Green
    Write-Host "  Offboarded: $($offboarded.Count)" -ForegroundColor Red
    
    Write-Host ""
    Write-Host "OFFBOARDING BREAKDOWN" -ForegroundColor Yellow
    $byDisable = ($AllUsers | Where-Object { $_.IsOffboardedByDisable }).Count
    $byInactivity = ($AllUsers | Where-Object { $_.IsOffboardedByInactivity }).Count
    $both = ($AllUsers | Where-Object { $_.IsOffboardedByDisable -and $_.IsOffboardedByInactivity }).Count
    
    Write-Host "  Account Disabled: $byDisable" -ForegroundColor Red
    Write-Host "  Inactive ($InactivityThresholdDays days or more): $byInactivity" -ForegroundColor Red
    Write-Host "  Both conditions: $both" -ForegroundColor Magenta
    
    $critical = $AllUsers | Where-Object { $_.IsOffboardedByInactivity -and $_.AccountEnabled }
    if ($critical.Count -gt 0) {
        Write-Host ""
        Write-Host "CRITICAL: Inactive but Enabled Accounts" -ForegroundColor Red
        Write-Host "   Found $($critical.Count) accounts with no sign-in for $InactivityThresholdDays days or more" -ForegroundColor Red
        Write-Host "   but are still ENABLED. These should be reviewed." -ForegroundColor Yellow
        $critical | Select-Object -First 5 | ForEach-Object {
            Write-Host "   - $($_.DisplayName) - $($_.DaysSinceLastSignIn) days inactive" -ForegroundColor Gray
        }
    }
    
    if ($GroupResults.Count -gt 0) {
        Write-Host ""
        Write-Host "GROUP ANALYSIS" -ForegroundColor Yellow
        foreach ($group in $GroupResults) {
            Write-Host "  $($group.GroupName):" -ForegroundColor Cyan
            Write-Host "    Total: $($group.Total) | Active: $($group.Active) | Offboarded: $($group.Offboarded)" -ForegroundColor White
            if ($group.Offboarded -gt 0) {
                Write-Host "    Security Risk: $($group.Offboarded) offboarded users have access!" -ForegroundColor Red
            }
        }
    }
    
    Write-Host "======================================================================" -ForegroundColor Cyan
}

Write-Host "Finance Department Census Tool" -ForegroundColor Cyan

Connect-GraphEnvironment

$financeUsers = Get-FinanceUsers

$targetGroups = @()
foreach ($id in $GroupIds) {
    try {
        $group = Get-MgGroup -GroupId $id
        $targetGroups += $group
    }
    catch {
        Write-Warning "Group ID not found or access denied: $id"
    }
}

$targetGroups = $targetGroups | Group-Object Id | ForEach-Object { $_.Group[0] }

$analysis = Get-GroupAnalysis -FinanceUsers $financeUsers -TargetGroups $targetGroups

Export-Results -AllUsers $financeUsers -GroupResults $analysis

Show-Dashboard -AllUsers $financeUsers -GroupResults $analysis

Disconnect-MgGraph
