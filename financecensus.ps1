<#
.SYNOPSIS
    Finance Department User Census with Enhanced Offboarding Detection
.DESCRIPTION
    Scans Finance department and analyzes specified groups/DLs for active/offboarded users.
    Includes last sign-in activity, days since last sign-in, and offboarding reason classification.
.PARAMETER DepartmentName
    Department to scan (default: Finance)
.PARAMETER GroupNames
    Array of group display names to analyze
.PARAMETER GroupIds
    Array of group object IDs to analyze
.PARAMETER ExportPath
    Path for output files
.PARAMETER InactivityThresholdDays
    Days since last sign-in to consider a user "inactive" (default: 90)
.PARAMETER IncludeSignInActivity
    Include last sign-in data (requires AuditLog.Read.All)
#>

[CmdletBinding()]
param(
    [string]$DepartmentName = "Finance",
    [string[]]$GroupNames = @(),
    [string[]]$GroupIds = @(),
    [string]$ExportPath = ".\FinanceCensus_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [int]$InactivityThresholdDays = 90,
    [switch]$IncludeSignInActivity
)

#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Reports

function Connect-GraphEnvironment {
    $scopes = @(
        "User.Read.All",
        "Directory.Read.All",
        "UserAuthenticationMethod.Read.All"
    )
    
    if ($IncludeSignInActivity) {
        $scopes += "AuditLog.Read.All"
    }
    
    Connect-MgGraph -Scopes $scopes -NoWelcome
    Write-Host "Connected to Microsoft Graph" -ForegroundColor Green
}

function Get-OffboardingReason {
    param(
        [bool]$AccountEnabled,
        [datetime]$LastSignIn,
        [int]$ThresholdDays
    )
    
    $now = Get-Date
    
    if (-not $AccountEnabled) {
        return "Account Disabled"
    }
    
    if ($LastSignIn -eq $null) {
        return "Never Signed In"
    }
    
    $daysSince = ($now - $LastSignIn).Days
    
    if ($daysSince -gt $ThresholdDays) {
        return "Inactive $daysSince Days"
    }
    
    return "Active"
}

function Get-FinanceUsers {
    Write-Host "`nScanning $DepartmentName department..." -ForegroundColor Cyan
    
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
        'SignInSessionsValidFromDateTime'
    )
    
    if ($IncludeSignInActivity) {
        $properties += 'SignInActivity'
    }
    
    $filter = "department eq '$DepartmentName'"
    
    try {
        $users = Get-MgUser -Filter $filter -Property $properties -All -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to retrieve users: $_"
        return @()
    }
    
    # Verify we got the right department
    $uniqueDepartments = $users.Department | Select-Object -Unique
    Write-Host "Found departments in results: $($uniqueDepartments -join ', ')" -ForegroundColor Yellow
    
    $results = foreach ($user in $users) {
        $lastSignIn = $null
        $daysSinceSignIn = $null
        
        if ($IncludeSignInActivity -and $user.SignInActivity.LastSignInDateTime) {
            $lastSignIn = [datetime]$user.SignInActivity.LastSignInDateTime
            $daysSinceSignIn = ((Get-Date) - $lastSignIn).Days
        }
        
        $offboardingReason = Get-OffboardingReason -AccountEnabled $user.AccountEnabled -LastSignIn $lastSignIn -ThresholdDays $InactivityThresholdDays
        $isActive = ($offboardingReason -eq "Active")
        
        [PSCustomObject]@{
            Id = $user.Id
            DisplayName = $user.DisplayName
            UserPrincipalName = $user.UserPrincipalName
            Email = $user.Mail
            JobTitle = $user.JobTitle
            Department = $user.Department
            OfficeLocation = $user.OfficeLocation
            AccountEnabled = $user.AccountEnabled
            CreatedDate = [datetime]$user.CreatedDateTime
            LastSignInDate = $lastSignIn
            DaysSinceLastSignIn = $daysSinceSignIn
            OffboardingReason = $offboardingReason
            IsActive = $isActive
            Status = if ($isActive) { "Active" } else { "Offboarded" }
            Groups = @()
        }
    }
    
    Write-Host "Found $($results.Count) users in $DepartmentName department" -ForegroundColor Green
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
    
    Write-Host "`nAnalyzing $($TargetGroups.Count) groups..." -ForegroundColor Cyan
    
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
            
            $result = [PSCustomObject]@{
                GroupId = $group.Id
                GroupName = $group.DisplayName
                Total = $groupFinanceUsers.Count
                Active = $active.Count
                Offboarded = $offboarded.Count
                ActiveUsers = $active
                OffboardedUsers = $offboarded
            }
            
            $results += $result
            
            Write-Host "  Total: $($result.Total) | Active: $($result.Active) | Offboarded: $($result.Offboarded)" -ForegroundColor White
            
            if ($result.Offboarded -gt 0) {
                Write-Host "  WARNING: $($result.Offboarded) offboarded users in group!" -ForegroundColor Red
                $offboarded | ForEach-Object {
                    Write-Host "    - $($_.DisplayName): $($_.OffboardingReason)" -ForegroundColor DarkRed
                }
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
    
    # Export all users with full details
    $allPath = Join-Path $ExportPath "All_Finance_Users.csv"
    $AllUsers | Select-Object Id, DisplayName, UserPrincipalName, Email, JobTitle, Department, OfficeLocation, Status, AccountEnabled, CreatedDate, LastSignInDate, DaysSinceLastSignIn, OffboardingReason, @{N='Groups';E={$_.Groups -join ';'}} | Export-Csv -Path $allPath -NoTypeInformation
    
    # Export active users
    $activePath = Join-Path $ExportPath "Active_Users.csv"
    $AllUsers | Where-Object { $_.IsActive } | Select-Object DisplayName, UserPrincipalName, Email, JobTitle, Department, OfficeLocation, LastSignInDate, DaysSinceLastSignIn | Export-Csv -Path $activePath -NoTypeInformation
    
    # Export offboarded users with reasons
    $offPath = Join-Path $ExportPath "Offboarded_Users.csv"
    $AllUsers | Where-Object { -not $_.IsActive } | Select-Object DisplayName, UserPrincipalName, Email, JobTitle, Department, OfficeLocation, AccountEnabled, LastSignInDate, DaysSinceLastSignIn, OffboardingReason | Export-Csv -Path $offPath -NoTypeInformation
    
    # Export group-specific reports
    foreach ($group in $GroupResults) {
        $safeName = $group.GroupName -replace '[\\/:*?"<>|]', '_'
        
        if ($group.ActiveUsers.Count -gt 0) {
            $group.ActiveUsers | Select-Object DisplayName, UserPrincipalName, Email, JobTitle, Department, LastSignInDate, DaysSinceLastSignIn | Export-Csv -Path (Join-Path $ExportPath "$safeName`_Active.csv") -NoTypeInformation
        }
        
        if ($group.OffboardedUsers.Count -gt 0) {
            $group.OffboardedUsers | Select-Object DisplayName, UserPrincipalName, Email, JobTitle, Department, OfficeLocation, AccountEnabled, LastSignInDate, DaysSinceLastSignIn, OffboardingReason | Export-Csv -Path (Join-Path $ExportPath "$safeName`_Offboarded_RISK.csv") -NoTypeInformation
        }
    }
    
    # Security risk report: offboarded users still in groups
    $risks = $AllUsers | Where-Object { -not $_.IsActive -and $_.Groups.Count -gt 0 }
    if ($risks.Count -gt 0) {
        $riskPath = Join-Path $ExportPath "SECURITY_RISK_Offboarded_In_Groups.csv"
        $risks | Select-Object DisplayName, UserPrincipalName, Email, JobTitle, Department, OffboardingReason, @{N='GroupMemberships';E={$_.Groups -join ';'}} | Export-Csv -Path $riskPath -NoTypeInformation
    }
    
    # Summary report
    $summaryPath = Join-Path $ExportPath "Summary_Report.txt"
    $summary = @"
Finance Department Census Report
Generated: $(Get-Date)
Department Filter: $DepartmentName
Inactivity Threshold: $InactivityThresholdDays days

TOTAL USERS: $($AllUsers.Count)
  Active: $(($AllUsers | Where-Object { $_.IsActive }).Count)
  Offboarded: $(($AllUsers | Where-Object { -not $_.IsActive }).Count)

OFFBOARDING BREAKDOWN:
$(($AllUsers | Where-Object { -not $_.IsActive } | Group-Object OffboardingReason | ForEach-Object { "  $($_.Name): $($_.Count)" }) -join "`n")

GROUPS ANALYZED: $($GroupResults.Count)
$(foreach ($g in $GroupResults) { "  $($g.GroupName): $($g.Total) total, $($g.Offboarded) offboarded" } -join "`n")

SECURITY RISKS:
  Offboarded users still in groups: $($risks.Count)
"@

    $summary | Out-File -FilePath $summaryPath
    
    Write-Host "`nReports saved to: $ExportPath" -ForegroundColor Green
    Write-Host "Files generated:" -ForegroundColor Gray
    Get-ChildItem $ExportPath | ForEach-Object { Write-Host "  $($_.Name)" -ForegroundColor Gray }
}

# Main Execution
Write-Host "Finance Department Census Tool v2.0" -ForegroundColor Cyan
Write-Host "Inactivity Threshold: $InactivityThresholdDays days" -ForegroundColor Yellow

Connect-GraphEnvironment

$financeUsers = Get-FinanceUsers

if ($financeUsers.Count -eq 0) {
    Write-Error "No users found in $DepartmentName department. Check department name spelling."
    Disconnect-MgGraph
    exit 1
}

# Resolve groups by name or ID
$targetGroups = @()

foreach ($name in $GroupNames) {
    try {
        $group = Get-MgGroup -Filter "displayName eq '$name'" -ErrorAction Stop
        if ($group) {
            $targetGroups += $group
            Write-Host "Found group by name: $name" -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "Group not found: $name"
    }
}

foreach ($id in $GroupIds) {
    try {
        $group = Get-MgGroup -GroupId $id -ErrorAction Stop
        $targetGroups += $group
        Write-Host "Found group by ID: $($group.DisplayName)" -ForegroundColor Green
    }
    catch {
        Write-Warning "Group ID not found or access denied: $id"
    }
}

# Remove duplicates
$targetGroups = $targetGroups | Group-Object Id | ForEach-Object { $_.Group[0] }

$analysis = Get-GroupAnalysis -FinanceUsers $financeUsers -TargetGroups $targetGroups

Export-Results -AllUsers $financeUsers -GroupResults $analysis

# Console Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "CENSUS COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Finance Users: $($financeUsers.Count)" -ForegroundColor White
Write-Host "Active: $(($financeUsers | Where-Object { $_.IsActive }).Count)" -ForegroundColor Green
Write-Host "Offboarded: $(($financeUsers | Where-Object { -not $_.IsActive }).Count)" -ForegroundColor Red

$offboardedBreakdown = $financeUsers | Where-Object { -not $_.IsActive } | Group-Object OffboardingReason
foreach ($category in $offboardedBreakdown) {
    Write-Host "  - $($category.Name): $($category.Count)" -ForegroundColor DarkRed
}

Write-Host "Groups Analyzed: $($analysis.Count)" -ForegroundColor White

Disconnect-MgGraph
