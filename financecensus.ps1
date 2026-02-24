<#
.SYNOPSIS
    Finance Department User Census
.DESCRIPTION
    Scans Finance department and analyzes specified groups/DLs for active/offboarded users
.PARAMETER DepartmentName
    Department to scan (default: Finance)
.PARAMETER GroupNames
    Array of group display names to analyze
.PARAMETER GroupIds
    Array of group object IDs to analyze
.PARAMETER ExportPath
    Path for output files
.PARAMETER IncludeSignInActivity
    Include last sign-in data (requires AuditLog.Read.All)
.PARAMETER InactivityThresholdDays
    Days since last sign-in to consider inactive (default: 90)
#>

[CmdletBinding()]
param(
    [string]$DepartmentName = "Finance",
    [string[]]$GroupNames = @(),
    [string[]]$GroupIds = @(),
    [string]$ExportPath = ".\FinanceCensus_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch]$IncludeSignInActivity,
    [int]$InactivityThresholdDays = 90
)

#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Groups

function Connect-GraphEnvironment {
    $scopes = @(
        "User.Read.All",
        "Directory.Read.All"
    )
    
    if ($IncludeSignInActivity) {
        $scopes += "AuditLog.Read.All"
    }
    
    Connect-MgGraph -Scopes $scopes -NoWelcome
    Write-Host "Connected to Microsoft Graph" -ForegroundColor Green
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
        'OfficeLocation'
    )
    
    if ($IncludeSignInActivity) {
        $properties += 'SignInActivity'
    }
    
    $filter = "department eq '$DepartmentName'"
    $users = Get-MgUser -Filter $filter -Property $properties -All
    
    $results = foreach ($user in $users) {
        $lastSignIn = $null
        $daysSinceSignIn = $null
        
        if ($IncludeSignInActivity -and $user.SignInActivity.LastSignInDateTime) {
            $lastSignIn = [datetime]$user.SignInActivity.LastSignInDateTime
            $daysSinceSignIn = ((Get-Date) - $lastSignIn).Days
        }
        
        # Determine offboarding reason
        $offboardingReason = "Unknown"
        if (-not $user.AccountEnabled) {
            $offboardingReason = "Account Disabled"
        }
        elseif ($lastSignIn -eq $null) {
            $offboardingReason = "Never Signed In"
        }
        elseif ($daysSinceSignIn -gt $InactivityThresholdDays) {
            $offboardingReason = "Inactive $daysSinceSignIn Days"
        }
        else {
            $offboardingReason = "Active"
        }
        
        $isActive = ($offboardingReason -eq "Active")
        $status = if ($isActive) { "Active" } else { "Offboarded" }
        
        [PSCustomObject]@{
            Id = $user.Id
            DisplayName = $user.DisplayName
            UserPrincipalName = $user.UserPrincipalName
            Email = $user.Mail
            JobTitle = $user.JobTitle
            Department = $user.Department
            OfficeLocation = $user.OfficeLocation
            Status = $status
            IsActive = $isActive
            AccountEnabled = $user.AccountEnabled
            CreatedDate = $user.CreatedDateTime
            LastSignInDate = $lastSignIn
            DaysSinceLastSignIn = $daysSinceSignIn
            OffboardingReason = $offboardingReason
            Groups = @()
        }
    }
    
    Write-Host "Found $($results.Count) users" -ForegroundColor Green
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
    $financeUserIds = $FinanceUsers.Id
    
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
    
    # All users with full details including Department and Sign-in info
    $allPath = Join-Path $ExportPath "All_Finance_Users.csv"
    $AllUsers | Select-Object Id, DisplayName, UserPrincipalName, Email, JobTitle, Department, OfficeLocation, Status, IsActive, AccountEnabled, CreatedDate, LastSignInDate, DaysSinceLastSignIn, OffboardingReason, @{N='Groups';E={$_.Groups -join ';'}} | Export-Csv -Path $allPath -NoTypeInformation
    
    # Active users
    $activePath = Join-Path $ExportPath "Active_Users.csv"
    $AllUsers | Where-Object { $_.IsActive } | Select-Object DisplayName, UserPrincipalName, Email, JobTitle, Department, LastSignInDate, DaysSinceLastSignIn | Export-Csv -Path $activePath -NoTypeInformation
    
    # Offboarded users with reasons
    $offPath = Join-Path $ExportPath "Offboarded_Users.csv"
    $AllUsers | Where-Object { -not $_.IsActive } | Select-Object DisplayName, UserPrincipalName, Email, JobTitle, Department, OfficeLocation, AccountEnabled, LastSignInDate, DaysSinceLastSignIn, OffboardingReason | Export-Csv -Path $offPath -NoTypeInformation
    
    # Group-specific exports
    foreach ($group in $GroupResults) {
        $safeName = $group.GroupName -replace '[\\/:*?"<>|]', '_'
        
        if ($group.ActiveUsers.Count -gt 0) {
            $group.ActiveUsers | Select-Object DisplayName, UserPrincipalName, Email, JobTitle, Department, LastSignInDate, DaysSinceLastSignIn | Export-Csv -Path (Join-Path $ExportPath "$safeName`_Active.csv") -NoTypeInformation
        }
        
        if ($group.OffboardedUsers.Count -gt 0) {
            $group.OffboardedUsers | Select-Object DisplayName, UserPrincipalName, Email, JobTitle, Department, OfficeLocation, AccountEnabled, LastSignInDate, DaysSinceLastSignIn, OffboardingReason | Export-Csv -Path (Join-Path $ExportPath "$safeName`_Offboarded_RISK.csv") -NoTypeInformation
        }
    }
    
    # Security risk: offboarded users still in groups
    $risks = $AllUsers | Where-Object { -not $_.IsActive -and $_.Groups.Count -gt 0 }
    if ($risks.Count -gt 0) {
        $riskPath = Join-Path $ExportPath "SECURITY_RISK_Offboarded_In_Groups.csv"
        $risks | Select-Object DisplayName, UserPrincipalName, Email, JobTitle, Department, OffboardingReason, @{N='GroupMemberships';E={$_.Groups -join ';'}} | Export-Csv -Path $riskPath -NoTypeInformation
    }
    
    Write-Host "`nReports saved to: $ExportPath" -ForegroundColor Green
}

# MAIN EXECUTION - This is the part that actually runs
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

Write-Host "`nCensus Complete" -ForegroundColor Green
Write-Host "Total Finance Users: $($financeUsers.Count)" -ForegroundColor White
Write-Host "Active: $(($financeUsers | Where-Object { $_.IsActive }).Count)" -ForegroundColor Green
Write-Host "Offboarded: $(($financeUsers | Where-Object { -not $_.IsActive }).Count)" -ForegroundColor Red
Write-Host "Groups Analyzed: $($analysis.Count)" -ForegroundColor White

Disconnect-MgGraph
