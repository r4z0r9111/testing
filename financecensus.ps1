<#
.SYNOPSIS
    Finance Department User Census
.DESCRIPTION
    Scans Finance department and analyzes specified groups/DLs for active/offboarded users
.PARAMETER DepartmentName
    Department to scan (default: Finance)
.PARAMETER GroupIds
    Array of group object IDs to analyze
.PARAMETER ExportPath
    Path for output files
.PARAMETER InactivityThresholdDays
    Number of days without sign-in to consider inactive (default: 90)
#>

[CmdletBinding()]
param(
    [string]$DepartmentName = "Finance",
    [string[]]$GroupIds = @(),
    [string]$ExportPath = ".\FinanceCensus_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [int]$InactivityThresholdDays = 90
)

#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Groups

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
        'SignInActivity'
    )
    
    $filter = "department eq '$DepartmentName'"
    $users = Get-MgUser -Filter $filter -Property $properties -All -ConsistencyLevel eventual
    
    $results = foreach ($user in $users) {
        $isActive = $user.AccountEnabled
        $status = if ($isActive) { "Active" } else { "Offboarded" }
        
        # Get last sign-in info
        $lastSignIn = $null
        $daysSinceSignIn = $null
        $signInStatus = "Unknown"
        
        if ($user.SignInActivity.LastSignInDateTime) {
            $lastSignIn = [datetime]$user.SignInActivity.LastSignInDateTime
            $daysSinceSignIn = ((Get-Date) - $lastSignIn).Days
            
            if ($daysSinceSignIn -gt $InactivityThresholdDays) {
                $signInStatus = "Inactive ($daysSinceSignIn days)"
            }
            else {
                $signInStatus = "Active ($daysSinceSignIn days ago)"
            }
        }
        else {
            $signInStatus = "Never signed in"
            $daysSinceSignIn = 999999
        }
        
        # Determine offboarding reason
        $offboardingReason = "N/A"
        if (-not $isActive) {
            $offboardingReason = "Account Disabled"
        }
        elseif ($daysSinceSignIn -gt $InactivityThresholdDays) {
            $offboardingReason = "Inactive for $daysSinceSignIn days"
            $status = "Offboarded (Inactive)"
        }
        
        [PSCustomObject]@{
            Id = $user.Id
            DisplayName = $user.DisplayName
            UserPrincipalName = $user.UserPrincipalName
            Email = $user.Mail
            JobTitle = $user.JobTitle
            Department = $user.Department
            Status = $status
            IsActive = $isActive
            AccountEnabled = $user.AccountEnabled
            OffboardingReason = $offboardingReason
            LastSignInDateTime = $lastSignIn
            DaysSinceLastSignIn = $daysSinceSignIn
            SignInStatus = $signInStatus
            CreatedDate = $user.CreatedDateTime
            OfficeLocation = $user.OfficeLocation
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
            
            $active = $groupFinanceUsers | Where-Object { $_.IsActive -and $_.DaysSinceLastSignIn -le $InactivityThresholdDays }
            $offboarded = $groupFinanceUsers | Where-Object { -not $_.IsActive -or $_.DaysSinceLastSignIn -gt $InactivityThresholdDays }
            
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
    
    # Common properties for all reports
    $commonProps = @(
        'DisplayName',
        'UserPrincipalName',
        'Email',
        'Department',
        'JobTitle',
        'Status',
        'OffboardingReason',
        'LastSignInDateTime',
        'DaysSinceLastSignIn',
        'SignInStatus',
        'AccountEnabled',
        'CreatedDate',
        'OfficeLocation'
    )
    
    # All users with full details
    $allPath = Join-Path $ExportPath "All_Finance_Users.csv"
    $AllUsers | Select-Object ($commonProps + @{N='GroupMemberships';E={$_.Groups -join ';'}}) | Export-Csv -Path $allPath -NoTypeInformation
    
    # Active only
    $activePath = Join-Path $ExportPath "Active_Users.csv"
    $AllUsers | Where-Object { $_.Status -eq "Active" } | Select-Object $commonProps | Export-Csv -Path $activePath -NoTypeInformation
    
    # Offboarded only with reasons
    $offPath = Join-Path $ExportPath "Offboarded_Users.csv"
    $AllUsers | Where-Object { $_.Status -ne "Active" } | Select-Object $commonProps | Export-Csv -Path $offPath -NoTypeInformation
    
    # Group details
    foreach ($group in $GroupResults) {
        $safeName = $group.GroupName -replace '[\\/:*?"<>|]', '_'
        
        if ($group.ActiveUsers.Count -gt 0) {
            $group.ActiveUsers | Select-Object $commonProps | Export-Csv -Path (Join-Path $ExportPath "$safeName`_Active.csv") -NoTypeInformation
        }
        
        if ($group.OffboardedUsers.Count -gt 0) {
            $group.OffboardedUsers | Select-Object $commonProps | Export-Csv -Path (Join-Path $ExportPath "$safeName`_Offboarded_RISK.csv") -NoTypeInformation
        }
    }
    
    # Security report - offboarded users still in groups
    $risks = $AllUsers | Where-Object { $_.Status -ne "Active" -and $_.Groups.Count -gt 0 }
    if ($risks.Count -gt 0) {
        $riskPath = Join-Path $ExportPath "SECURITY_RISK_Offboarded_In_Groups.csv"
        $risks | Select-Object ($commonProps + @{N='GroupMemberships';E={$_.Groups -join ';'}}) | Export-Csv -Path $riskPath -NoTypeInformation
    }
    
    # Summary report
    $summaryPath = Join-Path $ExportPath "Census_Summary.txt"
    $summary = @"
Finance Department Census Summary
Generated: $(Get-Date)
Department: $DepartmentName
Inactivity Threshold: $InactivityThresholdDays days

TOTAL USERS: $($AllUsers.Count)
- Active: $(($AllUsers | Where-Object { $_.Status -eq "Active" }).Count)
- Offboarded: $(($AllUsers | Where-Object { $_.Status -ne "Active" }).Count)

OFFBOARDING BREAKDOWN:
- Account Disabled: $(($AllUsers | Where-Object { $_.OffboardingReason -eq "Account Disabled" }).Count)
- Inactive > $InactivityThresholdDays days: $(($AllUsers | Where-Object { $_.OffboardingReason -like "Inactive*" }).Count)
- Never Signed In: $(($AllUsers | Where-Object { $_.SignInStatus -eq "Never signed in" }).Count)

GROUPS ANALYZED: $($GroupResults.Count)
$(foreach ($g in $GroupResults) { "- $($g.GroupName): $($g.Total) total, $($g.Offboarded) offboarded`n" })

SECURITY RISKS:
$(if ($risks.Count -gt 0) { "$($risks.Count) offboarded users still have group memberships!" } else { "None - all offboarded users removed from groups" })
"@
    $summary | Out-File -FilePath $summaryPath
    
    Write-Host "`nReports saved to: $ExportPath" -ForegroundColor Green
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

Write-Host "`nCensus Complete" -ForegroundColor Green
Write-Host "Total Finance Users: $($financeUsers.Count)" -ForegroundColor White
Write-Host "Active: $(($financeUsers | Where-Object { $_.Status -eq "Active" }).Count)" -ForegroundColor Green
Write-Host "Offboarded: $(($AllUsers | Where-Object { $_.Status -ne "Active" }).Count)" -ForegroundColor Red
Write-Host "Groups Analyzed: $($analysis.Count)" -ForegroundColor White

Disconnect-MgGraph
