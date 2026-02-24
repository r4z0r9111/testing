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
    Days without sign-in to consider inactive (default: 90)
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
        $isActive = $user.AccountEnabled
        $status = if ($isActive) { "Active" } else { "Offboarded" }
        
        $lastSignIn = $null
        $daysSinceSignIn = $null
        $signInStatus = "Unknown"
        $offboardingReason = "N/A"
        
        if ($IncludeSignInActivity -and $user.SignInActivity.LastSignInDateTime) {
            $lastSignIn = [datetime]$user.SignInActivity.LastSignInDateTime
            $daysSinceSignIn = ((Get-Date) - $lastSignIn).Days
            
            if ($daysSinceSignIn -gt $InactivityThresholdDays) {
                $signInStatus = "Inactive ($daysSinceSignIn days)"
                if ($isActive) {
                    $status = "Offboarded (Inactive)"
                    $offboardingReason = "No sign-in for $daysSinceSignIn days"
                }
            }
            else {
                $signInStatus = "Active (last sign-in $daysSinceSignIn days ago)"
            }
        }
        else {
            $signInStatus = "No sign-in data"
            if ($isActive) {
                $offboardingReason = "Account enabled but no recent sign-in data"
            }
        }
        
        if (-not $isActive) {
            $offboardingReason = "Account disabled in Azure AD"
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
            OffboardingReason = $offboardingReason
            LastSignInDate = $lastSignIn
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
            
            $active = $groupFinanceUsers | Where-Object { $_.IsActive -and ($_.DaysSinceLastSignIn -lt $InactivityThresholdDays -or $_.DaysSinceLastSignIn -eq $null) }
            $offboarded = $groupFinanceUsers | Where-Object { -not $_.IsActive -or $_.DaysSinceLastSignIn -ge $InactivityThresholdDays }
            
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
    
    $allPath = Join-Path $ExportPath "All_Finance_Users.csv"
    $AllUsers | Select-Object Id, DisplayName, UserPrincipalName, Email, Department, JobTitle, Status, OffboardingReason, IsActive, LastSignInDate, DaysSinceLastSignIn, SignInStatus, CreatedDate, OfficeLocation, @{N='Groups';E={$_.Groups -join ';'}} | Export-Csv -Path $allPath -NoTypeInformation
    
    $activePath = Join-Path $ExportPath "Active_Users.csv"
    $AllUsers | Where-Object { $_.Status -eq "Active" } | Select-Object DisplayName, UserPrincipalName, Email, Department, JobTitle, LastSignInDate, DaysSinceLastSignIn, SignInStatus, OfficeLocation | Export-Csv -Path $activePath -NoTypeInformation
    
    $offPath = Join-Path $ExportPath "Offboarded_Users.csv"
    $AllUsers | Where-Object { $_.Status -ne "Active" } | Select-Object DisplayName, UserPrincipalName, Email, Department, JobTitle, Status, OffboardingReason, LastSignInDate, DaysSinceLastSignIn, IsActive, OfficeLocation | Export-Csv -Path $offPath -NoTypeInformation
    
    foreach ($group in $GroupResults) {
        $safeName = $group.GroupName -replace '[\\/:*?"<>|]', '_'
        
        if ($group.ActiveUsers.Count -gt 0) {
            $group.ActiveUsers | Select-Object DisplayName, UserPrincipalName, Email, Department, JobTitle, LastSignInDate, DaysSinceLastSignIn, SignInStatus | Export-Csv -Path (Join-Path $ExportPath "$safeName`_Active.csv") -NoTypeInformation
        }
        
        if ($group.OffboardedUsers.Count -gt 0) {
            $group.OffboardedUsers | Select-Object DisplayName, UserPrincipalName, Email, Department, JobTitle, Status, OffboardingReason, LastSignInDate, DaysSinceLastSignIn, IsActive | Export-Csv -Path (Join-Path $ExportPath "$safeName`_Offboarded_RISK.csv") -NoTypeInformation
        }
    }
    
    $risks = $AllUsers | Where-Object { $_.Status -ne "Active" -and $_.Groups.Count -gt 0 }
    if ($risks.Count -gt 0) {
        $riskPath = Join-Path $ExportPath "SECURITY_RISK_Offboarded_In_Groups.csv"
        $risks | Select-Object DisplayName, UserPrincipalName, Email, Department, JobTitle, Status, OffboardingReason, LastSignInDate, DaysSinceLastSignIn, @{N='GroupMemberships';E={$_.Groups -join ';'}} | Export-Csv -Path $riskPath -NoTypeInformation
    }
    
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
Write-Host "Offboarded: $(($financeUsers | Where-Object { $_.Status -ne "Active" }).Count)" -ForegroundColor Red
Write-Host "Groups Analyzed: $($analysis.Count)" -ForegroundColor White

Disconnect-MgGraph
