<#
.SYNOPSIS
    Finance Department User Census with Flexible Group/DL Selection
    
.DESCRIPTION
    Scans entire Finance department AND specific groups/DLs you specify.
    Identifies active vs offboarded users in both contexts.
    
.PARAMETER GroupNames
    Array of group/DL display names to analyze (e.g., "Finance-Team", "All-Finance-Managers")
    
.PARAMETER GroupIds
    Array of group/DL Object IDs (alternative to names)
    
.PARAMETER SearchAllFinanceGroups
    Automatically find and analyze all groups that contain Finance users
#>

[CmdletBinding()]
param (
    [string]$DepartmentName = "Finance",
    
    [Parameter(Mandatory = $false)]
    [string[]]$GroupNames = @(),  # NEW: Use friendly names instead of IDs
    
    [Parameter(Mandatory = $false)]
    [string[]]$GroupIds = @(),
    
    [Parameter(Mandatory = $false)]
    [switch]$SearchAllFinanceGroups,  # NEW: Auto-discover Finance-related groups
    
    [string]$ExportPath = ".\FinanceCensus_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch]$IncludeSignInActivity,
    [switch]$IncludeTransitiveMembers
)

# Initialize
$script:Results = @{
    DepartmentUsers = @()
    GroupAnalysis = @{}
    Summary = @{}
}

function Connect-GraphEnvironment {
    $scopes = @(
        "User.Read.All",
        "GroupMember.Read.All",
        "Directory.Read.All",
        "Group.Read.All"  # Added to search groups by name
    )
    if ($IncludeSignInActivity) { $scopes += "AuditLog.Read.All" }
    
    Connect-MgGraph -Scopes $scopes -NoWelcome
    Write-Host "Connected to Microsoft Graph" -ForegroundColor Green
}

function Resolve-GroupsToAnalyze {
    <#
    .SYNOPSIS
        Convert group names to IDs and discover Finance-related groups
    #>
    [CmdletBinding()]
    param()
    
    $targetGroups = @()
    
    # Method 1: Use provided Group IDs directly
    if ($GroupIds.Count -gt 0) {
        Write-Host "`nUsing provided Group IDs..." -ForegroundColor Cyan
        foreach ($id in $GroupIds) {
            try {
                $group = Get-MgGroup -GroupId $id -Property "Id,DisplayName,Description,GroupTypes,MailEnabled,SecurityEnabled"
                $targetGroups += $group
                Write-Host "  ✓ Found: $($group.DisplayName) [$($group.Id)]" -ForegroundColor Green
            }
            catch {
                Write-Warning "  ✗ Group ID not found: $id"
            }
        }
    }
    
    # Method 2: Search by Group Names (NEW)
    if ($GroupNames.Count -gt 0) {
        Write-Host "`nResolving Group Names to IDs..." -ForegroundColor Cyan
        foreach ($name in $GroupNames) {
            try {
                # Search for exact match or partial match
                $groups = Get-MgGroup -Filter "startswith(DisplayName,'$name')" -All | 
                          Where-Object { $_.DisplayName -eq $name -or $_.DisplayName -like "*$name*" }
                
                if ($groups.Count -eq 1) {
                    $targetGroups += $groups[0]
                    Write-Host "  ✓ Found: $($groups[0].DisplayName) [$($groups[0].Id)]" -ForegroundColor Green
                }
                elseif ($groups.Count -gt 1) {
                    Write-Host "  Multiple matches for '$name':" -ForegroundColor Yellow
                    $groups | ForEach-Object { 
                        Write-Host "    - $($_.DisplayName) [$($_.Id)]" -ForegroundColor Gray
                        $targetGroups += $_
                    }
                }
                else {
                    Write-Warning "  ✗ No group found matching: $name"
                }
            }
            catch {
                Write-Warning "  ✗ Error searching for group: $name"
            }
        }
    }
    
    # Method 3: Auto-discover all groups containing Finance users (NEW)
    if ($SearchAllFinanceGroups) {
        Write-Host "`nAuto-discovering groups with Finance members..." -ForegroundColor Cyan
        
        # Get all groups (this might take time in large tenants)
        $allGroups = Get-MgGroup -All -Property "Id,DisplayName,Description"
        Write-Host "  Scanning $($allGroups.Count) total groups..." -ForegroundColor Gray
        
        $financeUserIds = $script:Results.DepartmentUsers.Id
        
        foreach ($group in $allGroups | Select-Object -First 100) {  # Limit to prevent throttling
            try {
                $members = Get-MgGroupMember -GroupId $group.Id -All
                $financeMembers = $members | Where-Object { 
                    $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user' -and 
                    $financeUserIds -contains $_.Id 
                }
                
                if ($financeMembers.Count -gt 0) {
                    $targetGroups += $group
                    Write-Host "  ✓ $($group.DisplayName): $($financeMembers.Count) Finance members" -ForegroundColor Green
                }
            }
            catch {
                # Continue on error (likely permissions or large group)
            }
        }
    }
    
    # Remove duplicates
    $uniqueGroups = $targetGroups | Group-Object Id | ForEach-Object { $_.Group[0] }
    
    Write-Host "`nTotal groups to analyze: $($uniqueGroups.Count)" -ForegroundColor Cyan
    return $uniqueGroups
}

function Get-DepartmentCensus {
    <#
    .SYNOPSIS
        Get all Finance department users (the foundation)
    #>
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host "  SCANNING ENTIRE $DepartmentName DEPARTMENT" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    
    $properties = @(
        'Id', 'DisplayName', 'UserPrincipalName', 'Mail', 'JobTitle',
        'Department', 'AccountEnabled', 'CreatedDateTime', 
        'LastPasswordChangeDateTime', 'OfficeLocation', 'CompanyName'
    )
    if ($IncludeSignInActivity) { $properties += 'SignInActivity' }
    
    # Get ALL Finance users (active + offboarded)
    $filter = "department eq '$DepartmentName'"
    
    Write-Host "`nQuerying: $filter" -ForegroundColor Gray
    $users = Get-MgUser -Filter $filter -Property $properties -All
    
    $processedUsers = foreach ($user in $users) {
        $status = if ($user.AccountEnabled) { "Active" } else { "Offboarded" }
        
        # Calculate days since last sign-in
        $lastSignIn = $null
        $daysInactive = $null
        if ($IncludeSignInActivity -and $user.SignInActivity.LastSignInDateTime) {
            $lastSignIn = [datetime]$user.SignInActivity.LastSignInDateTime
            $daysInactive = ((Get-Date) - $lastSignIn).Days
        }
        
        [PSCustomObject]@{
            Id = $user.Id
            DisplayName = $user.DisplayName
            UserPrincipalName = $user.UserPrincipalName
            Email = $user.Mail
            JobTitle = $user.JobTitle
            Department = $user.Department
            Status = $status
            IsActive = $user.AccountEnabled
            CreatedDate = $user.CreatedDateTime
            LastPasswordChange = $user.LastPasswordChangeDateTime
            LastSignInDateTime = $lastSignIn
            DaysSinceLastSignIn = $daysInactive
            OfficeLocation = $user.OfficeLocation
            CompanyName = $user.CompanyName
            Groups = @()  # Will be populated later
        }
    }
    
    $script:Results.DepartmentUsers = $processedUsers
    
    # Display Department Summary
    $active = $processedUsers | Where-Object { $_.IsActive }
    $offboarded = $processedUsers | Where-Object { -not $_.IsActive }
    
    Write-Host "`n📊 DEPARTMENT CENSUS RESULTS:" -ForegroundColor Yellow
    Write-Host "  Total Finance Users:     $($processedUsers.Count)" -ForegroundColor White
    Write-Host "  ├── Active Employees:    $($active.Count)" -ForegroundColor Green
    Write-Host "  └── Offboarded/Disabled: $($offboarded.Count)" -ForegroundColor Red
    
    if ($offboarded.Count -gt 0) {
        Write-Host "`n  ⚠ Offboarded users still in directory:" -ForegroundColor Yellow
        $offboarded | Select-Object -First 5 | ForEach-Object {
            Write-Host "    - $($_.DisplayName) ($($_.UserPrincipalName))" -ForegroundColor Gray
        }
        if ($offboarded.Count -gt 5) {
            Write-Host "    ... and $($offboarded.Count - 5) more" -ForegroundColor Gray
        }
    }
    
    return $processedUsers
}

function Analyze-Groups {
    <#
    .SYNOPSIS
        Analyze specific groups for Finance user membership
    #>
    param([array]$GroupsToAnalyze)
    
    if ($GroupsToAnalyze.Count -eq 0) { return @() }
    
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host "  ANALYZING SPECIFIC GROUPS/DLs" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    
    $groupResults = @()
    $financeUserIds = $script:Results.DepartmentUsers.Id
    
    foreach ($group in $GroupsToAnalyze) {
        Write-Host "`n📁 Group: $($group.DisplayName)" -ForegroundColor Cyan
        Write-Host "   ID: $($group.Id)" -ForegroundColor Gray
        Write-Host "   Type: $(if ($group.GroupTypes -contains 'Unified') { 'Microsoft 365' } else { if ($group.MailEnabled) { 'Distribution List' } else { 'Security Group' } })" -ForegroundColor Gray
        
        try {
            # Get members (direct or transitive)
            $members = if ($IncludeTransitiveMembers) {
                Get-MgGroupTransitiveMember -GroupId $group.Id -All
            } else {
                Get-MgGroupMember -GroupId $group.Id -All
            }
            
            # Filter to Finance users only
            $financeMembers = @()
            foreach ($member in $members) {
                if ($member.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
                    $user = $script:Results.DepartmentUsers | Where-Object { $_.Id -eq $member.Id }
                    if ($user) {
                        $financeMembers += $user
                        # Add group name to user's group list
                        ($script:Results.DepartmentUsers | Where-Object { $_.Id -eq $member.Id }).Groups += $group.DisplayName
                    }
                }
            }
            
            # Categorize by status
            $activeInGroup = $financeMembers | Where-Object { $_.IsActive }
            $offboardedInGroup = $financeMembers | Where-Object { -not $_.IsActive }
            
            $result = [PSCustomObject]@{
                GroupId = $group.Id
                GroupName = $group.DisplayName
                GroupType = if ($group.GroupTypes -contains 'Unified') { 'Microsoft 365' } else { if ($group.MailEnabled) { 'DL' } else { 'Security' } }
                TotalMembers = $financeMembers.Count
                ActiveMembers = $activeInGroup.Count
                OffboardedMembers = $offboardedInGroup.Count
                ActiveUsers = $activeInGroup
                OffboardedUsers = $offboardedInGroup
                RiskLevel = if ($offboardedInGroup.Count -gt 0) { "HIGH" } else { "LOW" }
            }
            
            $groupResults += $result
            $script:Results.GroupAnalysis[$group.Id] = $result
            
            # Display results
            Write-Host "   Finance Members: $($financeMembers.Count)" -ForegroundColor White
            Write-Host "   ├── Active:    $($activeInGroup.Count)" -ForegroundColor Green
            Write-Host "   └── Offboarded: $($offboardedInGroup.Count)" -ForegroundColor $(if ($offboardedInGroup.Count -gt 0) { "Red" } else { "Gray" })
            
            if ($offboardedInGroup.Count -gt 0) {
                Write-Host "   🚨 SECURITY RISK: Offboarded users have group access!" -ForegroundColor Red
                $offboardedInGroup | ForEach-Object {
                    Write-Host "      • $($_.DisplayName) - $($_.UserPrincipalName)" -ForegroundColor Yellow
                }
            }
        }
        catch {
            Write-Warning "   Error analyzing group: $_"
        }
    }
    
    return $groupResults
}

function Generate-Reports {
    <#
    .SYNOPSIS
        Export comprehensive reports
    #>
    param([array]$GroupResults)
    
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host "  GENERATING REPORTS" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    
    New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
    
    # 1. Master Department Report
    $deptReport = $script:Results.DepartmentUsers | Select-Object @(
        'Id', 'DisplayName', 'UserPrincipalName', 'Email', 'JobTitle',
        'Status', 'IsActive', 'CreatedDate', 'LastPasswordChange',
        'LastSignInDateTime', 'DaysSinceLastSignIn',
        @{Name='GroupMemberships'; Expression={$_.Groups -join '; '}}
    )
    $deptPath = Join-Path $ExportPath "01_Finance_Department_ALL_USERS.csv"
    $deptReport | Export-Csv -Path $deptPath -NoTypeInformation
    Write-Host "✓ Department census: $deptPath" -ForegroundColor Green
    
    # 2. Active Users Only
    $activePath = Join-Path $ExportPath "02_Finance_Active_Users.csv"
    $deptReport | Where-Object { $_.IsActive } | Export-Csv -Path $activePath -NoTypeInformation
    Write-Host "✓ Active users: $activePath" -ForegroundColor Green
    
    # 3. Offboarded Users Only
    $offboardedPath = Join-Path $ExportPath "03_Finance_Offboarded_Users.csv"
    $deptReport | Where-Object { -not $_.IsActive } | Export-Csv -Path $offboardedPath -NoTypeInformation
    Write-Host "✓ Offboarded users: $offboardedPath" -ForegroundColor Green
    
    # 4. Per-Group Reports
    if ($GroupResults.Count -gt 0) {
        $groupsPath = Join-Path $ExportPath "04_Group_Analysis"
        New-Item -ItemType Directory -Path $groupsPath -Force | Out-Null
        
        foreach ($group in $GroupResults) {
            $safeName = ($group.GroupName -replace '[\\/:*?"<>|]', '_')
            
            # Summary
            $summary = [PSCustomObject]@{
                GroupName = $group.GroupName
                GroupId = $group.GroupId
                GroupType = $group.GroupType
                TotalFinanceMembers = $group.TotalMembers
                ActiveMembers = $group.ActiveMembers
                OffboardedMembers = $group.OffboardedMembers
                RiskLevel = $group.RiskLevel
                AnalysisDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            $summary | Export-Csv -Path (Join-Path $groupsPath "$safeName`_SUMMARY.csv") -NoTypeInformation
            
            # Active members
            if ($group.ActiveUsers.Count -gt 0) {
                $group.ActiveUsers | Export-Csv -Path (Join-Path $groupsPath "$safeName`_ACTIVE.csv") -NoTypeInformation
            }
            
            # Offboarded members (CRITICAL)
            if ($group.OffboardedUsers.Count -gt 0) {
                $group.OffboardedUsers | Export-Csv -Path (Join-Path $groupsPath "$safeName`_OFFBOARDED_RISK.csv") -NoTypeInformation
            }
        }
        Write-Host "✓ Group analysis: $groupsPath" -ForegroundColor Green
    }
    
    # 5. Security Audit Report (Offboarded with Access)
    $securityRisk = $script:Results.DepartmentUsers | Where-Object { 
        -not $_.IsActive -and $_.Groups.Count -gt 0 
    }
    if ($securityRisk.Count -gt 0) {
        $riskPath = Join-Path $ExportPath "05_SECURITY_RISK_Offboarded_With_Group_Access.csv"
        $securityRisk | Select-Object DisplayName, UserPrincipalName, Email, @{Name='Groups'; Expression={$_.Groups -join '; '}} |
            Export-Csv -Path $riskPath -NoTypeInformation
        Write-Host "✓ SECURITY RISK REPORT: $riskPath" -ForegroundColor Red
    }
    
    # 6. JSON Summary for automation
    $jsonSummary = @{
        ReportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Department = $DepartmentName
        TotalUsers = $script:Results.DepartmentUsers.Count
        ActiveUsers = ($script:Results.DepartmentUsers | Where-Object { $_.IsActive }).Count
        OffboardedUsers = ($script:Results.DepartmentUsers | Where-Object { -not $_.IsActive }).Count
        GroupsAnalyzed = $GroupResults | Select-Object GroupName, GroupType, TotalMembers, ActiveMembers, OffboardedMembers, RiskLevel
        SecurityRisks = $securityRisk.Count
    }
    $jsonPath = Join-Path $ExportPath "Census_Summary.json"
    $jsonSummary | ConvertTo-Json -Depth 4 | Out-File -FilePath $jsonPath
    Write-Host "✓ JSON summary: $jsonPath" -ForegroundColor Green
    
    Write-Host "`n📁 All reports saved to: $ExportPath" -ForegroundColor Cyan
}

# ==================== MAIN ====================

Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║     Finance Department User Census Tool v2.1                 ║
║     Department-Wide + Specific Group/DL Analysis             ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Connect
Connect-GraphEnvironment

# Step 1: Always scan entire department first
Get-DepartmentCensus

# Step 2: Resolve and analyze specific groups/DLs
$groupsToCheck = Resolve-GroupsToAnalyze
$groupAnalysis = Analyze-Groups -GroupsToAnalyze $groupsToCheck

# Step 3: Generate reports
Generate-Reports -GroupResults $groupAnalysis

# Final Summary
Write-Host "`n" + ("=" * 60) -ForegroundColor Green
Write-Host "  CENSUS COMPLETE" -ForegroundColor Green
Write-Host ("=" * 60) -ForegroundColor Green
Write-Host "`nSummary:" -ForegroundColor Yellow
Write-Host "  • Department: $DepartmentName" -ForegroundColor White
Write-Host "  • Total Users: $($script:Results.DepartmentUsers.Count)" -ForegroundColor White
Write-Host "  • Groups Analyzed: $($groupsToCheck.Count)" -ForegroundColor White
if ($groupAnalysis.OffboardedMembers -gt 0) {
    Write-Host "  • SECURITY ALERTS: $($groupAnalysis.OffboardedMembers) offboarded users in groups!" -ForegroundColor Red
}

Disconnect-MgGraph | Out-Null
