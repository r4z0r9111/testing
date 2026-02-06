<#
.SYNOPSIS
    User Offboarding Compliance Checklist Auditor
.DESCRIPTION
    Performs a comprehensive audit of user offboarding status using Microsoft Graph API.
    Handles permission errors and provides guidance on required roles.
#>

#region Prerequisites Check

$requiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.Identity.SignIns"
)

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "ERROR: Missing module $module" -ForegroundColor Red
        Write-Host "Install with: Install-Module Microsoft.Graph -Scope CurrentUser -Force" -ForegroundColor Yellow
        exit 1
    }
    Import-Module $module -ErrorAction Stop
}

#endregion

#region Configuration

$PrivilegedGroupPatterns = @(
    "*Administrator*",
    "*Admin*",
    "*Owner*",
    "*Domain*",
    "*Enterprise*",
    "*Security*",
    "*Compliance*",
    "*Audit*",
    "*Global*",
    "*Privileged*",
    "*Emergency*"
)

#endregion

#region Helper Functions

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host "       USER OFFBOARDING COMPLIANCE CHECKLIST AUDITOR" -ForegroundColor Cyan
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Read-EmailInput {
    param([string]$PromptMessage)
    
    do {
        Write-Host $PromptMessage -ForegroundColor Yellow -NoNewline
        $email = Read-Host
        
        if ($email -match '^[\w\.-]+@[\w\.-]+\.\w+$') {
            return $email.ToLower().Trim()
        }
        
        Write-Host "    Invalid email format. Please try again." -ForegroundColor Red
    } while ($true)
}

function Write-SectionHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host "---------------------------------------------------------------" -ForegroundColor Blue
    Write-Host " $Title" -ForegroundColor Blue
    Write-Host "---------------------------------------------------------------" -ForegroundColor Blue
}

function Write-CheckItem {
    param(
        [string]$Category,
        [string]$Item,
        [ValidateSet("PASS", "FAIL", "WARNING", "INFO", "MANUAL", "ERROR")]
        [string]$Status,
        [string]$Details = "",
        [string]$Recommendation = ""
    )
    
    $icon = switch ($Status) {
        "PASS" { "[OK] " }
        "FAIL" { "[FAIL] " }
        "WARNING" { "[WARN] " }
        "INFO" { "[INFO] " }
        "MANUAL" { "[MANUAL] " }
        "ERROR" { "[ERROR] " }
    }
    
    $color = switch ($Status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "WARNING" { "Yellow" }
        "INFO" { "White" }
        "MANUAL" { "Cyan" }
        "ERROR" { "Red" }
    }
    
    Write-Host "  $icon" -NoNewline
    Write-Host "$Category" -ForegroundColor Gray -NoNewline
    Write-Host " -> " -NoNewline
    Write-Host "$Item" -ForegroundColor White -NoNewline
    
    if ($Details) {
        Write-Host " [$Details]" -ForegroundColor $color
    }
    else {
        Write-Host ""
    }
    
    if ($Recommendation) {
        Write-Host "      Recommendation: $Recommendation" -ForegroundColor DarkYellow
    }
}

function Test-GraphPermissions {
    try {
        # Test basic read access
        $testUser = Get-MgUser -Top 1 -ErrorAction Stop
        Write-Host "Graph API access verified." -ForegroundColor Green
        return $true
    }
    catch {
        $errorMsg = $_.Exception.Message
        
        if ($errorMsg -like "*Authorization_RequestDenied*" -or 
            $errorMsg -like "*unauthorized*" -or
            $errorMsg -like "*Insufficient privileges*") {
            
            Write-Host ""
            Write-Host "PERMISSION ERROR: Your account lacks required permissions." -ForegroundColor Red
            Write-Host ""
            Write-Host "Required Azure AD Role: Global Reader or Global Administrator" -ForegroundColor Yellow
            Write-Host "OR delegated permissions with admin consent:" -ForegroundColor Yellow
            Write-Host "  - User.Read.All" -ForegroundColor Gray
            Write-Host "  - Group.Read.All" -ForegroundColor Gray
            Write-Host "  - Directory.Read.All" -ForegroundColor Gray
            Write-Host "  - AuditLog.Read.All" -ForegroundColor Gray
            Write-Host "  - Application.Read.All" -ForegroundColor Gray
            Write-Host ""
            Write-Host "To fix this:" -ForegroundColor Cyan
            Write-Host "1. Ensure you have Global Reader role in Azure AD" -ForegroundColor White
            Write-Host "2. Or run Connect-MgGraph with -TenantId and ensure admin consent" -ForegroundColor White
            Write-Host "3. Check that your organization allows Graph API access" -ForegroundColor White
            Write-Host ""
            return $false
        }
        
        Write-Host "Graph API Error: $errorMsg" -ForegroundColor Red
        return $false
    }
}

#endregion

#region Check Functions

function Test-UserAccountStatus {
    param([object]$User)
    
    $checks = @()
    $findings = @()
    
    Write-SectionHeader "1. ACCOUNT STATUS"
    
    # Check if account is disabled
    if ($User.AccountEnabled -eq $false) {
        $checks += @{Category="Account"; Item="Status"; Status="PASS"; Details="Account is disabled"; Risk="NONE"}
        Write-CheckItem -Category "Account" -Item "Status" -Status "PASS" -Details "Account is disabled"
    }
    else {
        $checks += @{Category="Account"; Item="Status"; Status="FAIL"; Details="Account is still ENABLED"; Risk="CRITICAL"}
        $findings += @{Risk="CRITICAL"; Issue="Account is still active"; Action="Disable account immediately in Azure AD"}
        Write-CheckItem -Category "Account" -Item "Status" -Status "FAIL" -Details "Account is still ENABLED" -Recommendation "Disable account immediately"
    }
    
    # Check recent sign-ins
    if ($User.SignInActivity -and $User.SignInActivity.LastSignInDateTime) {
        $lastDate = [datetime]$User.SignInActivity.LastSignInDateTime
        $daysAgo = ((Get-Date) - $lastDate).Days
        
        if ($daysAgo -gt 30) {
            $checks += @{Category="Account"; Item="Recent Sign-in"; Status="PASS"; Details="No sign-ins for $daysAgo days"; Risk="NONE"}
            Write-CheckItem -Category "Account" -Item "Recent Sign-in" -Status "PASS" -Details "Last sign-in: $daysAgo days ago"
        }
        else {
            $checks += @{Category="Account"; Item="Recent Sign-in"; Status="WARNING"; Details="Recent sign-in: $daysAgo days ago"; Risk="HIGH"}
            $findings += @{Risk="HIGH"; Issue="Recent activity detected"; Action="Review audit logs for recent activity"}
            Write-CheckItem -Category "Account" -Item "Recent Sign-in" -Status "WARNING" -Details "Recent sign-in: $daysAgo days ago" -Recommendation "Review recent activity"
        }
    }
    else {
        $checks += @{Category="Account"; Item="Sign-in History"; Status="INFO"; Details="No sign-in data available"; Risk="NONE"}
        Write-CheckItem -Category "Account" -Item "Sign-in History" -Status "INFO" -Details "No recent sign-in data"
    }
    
    # Manual check for token revocation
    $checks += @{Category="Account"; Item="Token Revocation"; Status="MANUAL"; Details="Verify refresh tokens revoked"; Risk="MEDIUM"}
    Write-CheckItem -Category "Account" -Item "Token Revocation" -Status "MANUAL" -Details "Manual verification required" -Recommendation "Run Revoke-MgUserSignInSession"
    
    return $checks, $findings
}

function Test-LicenseStatus {
    param([string]$UserId)
    
    $checks = @()
    $findings = @()
    
    Write-SectionHeader "2. LICENSE STATUS"
    
    try {
        $licenses = Get-MgUserLicenseDetail -UserId $UserId -ErrorAction Stop
        
        if ($licenses.Count -eq 0) {
            $checks += @{Category="License"; Item="Assignment"; Status="PASS"; Details="All licenses removed"; Risk="NONE"}
            Write-CheckItem -Category "License" -Item "Assignment" -Status "PASS" -Details "No licenses assigned"
        }
        else {
            $skuList = $licenses | ForEach-Object { $_.SkuPartNumber }
            $skuString = $skuList -join ", "
            $checks += @{Category="License"; Item="Assignment"; Status="FAIL"; Details="$($licenses.Count) licenses active"; Risk="HIGH"}
            $findings += @{Risk="HIGH"; Issue="Licenses still assigned: $skuString"; Action="Remove all licenses in M365 Admin Center"}
            Write-CheckItem -Category "License" -Item "Assignment" -Status "FAIL" -Details "$($licenses.Count) licenses: $skuString" -Recommendation "Remove all licenses"
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        if ($errorMsg -like "*Authorization_RequestDenied*") {
            $checks += @{Category="License"; Item="Check"; Status="ERROR"; Details="Permission denied"; Risk="MEDIUM"}
            Write-CheckItem -Category "License" -Item "Check" -Status "ERROR" -Details "Insufficient permissions to read licenses" -Recommendation "Requires User.Read.All permission"
        }
        else {
            $checks += @{Category="License"; Item="Check"; Status="WARNING"; Details="Error retrieving licenses"; Risk="MEDIUM"}
            Write-CheckItem -Category "License" -Item "Check" -Status "WARNING" -Details "Unable to retrieve"
        }
    }
    
    return $checks, $findings
}

function Test-GroupMemberships {
    param([string]$UserId)
    
    $checks = @()
    $findings = @()
    
    Write-SectionHeader "3. GROUP MEMBERSHIPS"
    
    try {
        $groups = Get-MgUserTransitiveMemberOf -UserId $UserId -All -ErrorAction Stop | 
            Where-Object { $_.'@odata.type' -eq "#microsoft.graph.group" }
        
        if ($groups.Count -eq 0) {
            $checks += @{Category="Groups"; Item="Memberships"; Status="PASS"; Details="No group memberships"; Risk="NONE"}
            Write-CheckItem -Category "Groups" -Item "Memberships" -Status "PASS" -Details "User removed from all groups"
        }
        else {
            $privileged = @()
            $standard = @()
            
            foreach ($group in $groups) {
                try {
                    $detail = Get-MgGroup -GroupId $group.Id -Property "displayName,isAssignableToRole" -ErrorAction Stop
                    $isPriv = $false
                    
                    foreach ($pattern in $PrivilegedGroupPatterns) {
                        if ($detail.DisplayName -like $pattern) { 
                            $isPriv = $true
                            break 
                        }
                    }
                    
                    if ($detail.IsAssignableToRole -eq $true -or $isPriv) {
                        $privileged += $detail.DisplayName
                    }
                    else {
                        $standard += $detail.DisplayName
                    }
                }
                catch {
                    $standard += "Unknown (ID: $($group.Id))"
                }
            }
            
            if ($privileged.Count -gt 0) {
                $checks += @{Category="Groups"; Item="Privileged Access"; Status="FAIL"; Details="$($privileged.Count) privileged groups"; Risk="CRITICAL"}
                $findings += @{Risk="CRITICAL"; Issue="Access to privileged groups"; Action="Remove from all privileged groups immediately"}
                Write-CheckItem -Category "Groups" -Item "Privileged Access" -Status "FAIL" -Details "$($privileged.Count) admin groups" -Recommendation "Remove from privileged groups"
                foreach ($p in $privileged) {
                    Write-Host "      ! $p" -ForegroundColor Red
                }
            }
            else {
                $checks += @{Category="Groups"; Item="Privileged Access"; Status="PASS"; Details="No privileged groups"; Risk="NONE"}
                Write-CheckItem -Category "Groups" -Item "Privileged Access" -Status "PASS" -Details "No admin groups"
            }
            
            if ($standard.Count -gt 0) {
                $checks += @{Category="Groups"; Item="Standard Groups"; Status="WARNING"; Details="$($standard.Count) groups remain"; Risk="MEDIUM"}
                Write-CheckItem -Category "Groups" -Item "Standard Groups" -Status "WARNING" -Details "$($standard.Count) groups" -Recommendation "Remove non-essential groups"
            }
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        if ($errorMsg -like "*Authorization_RequestDenied*") {
            $checks += @{Category="Groups"; Item="Check"; Status="ERROR"; Details="Permission denied"; Risk="MEDIUM"}
            Write-CheckItem -Category "Groups" -Item "Check" -Status "ERROR" -Details "Insufficient permissions to read groups" -Recommendation "Requires Group.Read.All permission"
        }
        else {
            $checks += @{Category="Groups"; Item="Check"; Status="WARNING"; Details="Error retrieving groups"; Risk="MEDIUM"}
            Write-CheckItem -Category "Groups" -Item "Check" -Status "WARNING" -Details "Unable to retrieve"
        }
    }
    
    return $checks, $findings
}

function Test-MailboxStatus {
    $checks = @()
    
    Write-SectionHeader "4. MAILBOX STATUS"
    
    $checks += @{Category="Mailbox"; Item="Litigation Hold"; Status="MANUAL"; Details="Verify in Exchange Admin Center"; Risk="MEDIUM"}
    Write-CheckItem -Category "Mailbox" -Item "Litigation Hold" -Status "MANUAL" -Details "Check EAC" -Recommendation "Enable litigation hold if required"
    
    $checks += @{Category="Mailbox"; Item="Email Forwarding"; Status="MANUAL"; Details="Check for forwarding rules"; Risk="HIGH"}
    Write-CheckItem -Category "Mailbox" -Item "Email Forwarding" -Status "MANUAL" -Details "Check inbox rules" -Recommendation "Remove external forwarding rules"
    
    $checks += @{Category="Mailbox"; Item="Delegate Access"; Status="MANUAL"; Details="Check mailbox permissions"; Risk="MEDIUM"}
    Write-CheckItem -Category "Mailbox" -Item "Delegate Access" -Status "MANUAL" -Details="Check SendAs permissions" -Recommendation "Remove all delegates"
    
    return $checks, @()
}

function Test-TeamsStatus {
    $checks = @()
    
    Write-SectionHeader "5. MICROSOFT TEAMS"
    
    $checks += @{Category="Teams"; Item="Memberships"; Status="MANUAL"; Details="Verify team removal"; Risk="MEDIUM"}
    Write-CheckItem -Category "Teams" -Item "Memberships" -Status "MANUAL" -Details="Check all teams" -Recommendation="Remove from all Teams and channels"
    
    $checks += @{Category="Teams"; Item="File Ownership"; Status="MANUAL"; Details="Transfer ownership"; Risk="HIGH"}
    Write-CheckItem -Category "Teams" -Item "File Ownership" -Status "MANUAL" -Details="Check files in Teams" -Recommendation="Transfer file ownership to manager"
    
    return $checks, @()
}

function Test-ApplicationAccess {
    param([string]$UserId)
    
    $checks = @()
    $findings = @()
    
    Write-SectionHeader "6. APPLICATION ACCESS"
    
    try {
        $appRoles = Get-MgUserAppRoleAssignment -UserId $UserId -ErrorAction Stop
        
        if ($appRoles.Count -gt 0) {
            $checks += @{Category="Apps"; Item="Role Assignments"; Status="FAIL"; Details="$($appRoles.Count) app roles"; Risk="HIGH"}
            $findings += @{Risk="HIGH"; Issue="Application roles assigned"; Action="Remove all enterprise app assignments"}
            Write-CheckItem -Category "Apps" -Item="Role Assignments" -Status "FAIL" -Details="$($appRoles.Count) applications" -Recommendation="Remove app role assignments"
        }
        else {
            $checks += @{Category="Apps"; Item="Role Assignments"; Status="PASS"; Details="No app roles"; Risk="NONE"}
            Write-CheckItem -Category "Apps" -Item="Role Assignments" -Status "PASS" -Details="No application assignments"
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        if ($errorMsg -like "*Authorization_RequestDenied*") {
            $checks += @{Category="Apps"; Item="Check"; Status="ERROR"; Details="Permission denied"; Risk="MEDIUM"}
            Write-CheckItem -Category "Apps" -Item="Check" -Status "ERROR" -Details="Requires Application.Read.All permission" -Recommendation="Grant permission or check as Global Admin"
        }
        else {
            $checks += @{Category="Apps"; Item="Check"; Status="WARNING"; Details="Error retrieving apps"; Risk="MEDIUM"}
            Write-CheckItem -Category "Apps" -Item="Check" -Status "WARNING" -Details="Unable to retrieve"
        }
    }
    
    $checks += @{Category="Apps"; Item="OAuth Consents"; Status="MANUAL"; Details="Verify in Azure AD"; Risk="MEDIUM"}
    Write-CheckItem -Category "Apps" -Item="OAuth Consents" -Status "MANUAL" -Details="Check consents" -Recommendation="Revoke all OAuth consents"
    
    return $checks, $findings
}

function Test-DeviceAccess {
    param([string]$UserId)
    
    $checks = @()
    $findings = @()
    
    Write-SectionHeader "7. DEVICE ACCESS"
    
    try {
        $devices = Get-MgUserRegisteredDevice -UserId $UserId -All -ErrorAction Stop
        
        if ($devices.Count -gt 0) {
            $checks += @{Category="Devices"; Item="Registered Devices"; Status="WARNING"; Details="$($devices.Count) devices"; Risk="MEDIUM"}
            $findings += @{Risk="MEDIUM"; Issue="Devices still registered"; Action="Retire/wipe devices in Endpoint Manager"}
            Write-CheckItem -Category "Devices" -Item="Registered Devices" -Status "WARNING" -Details="$($devices.Count) devices" -Recommendation="Retire or wipe devices"
        }
        else {
            $checks += @{Category="Devices"; Item="Registered Devices"; Status="PASS"; Details="No devices"; Risk="NONE"}
            Write-CheckItem -Category "Devices" -Item="Registered Devices" -Status "PASS" -Details="No devices registered"
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        if ($errorMsg -like "*Authorization_RequestDenied*") {
            $checks += @{Category="Devices"; Item="Check"; Status="ERROR"; Details="Permission denied"; Risk="MEDIUM"}
            Write-CheckItem -Category "Devices" -Item="Check" -Status "ERROR" -Details="Requires Device.Read.All permission" -Recommendation="Grant permission or check manually in Endpoint Manager"
        }
        else {
            $checks += @{Category="Devices"; Item="Check"; Status="WARNING"; Details="Error retrieving devices"; Risk="MEDIUM"}
            Write-CheckItem -Category "Devices" -Item="Check" -Status "WARNING" -Details="Unable to retrieve"
        }
    }
    
    $checks += @{Category="Devices"; Item="BitLocker Keys"; Status="MANUAL"; Details="Backup recovery keys"; Risk="HIGH"}
    Write-CheckItem -Category "Devices" -Item="BitLocker Keys" -Status "MANUAL" -Details="Export keys" -Recommendation="Backup BitLocker keys before wipe"
    
    return $checks, $findings
}

function Test-DataGovernance {
    $checks = @()
    
    Write-SectionHeader "8. DATA GOVERNANCE"
    
    $checks += @{Category="Data"; Item="OneDrive Files"; Status="MANUAL"; Details="Transfer or archive"; Risk="HIGH"}
    Write-CheckItem -Category "Data" -Item="OneDrive Files" -Status "MANUAL" -Details="Handle user data" -Recommendation="Grant manager access for 30 days"
    
    $checks += @{Category="Data"; Item="SharePoint Sites"; Status="MANUAL"; Details="Transfer ownership"; Risk="HIGH"}
    Write-CheckItem -Category "Data" -Item="SharePoint Sites" -Status "MANUAL" -Details="Check site ownership" -Recommendation="Reassign site ownership"
    
    $checks += @{Category="Data"; Item="eDiscovery Hold"; Status="MANUAL"; Details="Check legal holds"; Risk="CRITICAL"}
    Write-CheckItem -Category "Data" -Item="eDiscovery Hold" -Status "MANUAL" -Details="Verify hold status" -Recommendation="Place on legal hold if required"
    
    return $checks, @()
}

#endregion

#region Report Generation

function Show-SummaryReport {
    param(
        [array]$AllChecks,
        [array]$AllFindings,
        [object]$User
    )
    
    $passCount = ($AllChecks | Where-Object { $_.Status -eq "PASS" }).Count
    $failCount = ($AllChecks | Where-Object { $_.Status -eq "FAIL" }).Count
    $warnCount = ($AllChecks | Where-Object { $_.Status -eq "WARNING" }).Count
    $manualCount = ($AllChecks | Where-Object { $_.Status -eq "MANUAL" }).Count
    $errorCount = ($AllChecks | Where-Object { $_.Status -eq "ERROR" }).Count
    $total = $AllChecks.Count
    
    $score = 0
    if ($total -gt 0) { 
        $score = [math]::Round(($passCount / $total) * 100) 
    }
    
    $criticalCount = ($AllFindings | Where-Object { $_.Risk -eq "CRITICAL" }).Count
    $highCount = ($AllFindings | Where-Object { $_.Risk -eq "HIGH" }).Count
    
    $riskLevel = "LOW"
    if ($criticalCount -gt 0) { $riskLevel = "CRITICAL" }
    elseif ($highCount -gt 0) { $riskLevel = "HIGH" }
    elseif ($warnCount -gt 0 -or $errorCount -gt 0) { $riskLevel = "MEDIUM" }
    
    $riskColor = "Green"
    if ($riskLevel -eq "CRITICAL") { $riskColor = "Magenta" }
    elseif ($riskLevel -eq "HIGH") { $riskColor = "Red" }
    elseif ($riskLevel -eq "MEDIUM") { $riskColor = "Yellow" }
    
    Write-Host ""
    Write-Host "===============================================================" -ForegroundColor $riskColor
    Write-Host "                 OFFBOARDING AUDIT SUMMARY" -ForegroundColor $riskColor
    Write-Host "===============================================================" -ForegroundColor $riskColor
    Write-Host ""
    
    Write-Host "User: $($User.DisplayName)" -ForegroundColor White
    Write-Host "Email: $($User.Mail)" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Risk Level: $riskLevel" -ForegroundColor $riskColor
    Write-Host "Compliance Score: $score%" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Results Summary:" -ForegroundColor White
    Write-Host "  Passed:  $passCount" -ForegroundColor Green
    Write-Host "  Failed:  $failCount" -ForegroundColor Red
    Write-Host "  Warnings: $warnCount" -ForegroundColor Yellow
    Write-Host "  Manual:  $manualCount" -ForegroundColor Cyan
    if ($errorCount -gt 0) {
        Write-Host "  Errors:  $errorCount (Permission issues)" -ForegroundColor Red
    }
    Write-Host ""
    
    if ($AllFindings.Count -gt 0) {
        Write-Host "---------------------------------------------------------------" -ForegroundColor Red
        Write-Host " CRITICAL FINDINGS" -ForegroundColor Red
        Write-Host "---------------------------------------------------------------" -ForegroundColor Red
        
        $critical = $AllFindings | Where-Object { $_.Risk -eq "CRITICAL" }
        $high = $AllFindings | Where-Object { $_.Risk -eq "HIGH" }
        
        if ($critical.Count -gt 0) {
            Write-Host ""
            Write-Host "CRITICAL (Immediate Action):" -ForegroundColor Magenta
            foreach ($f in $critical) {
                Write-Host "  Issue: $($f.Issue)" -ForegroundColor Magenta
                Write-Host "  Action: $($f.Action)" -ForegroundColor White
                Write-Host ""
            }
        }
        
        if ($high.Count -gt 0) {
            Write-Host "HIGH PRIORITY:" -ForegroundColor Red
            foreach ($f in $high) {
                Write-Host "  Issue: $($f.Issue)" -ForegroundColor Red
                Write-Host "  Action: $($f.Action)" -ForegroundColor White
                Write-Host ""
            }
        }
    }
    else {
        Write-Host "No critical findings detected." -ForegroundColor Green
    }
    
    if ($errorCount -gt 0) {
        Write-Host ""
        Write-Host "---------------------------------------------------------------" -ForegroundColor Yellow
        Write-Host " PERMISSION ERRORS DETECTED" -ForegroundColor Yellow
        Write-Host "---------------------------------------------------------------" -ForegroundColor Yellow
        Write-Host "Some checks failed due to insufficient permissions." -ForegroundColor Yellow
        Write-Host "To get full results, ensure you have one of these roles:" -ForegroundColor White
        Write-Host "  - Global Reader (recommended for audits)" -ForegroundColor Gray
        Write-Host "  - Global Administrator" -ForegroundColor Gray
        Write-Host "  - Privileged Role Administrator" -ForegroundColor Gray
        Write-Host ""
    }
    
    Write-Host "---------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " MANUAL VERIFICATION CHECKLIST" -ForegroundColor Cyan
    Write-Host "---------------------------------------------------------------"
    
    $manualChecks = $AllChecks | Where-Object { $_.Status -eq "MANUAL" }
    foreach ($check in $manualChecks) {
        Write-Host "  [ ] $($check.Category): $($check.Item)" -ForegroundColor Cyan
        if ($check.Recommendation) {
            Write-Host "      $($check.Recommendation)" -ForegroundColor Gray
        }
    }
    
    # Export report
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeName = $User.UserPrincipalName -replace "@", "_" -replace "\.", "_"
    
    $report = @{
        AuditDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        User = @{
            Name = $User.DisplayName
            Email = $User.Mail
            UPN = $User.UserPrincipalName
        }
        Summary = @{
            RiskLevel = $riskLevel
            Score = $score
            Passed = $passCount
            Failed = $failCount
            Warnings = $warnCount
            Manual = $manualCount
            Errors = $errorCount
        }
        Findings = $AllFindings
        Checks = $AllChecks
    }
    
    try {
        $jsonPath = ".\OffboardingAudit_${safeName}_$timestamp.json"
        $report | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -ErrorAction Stop
        Write-Host ""
        Write-Host "JSON report saved: $jsonPath" -ForegroundColor Green
    }
    catch {
        Write-Host "Warning: Could not save JSON report: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    try {
        $csvPath = ".\OffboardingAudit_${safeName}_$timestamp.csv"
        $AllChecks | Export-Csv -Path $csvPath -NoTypeInformation -ErrorAction Stop
        Write-Host "CSV report saved: $csvPath" -ForegroundColor Green
    }
    catch {
        Write-Host "Warning: Could not save CSV report: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

#endregion

#region Main Execution

try {
    Show-Banner
    
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    Write-Host "PowerShell Version: $($psVersion.Major).$($psVersion.Minor)" -ForegroundColor Gray
    Write-Host ""
    
    # Connect to Graph with explicit scopes
    $context = Get-MgContext
    if (-not $context) {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
        
        $scopes = @(
            "User.Read.All",
            "Group.Read.All",
            "Directory.Read.All",
            "AuditLog.Read.All",
            "Application.Read.All"
        )
        
        try {
            Connect-MgGraph -Scopes $scopes -ErrorAction Stop
            $context = Get-MgContext
        }
        catch {
            Write-Host "Failed to connect: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    }
    
    Write-Host "Connected as: $($context.Account)" -ForegroundColor Green
    Write-Host ""
    
    # Test permissions before proceeding
    if (-not (Test-GraphPermissions)) {
        Write-Host ""
        Write-Host "Cannot proceed without proper permissions." -ForegroundColor Red
        Write-Host ""
        Write-Host "Alternative: Run this script as a user with Global Reader role," -ForegroundColor Yellow
        Write-Host "or use Connect-MgGraph with a service principal that has admin consent." -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host ""
    
    # Get user email
    $email = Read-EmailInput -PromptMessage "Enter email of user to audit: "
    
    Write-Host ""
    Write-Host "Retrieving user information..." -ForegroundColor Yellow
    
    # Get user with required properties
    $userFilter = "mail eq '$email' or userPrincipalName eq '$email'"
    $selectProperties = @(
        "id",
        "displayName",
        "mail",
        "userPrincipalName",
        "accountEnabled",
        "department",
        "signInActivity"
    )
    
    try {
        $user = Get-MgUser -Filter $userFilter -Property $selectProperties -ErrorAction Stop | Select-Object -First 1
    }
    catch {
        Write-Host "Error retrieving user: $($_.Exception.Message)" -ForegroundColor Red
        if ($_.Exception.Message -like "*Authorization_RequestDenied*") {
            Write-Host "Your account cannot read user details. Ensure you have User.Read.All permission." -ForegroundColor Yellow
        }
        exit 1
    }
    
    if (-not $user) {
        Write-Host "User not found: $email" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Found: $($user.DisplayName)" -ForegroundColor Green
    Write-Host "Department: $($user.Department)" -ForegroundColor Gray
    Write-Host ""
    
    # Confirm audit
    $confirm = Read-Host "Proceed with audit? (yes/no)"
    if ($confirm -ne "yes") {
        Write-Host "Audit cancelled." -ForegroundColor Yellow
        exit 0
    }
    
    Write-Host ""
    Write-Host "Running compliance checks..." -ForegroundColor Green
    Write-Host ""
    
    # Run all checks
    $allChecks = @()
    $allFindings = @()
    
    # Check 1: Account Status
    $c, $f = Test-UserAccountStatus -User $user
    $allChecks += $c
    $allFindings += $f
    
    # Check 2: License Status
    $c, $f = Test-LicenseStatus -UserId $user.Id
    $allChecks += $c
    $allFindings += $f
    
    # Check 3: Group Memberships
    $c, $f = Test-GroupMemberships -UserId $user.Id
    $allChecks += $c
    $allFindings += $f
    
    # Check 4: Mailbox Status
    $c, $f = Test-MailboxStatus
    $allChecks += $c
    $allFindings += $f
    
    # Check 5: Teams Status
    $c, $f = Test-TeamsStatus
    $allChecks += $c
    $allFindings += $f
    
    # Check 6: Application Access
    $c, $f = Test-ApplicationAccess -UserId $user.Id
    $allChecks += $c
    $allFindings += $f
    
    # Check 7: Device Access
    $c, $f = Test-DeviceAccess -UserId $user.Id
    $allChecks += $c
    $allFindings += $f
    
    # Check 8: Data Governance
    $c, $f = Test-DataGovernance
    $allChecks += $c
    $allFindings += $f
    
    # Show report
    Show-SummaryReport -AllChecks $allChecks -AllFindings $allFindings -User $user
    
    Write-Host ""
    Write-Host "Audit complete!" -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "CRITICAL ERROR: $($_.Exception.Message)" -ForegroundColor Red
    
    if ($_.Exception.Message -like "*Authorization_RequestDenied*" -or
        $_.Exception.Message -like "*unsupported user role*" -or
        $_.Exception.Message -like "*unauthorized*") {
        Write-Host ""
        Write-Host "This error indicates your account lacks required Azure AD permissions." -ForegroundColor Yellow
        Write-Host "Required: Global Reader or Global Administrator role" -ForegroundColor Yellow
        Write-Host "Or delegated app permissions with admin consent." -ForegroundColor Yellow
    }
    
    exit 1
}

#endregion
