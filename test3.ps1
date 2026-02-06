<#
.SYNOPSIS
    User Offboarding Compliance Checklist Auditor
.DESCRIPTION
    Performs a comprehensive audit of user offboarding status across Microsoft 365,
    Azure AD, Exchange, and Teams. Generates a compliance report with findings
    and recommendations. Interactive prompts only - no parameters required.
.NOTES
    Version: 2.0
    Requires: Microsoft.Graph modules, ExchangeOnlineManagement (optional)
#>

#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Teams, Microsoft.Graph.Mail

#region Configuration

$Script:ChecklistConfig = @{
    # Days thresholds for warnings
    DisabledThresholdDays = 1      # Should be disabled within 1 day
    LicenseRemovalThresholdDays = 7 # Licenses should be removed within 7 days
    MailboxArchiveThresholdDays = 30 # Archive should be configured within 30 days
    DataRetentionDays = 90          # Data should be retained for 90 days
    
    # High-risk group patterns to check
    PrivilegedGroupPatterns = @(
        "*Administrator*", "*Admin*", "*Owner*", "*Domain*", 
        "*Enterprise*", "*Security*", "*Compliance*", "*Audit*",
        "*Global*", "*Privileged*", "*Emergency*", "*BreakGlass*"
    )
    
    # External sharing indicators
    ExternalSharingIndicators = @(
        "External", "Guest", "Partner", "Vendor", "Contractor"
    )
}

#endregion

#region Helper Functions

function Show-Banner {
    Clear-Host
    Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║           USER OFFBOARDING COMPLIANCE CHECKLIST AUDITOR                      ║
║                                                                              ║
║              Audit offboarding status without making changes                 ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
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
        
        Write-Host "    ❌ Invalid email format. Please try again." -ForegroundColor Red
    } while ($true)
}

function Write-SectionHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Blue
    Write-Host "║ $Title" -ForegroundColor Blue
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Blue
}

function Write-CheckItem {
    param(
        [string]$Category,
        [string]$Item,
        [ValidateSet("PASS", "FAIL", "WARNING", "INFO", "MANUAL")]
        [string]$Status,
        [string]$Details = "",
        [string]$Recommendation = ""
    )
    
    $icons = @{
        "PASS" = "✅"
        "FAIL" = "❌"
        "WARNING" = "⚠️"
        "INFO" = "ℹ️"
        "MANUAL" = "👤"
    }
    
    $colors = @{
        "PASS" = "Green"
        "FAIL" = "Red"
        "WARNING" = "Yellow"
        "INFO" = "White"
        "MANUAL" = "Cyan"
    }
    
    Write-Host "  $($icons[$Status]) " -NoNewline
    Write-Host "$Category" -ForegroundColor Gray -NoNewline
    Write-Host " → " -NoNewline
    Write-Host "$Item" -ForegroundColor White -NoNewline
    
    if ($Details) {
        Write-Host " [$Details]" -ForegroundColor $colors[$Status]
    }
    else {
        Write-Host ""
    }
    
    if ($Recommendation) {
        Write-Host "      💡 Recommendation: $Recommendation" -ForegroundColor DarkYellow
    }
}

function Get-ComplianceScore {
    param([array]$Checks)
    
    $passed = ($Checks | Where-Object { $_.Status -eq "PASS" }).Count
    $total = $Checks.Count
    
    if ($total -eq 0) { return 0 }
    
    return [math]::Round(($passed / $total) * 100)
}

function Get-RiskLevel {
    param([array]$Findings)
    
    $criticalCount = ($Findings | Where-Object { $_.Risk -eq "CRITICAL" }).Count
    $highCount = ($Findings | Where-Object { $_.Risk -eq "HIGH" }).Count
    
    if ($criticalCount -gt 0) { return "CRITICAL" }
    if ($highCount -gt 0) { return "HIGH" }
    return "MEDIUM"
}

#endregion

#region Check Functions

function Test-UserAccountStatus {
    param([object]$User)
    
    $checks = @()
    $findings = @()
    
    Write-SectionHeader "1. ACCOUNT STATUS & IDENTITY"
    
    # Check 1.1: Account Enabled/Disabled
    if ($User.AccountEnabled -eq $false) {
        $lastSignIn = $User.SignInActivity.LastSignInDateTime
        $disabledDate = if ($lastSignIn) { 
            [datetime]$lastSignIn 
        } else { 
            "Unknown" 
        }
        
        $checks += [PSCustomObject]@{
            Category = "Account"
            Item = "Account Disabled"
            Status = "PASS"
            Details = "Account is disabled"
            Risk = "NONE"
        }
        
        Write-CheckItem -Category "Account" -Item "Account Status" -Status "PASS" -Details "Account is properly disabled"
    }
    else {
        $checks += [PSCustomObject]@{
            Category = "Account"
            Item = "Account Disabled"
            Status = "FAIL"
            Details = "Account is STILL ENABLED"
            Risk = "CRITICAL"
        }
        
        $findings += [PSCustomObject]@{
            Risk = "CRITICAL"
            Issue = "User account is still active"
            Impact = "User can still access all resources and data"
            Remediation = "Disable account immediately in Azure AD"
        }
        
        Write-CheckItem -Category "Account" -Item "Account Status" -Status "FAIL" -Details "ACCOUNT IS STILL ENABLED" -Recommendation "Disable account immediately in Azure AD portal"
    }
    
    # Check 1.2: Sign-in Activity
    $lastSignIn = $User.SignInActivity.LastSignInDateTime
    if ($lastSignIn) {
        $lastSignInDate = [datetime]$lastSignIn
        $daysSinceSignIn = (Get-Date) - $lastSignInDate
        
        if ($daysSinceSignIn.Days -gt 30) {
            $checks += [PSCustomObject]@{
                Category = "Account"
                Item = "Recent Sign-in Activity"
                Status = "PASS"
                Details = "Last sign-in: $($daysSinceSignIn.Days) days ago"
                Risk = "NONE"
            }
            Write-CheckItem -Category "Account" -Item "Recent Activity" -Status "PASS" -Details "No recent sign-ins ($($daysSinceSignIn.Days) days)"
        }
        else {
            $checks += [PSCustomObject]@{
                Category = "Account"
                Item = "Recent Sign-in Activity"
                Status = "WARNING"
                Details = "Recent sign-in: $($daysSinceSignIn.Days) days ago"
                Risk = "HIGH"
            }
            
            $findings += [PSCustomObject]@{
                Risk = "HIGH"
                Issue = "Recent sign-in activity detected"
                Impact = "User may have accessed resources recently before offboarding"
                Remediation = "Review audit logs for recent activity"
            }
            
            Write-CheckItem -Category "Account" -Item "Recent Activity" -Status "WARNING" -Details "Recent sign-in: $($daysSinceSignIn.Days) days ago" -Recommendation "Review recent activity in audit logs"
        }
    }
    else {
        $checks += [PSCustomObject]@{
            Category = "Account"
            Item = "Sign-in History"
            Status = "INFO"
            Details = "No sign-in history available"
            Risk = "NONE"
        }
        Write-CheckItem -Category "Account" -Item "Sign-in History" -Status "INFO" -Details "No recent sign-in data"
    }
    
    # Check 1.3: Password Status
    $passwordPolicies = $User.PasswordPolicies
    if ($passwordPolicies -contains "DisablePasswordExpiration" -or $passwordPolicies -contains "DisableStrongPassword") {
        $checks += [PSCustomObject]@{
            Category = "Account"
            Item = "Password Policy"
            Status = "WARNING"
            Details = "Weak password policies may still apply"
            Risk = "MEDIUM"
        }
        Write-CheckItem -Category "Account" -Item "Password Policy" -Status "WARNING" -Details "Weak policies detected" -Recommendation "Ensure password is changed or account is blocked"
    }
    else {
        $checks += [PSCustomObject]@{
            Category = "Account"
            Item = "Password Policy"
            Status = "PASS"
            Details = "Standard password policies"
            Risk = "NONE"
        }
        Write-CheckItem -Category "Account" -Item "Password Policy" -Status "PASS" -Details "Standard policies apply"
    }
    
    # Check 1.4: Block Credential
    # This would require additional API calls, marked as manual
    $checks += [PSCustomObject]@{
        Category = "Account"
        Item = "Credential Block"
        Status = "MANUAL"
        Details = "Verify refresh tokens revoked"
        Risk = "MEDIUM"
    }
    Write-CheckItem -Category "Account" -Item "Credential Revocation" -Status "MANUAL" -Details "Manual verification required" -Recommendation "Run Revoke-MgUserSignInSession and verify in Azure AD"
    
    return @{
        Checks = $checks
        Findings = $findings
    }
}

function Test-LicenseStatus {
    param([string]$UserId, [string]$UserPrincipalName)
    
    $checks = @()
    $findings = @()
    
    Write-SectionHeader "2. LICENSE & SUBSCRIPTION STATUS"
    
    try {
        $licenses = Get-MgUserLicenseDetail -UserId $UserId -ErrorAction SilentlyContinue
        
        if ($licenses.Count -eq 0) {
            $checks += [PSCustomObject]@{
                Category = "License"
                Item = "License Assignment"
                Status = "PASS"
                Details = "All licenses removed"
                Risk = "NONE"
            }
            Write-CheckItem -Category "License" -Item "License Status" -Status "PASS" -Details "No licenses assigned"
        }
        else {
            $skuNames = $licenses | ForEach-Object { 
                $_.SkuPartNumber -replace "ENTERPRISEPACK", "Office 365 E3" `
                                  -replace "ENTERPRISEPREMIUM", "Office 365 E5" `
                                  -replace "SPE_E5", "Microsoft 365 E5" `
                                  -replace "SPE_E3", "Microsoft 365 E3"
            }
            
            $checks += [PSCustomObject]@{
                Category = "License"
                Item = "License Assignment"
                Status = "FAIL"
                Details = "$($licenses.Count) licenses still assigned"
                Risk = "HIGH"
            }
            
            $findings += [PSCustomObject]@{
                Risk = "HIGH"
                Issue = "Active licenses still assigned"
                Impact = "Continued billing and potential data access via shared links"
                Remediation = "Remove all licenses: $($skuNames -join ', ')"
            }
            
            Write-CheckItem -Category "License" -Item "License Status" -Status "FAIL" -Details "$($licenses.Count) licenses still active: $($skuNames -join ', ')" -Recommendation "Remove all licenses in Microsoft 365 Admin Center"
            
            # List specific licenses
            foreach ($license in $skuNames) {
                Write-Host "      📋 $license" -ForegroundColor Red
            }
        }
    }
    catch {
        $checks += [PSCustomObject]@{
            Category = "License"
            Item = "License Check"
            Status = "WARNING"
            Details = "Unable to retrieve license data"
            Risk = "MEDIUM"
        }
        Write-CheckItem -Category "License" -Item "License Check" -Status "WARNING" -Details "Error retrieving data"
    }
    
    return @{
        Checks = $checks
        Findings = $findings
    }
}

function Test-GroupMemberships {
    param([string]$UserId, [string]$DisplayName)
    
    $checks = @()
    $findings = @()
    
    Write-SectionHeader "3. GROUP MEMBERSHIPS & ACCESS"
    
    try {
        $groups = Get-MgUserTransitiveMemberOf -UserId $UserId -All | 
            Where-Object { $_.'@odata.type' -eq "#microsoft.graph.group" }
        
        if ($groups.Count -eq 0) {
            $checks += [PSCustomObject]@{
                Category = "Groups"
                Item = "Group Memberships"
                Status = "PASS"
                Details = "No group memberships"
                Risk = "NONE"
            }
            Write-CheckItem -Category "Groups" -Item "Memberships" -Status "PASS" -Details "User removed from all groups"
        }
        else {
            # Analyze groups
            $privilegedGroups = @()
            $sensitiveGroups = @()
            $standardGroups = @()
            
            foreach ($group in $groups) {
                $groupDetail = Get-MgGroup -GroupId $group.Id -Property "displayName,description,groupTypes,isAssignableToRole"
                
                $isPrivileged = $false
                foreach ($pattern in $Script:ChecklistConfig.PrivilegedGroupPatterns) {
                    if ($groupDetail.DisplayName -like $pattern) {
                        $isPrivileged = $true
                        break
                    }
                }
                
                $groupInfo = [PSCustomObject]@{
                    Name = $groupDetail.DisplayName
                    Id = $group.Id
                    IsPrivileged = $isPrivileged
                    IsRoleAssignable = $groupDetail.IsAssignableToRole
                    IsDynamic = $groupDetail.GroupTypes -contains "DynamicMembership"
                }
                
                if ($groupDetail.IsAssignableToRole) {
                    $privilegedGroups += $groupInfo
                }
                elseif ($isPrivileged) {
                    $sensitiveGroups += $groupInfo
                }
                else {
                    $standardGroups += $groupInfo
                }
            }
            
            if ($privilegedGroups.Count -gt 0 -or $sensitiveGroups.Count -gt 0) {
                $checks += [PSCustomObject]@{
                    Category = "Groups"
                    Item = "Privileged Access"
                    Status = "FAIL"
                    Details = "$($privilegedGroups.Count) role-assignable, $($sensitiveGroups.Count) sensitive groups"
                    Risk = "CRITICAL"
                }
                
                $findings += [PSCustomObject]@{
                    Risk = "CRITICAL"
                    Issue = "User retains access to privileged groups"
                    Impact = "Potential elevation of privilege or unauthorized admin access"
                    Remediation = "Remove from all privileged groups immediately"
                }
                
                Write-CheckItem -Category "Groups" -Item "Privileged Access" -Status "FAIL" -Details "$($privilegedGroups.Count) role-assignable, $($sensitiveGroups.Count) admin groups" -Recommendation "Remove from all privileged groups immediately"
                
                foreach ($pg in $privilegedGroups) {
                    Write-Host "      🛑 ROLE-ASSIGNABLE: $($pg.Name)" -ForegroundColor Magenta
                }
                foreach ($sg in $sensitiveGroups) {
                    Write-Host "      🔴 SENSITIVE: $($sg.Name)" -ForegroundColor Red
                }
            }
            else {
                $checks += [PSCustomObject]@{
                    Category = "Groups"
                    Item = "Privileged Access"
                    Status = "PASS"
                    Details = "No privileged groups"
                    Risk = "NONE"
                }
                Write-CheckItem -Category "Groups" -Item "Privileged Access" -Status "PASS" -Details "No admin/privileged groups"
            }
            
            if ($standardGroups.Count -gt 0) {
                $checks += [PSCustomObject]@{
                    Category = "Groups"
                    Item = "Standard Groups"
                    Status = "WARNING"
                    Details = "$($standardGroups.Count) standard groups remain"
                    Risk = "MEDIUM"
                }
                
                Write-CheckItem -Category "Groups" -Item "Standard Memberships" -Status "WARNING" -Details "$($standardGroups.Count) groups remain" -Recommendation "Remove from non-essential groups (keep if data access needed for transition)"
                
                if ($standardGroups.Count -le 10) {
                    foreach ($sg in $standardGroups) {
                        Write-Host "      🟡 $($sg.Name)" -ForegroundColor Yellow
                    }
                }
                else {
                    Write-Host "      🟡 ... and $($standardGroups.Count - 10) more" -ForegroundColor Yellow
                }
            }
        }
    }
    catch {
        $checks += [PSCustomObject]@{
            Category = "Groups"
            Item = "Group Check"
            Status = "WARNING"
            Details = "Error retrieving groups"
            Risk = "MEDIUM"
        }
        Write-CheckItem -Category "Groups" -Item "Group Check" -Status "WARNING" -Details "Unable to retrieve"
    }
    
    return @{
        Checks = $checks
        Findings = $findings
    }
}

function Test-MailboxStatus {
    param([object]$User)
    
    $checks = @()
    $findings = @()
    
    Write-SectionHeader "4. EXCHANGE & MAILBOX STATUS"
    
    # Check litigation hold
    try {
        $mailbox = Get-MgUser -UserId $User.Id -Property "mailSettings,assignedLicenses" -ErrorAction SilentlyContinue
        
        $checks += [PSCustomObject]@{
            Category = "Mailbox"
            Item = "Litigation Hold"
            Status = "MANUAL"
            Details = "Verify in Exchange Admin Center"
            Risk = "MEDIUM"
        }
        Write-CheckItem -Category "Mailbox" -Item "Litigation Hold" -Status "MANUAL" -Details "Check EAC for hold status" -Recommendation "Ensure litigation hold is enabled if required for compliance"
        
        $checks += [PSCustomObject]@{
            Category = "Mailbox"
            Item = "Email Forwarding"
            Status = "MANUAL"
            Details = "Verify forwarding rules"
            Risk = "HIGH"
        }
        Write-CheckItem -Category "Mailbox" -Item "Forwarding Rules" -Status "MANUAL" -Details "Check for hidden forwarding" -Recommendation "Check for inbox rules forwarding to external addresses"
        
        $checks += [PSCustomObject]@{
            Category = "Mailbox"
            Item = "Delegate Access"
            Status = "MANUAL"
            Details = "Check mailbox permissions"
            Risk = "MEDIUM"
        }
        Write-CheckItem -Category "Mailbox" -Item "Delegate Access" -Status "MANUAL" -Details "Verify SendAs/SendOnBehalf permissions" -Recommendation "Remove all delegate permissions"
        
        $checks += [PSCustomObject]@{
            Category = "Mailbox"
            Item = "Auto-Reply"
            Status = "MANUAL"
            Details = "Check automatic replies"
            Risk = "LOW"
        }
        Write-CheckItem -Category "Mailbox" -Item "Auto-Reply" -Status "MANUAL" -Details "Verify out-of-office message" -Recommendation "Configure or disable auto-reply as appropriate"
        
    }
    catch {
        $checks += [PSCustomObject]@{
            Category = "Mailbox"
            Item = "Mailbox Check"
            Status = "WARNING"
            Details = "Unable to verify"
            Risk = "MEDIUM"
        }
    }
    
    return @{
        Checks = $checks
        Findings = $findings
    }
}

function Test-TeamsStatus {
    param([string]$UserId)
    
    $checks = @()
    $findings = @()
    
    Write-SectionHeader "5. MICROSOFT TEAMS STATUS"
    
    try {
        # Check Teams app installation (indicates usage)
        $checks += [PSCustomObject]@{
            Category = "Teams"
            Item = "Teams Membership Audit"
            Status = "MANUAL"
            Details = "Check team memberships"
            Risk = "MEDIUM"
        }
        Write-CheckItem -Category "Teams" -Item "Team Memberships" -Status "MANUAL" -Details "Verify removal from all teams" -Recommendation "Remove from all Teams including private channels"
        
        $checks += [PSCustomObject]@{
            Category = "Teams"
            Item = "Shared Files"
            Status = "MANUAL"
            Details = "Check file ownership"
            Risk = "HIGH"
        }
        Write-CheckItem -Category "Teams" -Item "File Ownership" -Status "MANUAL" -Details "Transfer file ownership" -Recommendation "Transfer ownership of files in Teams/SharePoint to manager"
        
        $checks += [PSCustomObject]@{
            Category = "Teams"
            Item = "Meeting Organized"
            Status = "MANUAL"
            Details = "Check future meetings"
            Risk = "MEDIUM"
        }
        Write-CheckItem -Category "Teams" -Item "Future Meetings" -Status "MANUAL" -Details "Cancel or reassign meetings" -Recommendation "Cancel future meetings or transfer organizer role"
        
    }
    catch {
        $checks += [PSCustomObject]@{
            Category = "Teams"
            Item = "Teams Check"
            Status = "WARNING"
            Details = "Unable to verify Teams status"
            Risk = "MEDIUM"
        }
    }
    
    return @{
        Checks = $checks
        Findings = $findings
    }
}

function Test-ApplicationAccess {
    param([string]$UserId)
    
    $checks = @()
    $findings = @()
    
    Write-SectionHeader "6. APPLICATION & SERVICE ACCESS"
    
    try {
        # Check app role assignments
        $appRoles = Get-MgUserAppRoleAssignment -UserId $UserId -ErrorAction SilentlyContinue
        
        if ($appRoles.Count -gt 0) {
            $checks += [PSCustomObject]@{
                Category = "Apps"
                Item = "App Role Assignments"
                Status = "FAIL"
                Details = "$($appRoles.Count) app roles assigned"
                Risk = "HIGH"
            }
            
            $findings += [PSCustomObject]@{
                Risk = "HIGH"
                Issue = "Application role assignments remain"
                Impact = "User may retain access to enterprise applications"
                Remediation = "Remove all app role assignments in Enterprise Applications"
            }
            
            Write-CheckItem -Category "Apps" -Item "App Roles" -Status "FAIL" -Details "$($appRoles.Count) applications" -Recommendation "Remove all enterprise application assignments"
        }
        else {
            $checks += [PSCustomObject]@{
                Category = "Apps"
                Item = "App Role Assignments"
                Status = "PASS"
                Details = "No app roles assigned"
                Risk = "NONE"
            }
            Write-CheckItem -Category "Apps" -Item "App Roles" -Status "PASS" -Details "No application assignments"
        }
        
        # Check OAuth grants (consents)
        $checks += [PSCustomObject]@{
            Category = "Apps"
            Item = "OAuth Consents"
            Status = "MANUAL"
            Details = "Verify in Azure AD"
            Risk = "MEDIUM"
        }
        Write-CheckItem -Category "Apps" -Item "OAuth Grants" -Status "MANUAL" -Details "Check for active consents" -Recommendation "Revoke all OAuth consents granted by user"
        
    }
    catch {
        $checks += [PSCustomObject]@{
            Category = "Apps"
            Item = "App Check"
            Status = "WARNING"
            Details = "Error retrieving app data"
            Risk = "MEDIUM"
        }
    }
    
    return @{
        Checks = $checks
        Findings = $findings
    }
}

function Test-DeviceAccess {
    param([string]$UserId)
    
    $checks = @()
    $findings = @()
    
    Write-SectionHeader "7. DEVICE & ENDPOINT STATUS"
    
    try {
        $devices = Get-MgUserRegisteredDevice -UserId $UserId -ErrorAction SilentlyContinue
        
        if ($devices.Count -gt 0) {
            $checks += [PSCustomObject]@{
                Category = "Devices"
                Item = "Registered Devices"
                Status = "WARNING"
                Details = "$($devices.Count) devices registered"
                Risk = "MEDIUM"
            }
            
            $findings += [PSCustomObject]@{
                Risk = "MEDIUM"
                Issue = "Devices still registered to user"
                Impact = "Device may retain cached credentials and corporate data"
                Remediation = "Retire or wipe devices in Intune/Endpoint Manager"
            }
            
            Write-CheckItem -Category "Devices" -Item "Device Registration" -Status "WARNING" -Details "$($devices.Count) devices" -Recommendation "Retire/wipe all devices in Endpoint Manager"
        }
        else {
            $checks += [PSCustomObject]@{
                Category = "Devices"
                Item = "Registered Devices"
                Status = "PASS"
                Details = "No devices registered"
                Risk = "NONE"
            }
            Write-CheckItem -Category "Devices" -Item "Device Registration" -Status "PASS" -Details "No devices registered"
        }
        
        # Check BitLocker keys
        $checks += [PSCustomObject]@{
            Category = "Devices"
            Item = "BitLocker Keys"
            Status = "MANUAL"
            Details = "Backup recovery keys"
            Risk = "HIGH"
        }
        Write-CheckItem -Category "Devices" -Item "BitLocker Recovery" -Status "MANUAL" -Details "Ensure keys are backed up" -Recommendation "Export BitLocker recovery keys before device wipe"
        
    }
    catch {
        $checks += [PSCustomObject]@{
            Category = "Devices"
            Item = "Device Check"
            Status = "WARNING"
            Details = "Unable to retrieve devices"
            Risk = "MEDIUM"
        }
    }
    
    return @{
        Checks = $checks
        Findings = $findings
    }
}

function Test-DataGovernance {
    param([object]$User)
    
    $checks = @()
    $findings = @()
    
    Write-SectionHeader "8. DATA GOVERNANCE & COMPLIANCE"
    
    # Check OneDrive status
    $checks += [PSCustomObject]@{
        Category = "Data"
        Item = "OneDrive Data"
        Status = "MANUAL"
        Details = "Verify data handling"
        Risk = "HIGH"
    }
    Write-CheckItem -Category "Data" -Item "OneDrive Files" -Status "MANUAL" -Details "Transfer or archive data" -Recommendation "Grant manager access to OneDrive for 30 days, then delete"
    
    # Check SharePoint ownership
    $checks += [PSCustomObject]@{
        Category = "Data"
        Item = "SharePoint Ownership"
        Status = "MANUAL"
        Details = "Check site ownership"
        Risk = "HIGH"
    }
    Write-CheckItem -Category "Data" -Item "SharePoint Sites" -Status "MANUAL" -Details "Transfer site ownership" -Recommendation "Reassign ownership of SharePoint sites created by user"
    
    # Check retention labels
    $checks += [PSCustomObject]@{
        Category = "Data"
        Item = "Retention Labels"
        Status = "MANUAL"
        Details = "Verify label application"
        Risk = "MEDIUM"
    }
    Write-CheckItem -Category "Data" -Item "Retention Policy" -Status "MANUAL" -Details "Ensure retention labels applied" -Recommendation "Verify compliance with data retention policies"
    
    # Check eDiscovery holds
    $checks += [PSCustomObject]@{
        Category = "Data"
        Item = "eDiscovery Hold"
        Status = "MANUAL"
        Details = "Check legal holds"
        Risk = "CRITICAL"
    }
    Write-CheckItem -Category "Data" -Item "Legal Hold" -Status "MANUAL" -Details "Verify eDiscovery status" -Recommendation "Ensure user is placed on legal hold if litigation is anticipated"
    
    return @{
        Checks = $checks
        Findings = $findings
    }
}

function Test-ExternalAccess {
    param([object]$User)
    
    $checks = @()
    $findings = @()
    
    Write-SectionHeader "9. EXTERNAL ACCESS & SHARING"
    
    # Check B2B collaboration
    $checks += [PSCustomObject]@{
        Category = "External"
        Item = "Guest Invitations"
        Status = "MANUAL"
        Details = "Check invited guests"
        Risk = "MEDIUM"
    }
    Write-CheckItem -Category "External" -Item "Guest Invites" -Status "MANUAL" -Details "Review invited external users" -Recommendation "Transfer ownership of guest invitations to manager"
    
    # Check external sharing
    $checks += [PSCustomObject]@{
        Category = "External"
        Item = "Shared Links"
        Status = "MANUAL"
        Details = "Check anonymous links"
        Risk = "HIGH"
    }
    Write-CheckItem -Category "External" -Item "Anonymous Sharing" -Status "MANUAL" -Details "Audit shared links" -Recommendation "Disable or transfer ownership of anonymously shared links"
    
    # Check external collaborations
    $checks += [PSCustomObject]@{
        Category = "External"
        Item = "External Collaborations"
        Status = "MANUAL"
        Details = "Check Teams/SharePoint external access"
        Risk = "MEDIUM"
    }
    Write-CheckItem -Category "External" -Item "External Access" -Status "MANUAL" -Details "Review external collaborations" -Recommendation "Document external collaborations for business continuity"
    
    return @{
        Checks = $checks
        Findings = $findings
    }
}

#endregion

#region Report Generation

function Show-SummaryReport {
    param(
        [array]$AllChecks,
        [array]$AllFindings,
        [object]$User
    )
    
    $complianceScore = Get-ComplianceScore -Checks $AllChecks
    $riskLevel = Get-RiskLevel -Findings $AllFindings
    
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor $(switch($riskLevel){"CRITICAL"{"Magenta"}"HIGH"{"Red"}default{"Yellow"}})
    Write-Host "║                         OFFBOARDING AUDIT SUMMARY                            ║" -ForegroundColor $(switch($riskLevel){"CRITICAL"{"Magenta"}"HIGH"{"Red"}default{"Yellow"}})
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor $(switch($riskLevel){"CRITICAL"{"Magenta"}"HIGH"{"Red"}default{"Yellow"}})
    Write-Host ""
    
    Write-Host "User: $($User.DisplayName)" -ForegroundColor White
    Write-Host "Email: $($User.Mail)" -ForegroundColor White
    Write-Host "UPN: $($User.UserPrincipalName)" -ForegroundColor White
    Write-Host ""
    
    # Risk Badge
    $riskColor = switch ($riskLevel) {
        "CRITICAL" { "Magenta" }
        "HIGH" { "Red" }
        "MEDIUM" { "Yellow" }
        default { "Green" }
    }
    
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor $riskColor
    Write-Host "║  RISK LEVEL: $riskLevel" -ForegroundColor $riskColor
    Write-Host "║  COMPLIANCE SCORE: $complianceScore%" -ForegroundColor $riskColor
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor $riskColor
    Write-Host ""
    
    # Statistics
    $passCount = ($AllChecks | Where-Object { $_.Status -eq "PASS" }).Count
    $failCount = ($AllChecks | Where-Object { $_.Status -eq "FAIL" }).Count
    $warnCount = ($AllChecks | Where-Object { $_.Status -eq "WARNING" }).Count
    $manualCount = ($AllChecks | Where-Object { $_.Status -eq "MANUAL" }).Count
    
    Write-Host "Check Results:" -ForegroundColor White
    Write-Host "    ✅ Passed:        $passCount" -ForegroundColor Green
    Write-Host "    ❌ Failed:        $failCount" -ForegroundColor Red
    Write-Host "    ⚠️  Warnings:      $warnCount" -ForegroundColor Yellow
    Write-Host "    👤 Manual Checks: $manualCount" -ForegroundColor Cyan
    Write-Host ""
    
    # Critical Findings
    if ($AllFindings.Count -gt 0) {
        Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "║                         CRITICAL FINDINGS REQUIRING ACTION                   ║" -ForegroundColor Red
        Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
        Write-Host ""
        
        $criticalFindings = $AllFindings | Where-Object { $_.Risk -eq "CRITICAL" }
        $highFindings = $AllFindings | Where-Object { $_.Risk -eq "HIGH" }
        
        if ($criticalFindings.Count -gt 0) {
            Write-Host "🛑 CRITICAL (Immediate Action Required):" -ForegroundColor Magenta
            foreach ($finding in $criticalFindings) {
                Write-Host ""
                Write-Host "  Issue: $($finding.Issue)" -ForegroundColor Magenta
                Write-Host "  Impact: $($finding.Impact)" -ForegroundColor Gray
                Write-Host "  Action: $($finding.Remediation)" -ForegroundColor White
            }
            Write-Host ""
        }
        
        if ($highFindings.Count -gt 0) {
            Write-Host "🔴 HIGH PRIORITY:" -ForegroundColor Red
            foreach ($finding in $highFindings) {
                Write-Host ""
                Write-Host "  Issue: $($finding.Issue)" -ForegroundColor Red
                Write-Host "  Impact: $($finding.Impact)" -ForegroundColor Gray
                Write-Host "  Action: $($finding.Remediation)" -ForegroundColor White
            }
        }
    }
    else {
        Write-Host "✅ No critical findings detected!" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                         MANUAL VERIFICATION CHECKLIST                        ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "The following items require manual verification:" -ForegroundColor Yellow
    Write-Host ""
    
    $manualChecks = $AllChecks | Where-Object { $_.Status -eq "MANUAL" }
    foreach ($check in $manualChecks) {
        Write-Host "  ☐ $($check.Category): $($check.Item)" -ForegroundColor Cyan
        Write-Host "     $($check.Recommendation)" -ForegroundColor Gray
        Write-Host ""
    }
    
    # Export Report
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeName = $User.UserPrincipalName -replace "@", "_" -replace "\.", "_"
    $reportPath = ".\OffboardingAudit_${safeName}_$timestamp.json"
    
    $report = [PSCustomObject]@{
        AuditDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        AuditedBy = (Get-MgContext).Account
        User = @{
            DisplayName = $User.DisplayName
            Email = $User.Mail
            UserPrincipalName = $User.UserPrincipalName
            Id = $User.Id
        }
        Summary = @{
            RiskLevel = $riskLevel
            ComplianceScore = $complianceScore
            TotalChecks = $AllChecks.Count
            Passed = $passCount
            Failed = $failCount
            Warnings = $warnCount
            Manual = $manualCount
        }
        Findings = $AllFindings
        Checks = $AllChecks
    }
    
    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath
    Write-Host "📄 Detailed audit report saved to: $reportPath" -ForegroundColor Green
    
    # Also export as CSV for easy sharing
    $csvPath = ".\OffboardingAudit_${safeName}_$timestamp.csv"
    $AllChecks | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "📄 Checklist CSV saved to: $csvPath" -ForegroundColor Green
}

#endregion

#region Main Execution

try {
    Show-Banner
    
    # Connect to Microsoft Graph
    $context = Get-MgContext
    if (-not $context) {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
        Connect-MgGraph -Scopes @(
            "User.Read.All",
            "Group.Read.All",
            "Directory.Read.All",
            "AuditLog.Read.All",
            "Application.Read.All",
            "Device.Read.All",
            "TeamSettings.Read.All"
        )
        $context = Get-MgContext
    }
    
    Write-Host "Connected as: $($context.Account)" -ForegroundColor Green
    Write-Host ""
    
    # Get user email
    $email = Read-EmailInput -PromptMessage "Enter email of offboarded user to audit: "
    
    Write-Host ""
    Write-Host "Retrieving user information..." -ForegroundColor Yellow
    
    $user = Get-MgUser -Filter "mail eq '$email' or userPrincipalName eq '$email'" `
        -Property @(
            "id", "displayName", "mail", "userPrincipalName", 
            "accountEnabled", "createdDateTime", "deletedDateTime",
            "department", "jobTitle", "manager", "signInActivity",
            "assignedLicenses", "passwordPolicies"
        ) -ExpandProperty Manager
    
    if (-not $user) {
        throw "User not found: $email"
    }
    
    Write-Host "Found: $($user.DisplayName)" -ForegroundColor Green
    Write-Host ""
    
    # Confirm audit
    Write-Host "This will perform a comprehensive offboarding audit for:" -ForegroundColor Yellow
    Write-Host "  Name:  $($user.DisplayName)" -ForegroundColor White
    Write-Host "  Email: $($user.Mail)" -ForegroundColor White
    Write-Host "  Dept:  $($user.Department)" -ForegroundColor White
    Write-Host ""
    
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
    
    # 1. Account Status
    $result = Test-UserAccountStatus -User $user
    $allChecks += $result.Checks
    $allFindings += $result.Findings
    
    # 2. License Status
    $result = Test-LicenseStatus -UserId $user.Id -UserPrincipalName $user.UserPrincipalName
    $allChecks += $result.Checks
    $allFindings += $result.Findings
    
    # 3. Group Memberships
    $result = Test-GroupMemberships -UserId $user.Id -DisplayName $user.DisplayName
    $allChecks += $result.Checks
    $allFindings += $result.Findings
    
    # 4. Mailbox Status
    $result = Test-MailboxStatus -User $user
    $allChecks += $result.Checks
    $allFindings += $result.Findings
    
    # 5. Teams Status
    $result = Test-TeamsStatus -UserId $user.Id
    $allChecks += $result.Checks
    $allFindings += $result.Findings
    
    # 6. Application Access
    $result = Test-ApplicationAccess -UserId $user.Id
    $allChecks += $result.Checks
    $allFindings += $result.Findings
    
    # 7. Device Access
    $result = Test-DeviceAccess -UserId $user.Id
    $allChecks += $result.Checks
    $allFindings += $result.Findings
    
    # 8. Data Governance
    $result = Test-DataGovernance -User $user
    $allChecks += $result.Checks
    $allFindings += $result.Findings
    
    # 9. External Access
    $result = Test-ExternalAccess -User $user
    $allChecks += $result.Checks
    $allFindings += $result.Findings
    
    # Show final report
    Show-SummaryReport -AllChecks $allChecks -AllFindings $allFindings -User $user
    
    Write-Host ""
    Write-Host "Audit complete!" -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "ERROR: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
    exit 1
}

#endregion
