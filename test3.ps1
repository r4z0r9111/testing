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
