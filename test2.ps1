<#
.SYNOPSIS
    Interactive Group Membership Copy Script with Safety Filters
.DESCRIPTION
    Copies group memberships from one user to another with interactive prompts
    and built-in safety checks. No command-line parameters required.
#>

#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Authentication

#region Safety Configuration (Edit these for your organization)

$Script:PrivilegedGroupPatterns = @(
    "*Administrator*", "*Admin*", "*Owner*", 
    "*Domain*", "*Enterprise*", "*Schema*",
    "*HR*", "*Finance*", "*Executive*", "*C-Level*",
    "*Security*", "*Compliance*", "*Audit*",
    "*Global*", "*Privileged*", "*Emergency*"
)

$Script:HighRiskOperations = @(
    "Adding user to privileged groups (potential privilege escalation)"
    "Granting group ownership (grants admin rights over group)"
    "Modifying dynamic groups (may violate group policies)"
)

#endregion

#region Helper Functions

function Show-Banner {
    Clear-Host
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║     MICROSOFT GRAPH GROUP MEMBERSHIP COPY UTILITY               ║
║     Interactive Mode with Safety Filters                         ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
    Write-Host ""
}

function Read-EmailInput {
    param(
        [string]$PromptMessage,
        [switch]$AllowEmpty
    )
    
    do {
        Write-Host $PromptMessage -ForegroundColor Yellow -NoNewline
        $email = Read-Host
        
        if ([string]::IsNullOrWhiteSpace($email) -and $AllowEmpty) {
            return $null
        }
        
        # Basic email validation
        if ($email -match '^[\w\.-]+@[\w\.-]+\.\w+$') {
            return $email.ToLower().Trim()
        }
        
        Write-Host "    ❌ Invalid email format. Please try again." -ForegroundColor Red
    } while ($true)
}

function Confirm-Action {
    param(
        [string]$Message,
        [string]$RequireExactText = $null
    )
    
    Write-Host ""
    if ($RequireExactText) {
        Write-Host "⚠️  $Message" -ForegroundColor Yellow
        Write-Host "    To confirm, type exactly: " -NoNewline
        Write-Host $RequireExactText -ForegroundColor Red -NoNewline
        $response = Read-Host
        return ($response -eq $RequireExactText)
    }
    else {
        Write-Host "❓ $Message (yes/no): " -ForegroundColor Yellow -NoNewline
        $response = Read-Host
        return ($response -eq "yes" -or $response -eq "y")
    }
}

function Show-Progress {
    param(
        [string]$Activity,
        [int]$PercentComplete
    )
    Write-Progress -Activity $Activity -PercentComplete $PercentComplete -Status "Processing..."
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error", "Critical")]
        [string]$Level = "Info",
        [int]$Indent = 0
    )
    
    $indentStr = "    " * $Indent
    $timestamp = Get-Date -Format "HH:mm:ss"
    
    $colorMap = @{
        "Info" = "White"
        "Success" = "Green"
        "Warning" = "Yellow"
        "Error" = "Red"
        "Critical" = "Magenta"
    }
    
    $prefix = switch ($Level) {
        "Success" { "✓ " }
        "Error" { "✗ " }
        "Warning" { "⚠ " }
        "Critical" { "🛑 " }
        default { "ℹ " }
    }
    
    Write-Host "[$timestamp] $indentStr$prefix$Message" -ForegroundColor $colorMap[$Level]
}

function Get-UserDetails {
    param([string]$Email)
    
    try {
        Write-Log "Looking up user: $Email" -Level "Info" -Indent 1
        
        $user = Get-MgUser -Filter "mail eq '$Email' or userPrincipalName eq '$Email'" `
            -Property "id,displayName,mail,userPrincipalName,jobTitle,department,accountEnabled"
        
        if (-not $user) {
            throw "User not found in directory"
        }
        
        Write-Log "Found: $($user.DisplayName)" -Level "Success" -Indent 2
        Write-Log "Department: $($user.Department)" -Level "Info" -Indent 2
        Write-Log "Job Title: $($user.JobTitle)" -Level "Info" -Indent 2
        Write-Log "Account Status: $(if($user.AccountEnabled){'Enabled'}else{'Disabled'})" -Level "Info" -Indent 2
        
        return $user
    }
    catch {
        Write-Log "Failed to find user: $_" -Level "Error" -Indent 2
        return $null
    }
}

function Get-GroupMemberships {
    param([string]$UserId)
    
    Write-Log "Retrieving group memberships..." -Level "Info" -Indent 1
    
    try {
        $groups = Get-MgUserTransitiveMemberOf -UserId $UserId -All | 
            Where-Object { $_.'@odata.type' -eq "#microsoft.graph.group" }
        
        $detailedGroups = @()
        $processed = 0
        
        foreach ($group in $groups) {
            $processed++
            Show-Progress -Activity "Analyzing groups..." -PercentComplete (($processed / $groups.Count) * 100)
            
            $detail = Get-MgGroup -GroupId $group.Id -Property @(
                "id", "displayName", "description", "groupTypes", 
                "mailEnabled", "securityEnabled", "mail", "membershipRule",
                "visibility", "isAssignableToRole"
            )
            
            $isPrivileged = $false
            foreach ($pattern in $Script:PrivilegedGroupPatterns) {
                if ($detail.DisplayName -like $pattern) {
                    $isPrivileged = $true
                    break
                }
            }
            
            $isDynamic = $detail.GroupTypes -contains "DynamicMembership"
            $isRoleAssignable = $detail.IsAssignableToRole -eq $true
            
            $detailedGroups += [PSCustomObject]@{
                Id = $detail.Id
                DisplayName = $detail.DisplayName
                Description = $detail.Description
                Mail = $detail.Mail
                GroupTypes = ($detail.GroupTypes -join ", ")
                IsDynamic = $isDynamic
                IsPrivileged = $isPrivileged
                IsRoleAssignable = $isRoleAssignable
                IsMailEnabled = $detail.MailEnabled
                IsSecurityEnabled = $detail.SecurityEnabled
                Visibility = $detail.Visibility
                MembershipRule = $detail.MembershipRule
                RiskLevel = if ($isRoleAssignable) { "CRITICAL" } 
                           elseif ($isPrivileged) { "HIGH" } 
                           elseif ($isDynamic) { "MEDIUM" }
                           else { "LOW" }
            }
        }
        
        Write-Progress -Activity "Analyzing groups..." -Completed
        Write-Log "Found $($detailedGroups.Count) groups" -Level "Success" -Indent 2
        
        return $detailedGroups | Sort-Object RiskLevel -Descending
    }
    catch {
        Write-Log "Failed to retrieve groups: $_" -Level "Error" -Indent 2
        return $null
    }
}

function Show-GroupAnalysis {
    param([array]$Groups)
    
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                    GROUP ANALYSIS REPORT                         ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    $critical = $Groups | Where-Object { $_.RiskLevel -eq "CRITICAL" }
    $high = $Groups | Where-Object { $_.RiskLevel -eq "HIGH" }
    $medium = $Groups | Where-Object { $_.RiskLevel -eq "MEDIUM" }
    $low = $Groups | Where-Object { $_.RiskLevel -eq "LOW" }
    
    Write-Host "Risk Distribution:" -ForegroundColor White
    Write-Host "    🛑 CRITICAL (Role-assignable): $($critical.Count)" -ForegroundColor Magenta
    Write-Host "    🔴 HIGH (Privileged): $($high.Count)" -ForegroundColor Red
    Write-Host "    🟡 MEDIUM (Dynamic): $($medium.Count)" -ForegroundColor Yellow
    Write-Host "    🟢 LOW (Standard): $($low.Count)" -ForegroundColor Green
    Write-Host ""
    
    if ($critical.Count -gt 0) {
        Write-Host "CRITICAL GROUPS (Can assign Azure AD roles):" -ForegroundColor Magenta
        $critical | ForEach-Object { 
            Write-Host "    🛑 $($_.DisplayName)" -ForegroundColor Magenta
            if ($_.Description) { Write-Host "       $($_.Description)" -ForegroundColor Gray }
        }
        Write-Host ""
    }
    
    if ($high.Count -gt 0) {
        Write-Host "HIGH RISK GROUPS (Administrative access):" -ForegroundColor Red
        $high | ForEach-Object { 
            Write-Host "    🔴 $($_.DisplayName)" -ForegroundColor Red
        }
        Write-Host ""
    }
    
    if ($medium.Count -gt 0) {
        Write-Host "DYNAMIC GROUPS (Auto-assigned, may be skipped):" -ForegroundColor Yellow
        $medium | ForEach-Object { 
            Write-Host "    🟡 $($_.DisplayName)" -ForegroundColor Yellow
        }
        Write-Host ""
    }
    
    Write-Host "STANDARD GROUPS: $($low.Count)" -ForegroundColor Green
    Write-Host ""
}

function Invoke-GroupCopy {
    param(
        [array]$Groups,
        [string]$TargetUserId,
        [string]$TargetUserName,
        [bool]$SkipPrivileged,
        [bool]$SkipDynamic,
        [bool]$WhatIf
    )
    
    $results = @{
        Success = @()
        Failed = @()
        Skipped = @()
        BlockedByFilter = @()
    }
    
    $total = $Groups.Count
    $current = 0
    
    foreach ($group in $Groups) {
        $current++
        $percent = [math]::Round(($current / $total) * 100)
        Show-Progress -Activity "Processing group $current of $total" -PercentComplete $percent
        
        # Apply filters
        if ($SkipPrivileged -and ($group.IsPrivileged -or $group.IsRoleAssignable)) {
            $results.BlockedByFilter += [PSCustomObject]@{
                GroupName = $group.DisplayName
                Reason = "Blocked by safety filter (privileged group)"
                GroupId = $group.Id
            }
            continue
        }
        
        if ($SkipDynamic -and $group.IsDynamic) {
            $results.BlockedByFilter += [PSCustomObject]@{
                GroupName = $group.DisplayName
                Reason = "Blocked by safety filter (dynamic group)"
                GroupId = $group.Id
            }
            continue
        }
        
        if ($WhatIf) {
            $results.Success += [PSCustomObject]@{
                GroupName = $group.DisplayName
                Reason = "WHATIF: Would be added"
                GroupId = $group.Id
            }
            continue
        }
        
        # Check if already member
        try {
            $existing = Get-MgGroupMember -GroupId $group.Id -All | 
                Where-Object { $_.Id -eq $TargetUserId }
            
            if ($existing) {
                $results.Skipped += [PSCustomObject]@{
                    GroupName = $group.DisplayName
                    Reason = "Already a member"
                    GroupId = $group.Id
                }
                continue
            }
        }
        catch {
            # Continue anyway, will catch in main try
        }
        
        # Attempt to add
        try {
            $body = @{
                "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$TargetUserId"
            }
            
            New-MgGroupMemberByRef -GroupId $group.Id -BodyParameter $body -ErrorAction Stop
            
            $results.Success += [PSCustomObject]@{
                GroupName = $group.DisplayName
                Reason = "Successfully added"
                GroupId = $group.Id
            }
        }
        catch {
            $errorMsg = $_.Exception.Message
            
            if ($errorMsg -like "*One or more added object references already exist*") {
                $results.Skipped += [PSCustomObject]@{
                    GroupName = $group.DisplayName
                    Reason = "Already a member"
                    GroupId = $group.Id
                }
            }
            elseif ($errorMsg -like "*Dynamic*") {
                $results.Skipped += [PSCustomObject]@{
                    GroupName = $group.DisplayName
                    Reason = "Dynamic group (cannot manually assign)"
                    GroupId = $group.Id
                }
            }
            elseif ($errorMsg -like "*insufficient privileges*" -or $errorMsg -like "*Authorization*") {
                $results.Failed += [PSCustomObject]@{
                    GroupName = $group.DisplayName
                    Reason = "Insufficient privileges"
                    GroupId = $group.Id
                }
            }
            else {
                $results.Failed += [PSCustomObject]@{
                    GroupName = $group.DisplayName
                    Reason = $errorMsg
                    GroupId = $group.Id
                }
            }
        }
    }
    
    Write-Progress -Activity "Processing groups..." -Completed
    return $results
}

function Show-FinalReport {
    param([hashtable]$Results)
    
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                      EXECUTION REPORT                            ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    $totalProcessed = $Results.Success.Count + $Results.Failed.Count + 
                      $Results.Skipped.Count + $Results.BlockedByFilter.Count
    
    Write-Host "SUMMARY:" -ForegroundColor White
    Write-Host "    Total Groups Evaluated: $totalProcessed" -ForegroundColor White
    Write-Host ""
    
    if ($Results.Success.Count -gt 0) {
        Write-Host "✓ SUCCESSFULLY ADDED: $($Results.Success.Count)" -ForegroundColor Green
        $Results.Success | ForEach-Object { 
            Write-Host "      ✓ $($_.GroupName)" -ForegroundColor Green
        }
        Write-Host ""
    }
    
    if ($Results.Skipped.Count -gt 0) {
        Write-Host "○ SKIPPED: $($Results.Skipped.Count)" -ForegroundColor Yellow
        $Results.Skipped | ForEach-Object { 
            Write-Host "      ○ $($_.GroupName) - $($_.Reason)" -ForegroundColor Yellow
        }
        Write-Host ""
    }
    
    if ($Results.BlockedByFilter.Count -gt 0) {
        Write-Host "🛡️  BLOCKED BY SAFETY FILTERS: $($Results.BlockedByFilter.Count)" -ForegroundColor Cyan
        $Results.BlockedByFilter | ForEach-Object { 
            Write-Host "      🛡️  $($_.GroupName) - $($_.Reason)" -ForegroundColor Cyan
        }
        Write-Host ""
    }
    
    if ($Results.Failed.Count -gt 0) {
        Write-Host "✗ FAILED: $($Results.Failed.Count)" -ForegroundColor Red
        $Results.Failed | ForEach-Object { 
            Write-Host "      ✗ $($_.GroupName)" -ForegroundColor Red
            Write-Host "        Error: $($_.Reason)" -ForegroundColor DarkRed
        }
        Write-Host ""
    }
    
    # Export to file
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "GroupCopy_Report_$timestamp.csv"
    
    $allResults = @()
    $allResults += $Results.Success | Select-Object *, @{N="Result";E={"Success"}}
    $allResults += $Results.Skipped | Select-Object *, @{N="Result";E={"Skipped"}}
    $allResults += $Results.BlockedByFilter | Select-Object *, @{N="Result";E={"BlockedByFilter"}}
    $allResults += $Results.Failed | Select-Object *, @{N="Result";E={"Failed"}}
    
    if ($allResults.Count -gt 0) {
        $allResults | Export-Csv -Path ".\$filename" -NoTypeInformation
        Write-Host "📄 Detailed report saved to: $filename" -ForegroundColor White
    }
}

#endregion

#region Main Execution

try {
    Show-Banner
    
    # Check Microsoft Graph Connection
    $context = Get-MgContext
    if (-not $context) {
        Write-Log "Connecting to Microsoft Graph..." -Level "Info"
        Connect-MgGraph -Scopes "User.Read.All", "Group.ReadWrite.All", "Directory.ReadWrite.All"
        $context = Get-MgContext
    }
    
    Write-Log "Connected as: $($context.Account)" -Level "Success"
    Write-Host ""
    
    # Step 1: Source User
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host "STEP 1: SOURCE USER (User to copy groups FROM)" -ForegroundColor Blue
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Blue
    
    $sourceEmail = Read-EmailInput -PromptMessage "Enter source user email: "
    $sourceUser = Get-UserDetails -Email $sourceEmail
    
    if (-not $sourceUser) {
        throw "Cannot proceed without valid source user"
    }
    
    # Step 2: Retrieve and Analyze Groups
    $sourceGroups = Get-GroupMemberships -UserId $sourceUser.Id
    
    if (-not $sourceGroups -or $sourceGroups.Count -eq 0) {
        Write-Log "Source user has no group memberships. Nothing to copy." -Level "Warning"
        exit 0
    }
    
    Show-GroupAnalysis -Groups $sourceGroups
    
    # Step 3: Target User
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host "STEP 2: TARGET USER (User to copy groups TO)" -ForegroundColor Blue
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Blue
    
    $targetEmail = Read-EmailInput -PromptMessage "Enter target user email: "
    
    if ($targetEmail -eq $sourceEmail) {
        throw "Source and target users cannot be the same"
    }
    
    $targetUser = Get-UserDetails -Email $targetEmail
    
    if (-not $targetUser) {
        throw "Cannot proceed without valid target user"
    }
    
    # Step 4: Safety Confirmation
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host "⚠️  SAFETY CONFIRMATION REQUIRED" -ForegroundColor Red
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host ""
    Write-Host "You are about to copy $($sourceGroups.Count) group memberships:" -ForegroundColor Yellow
    Write-Host "    FROM: $($sourceUser.DisplayName) ($sourceEmail)" -ForegroundColor White
    Write-Host "    TO:   $($targetUser.DisplayName) ($targetEmail)" -ForegroundColor White
    Write-Host ""
    
    $hasPrivileged = ($sourceGroups | Where-Object { $_.IsPrivileged -or $_.IsRoleAssignable }).Count -gt 0
    $hasDynamic = ($sourceGroups | Where-Object { $_.IsDynamic }).Count -gt 0
    
    if ($hasPrivileged) {
        Write-Host "🛑 WARNING: Source user has PRIVILEGED/ADMIN groups!" -ForegroundColor Magenta
    }
    
    # Step 5: Filter Selection
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host "STEP 3: SAFETY FILTERS" -ForegroundColor Blue
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host ""
    
    $skipPrivileged = $true
    if ($hasPrivileged) {
        $skipPrivileged = -not (Confirm-Action -Message "Include PRIVILEGED groups (Admin, Security, etc.)?" -RequireExactText "INCLUDE-PRIVILEGED")
        if (-not $skipPrivileged) {
            Write-Log "Privileged groups WILL be included" -Level "Critical"
        }
    }
    
    $skipDynamic = Confirm-Action -Message "Skip DYNAMIC groups (recommended)?"
    
    $whatIf = Confirm-Action -Message "Run in PREVIEW mode first (no changes made)?"
    
    # Final Confirmation
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host "FINAL CONFIRMATION" -ForegroundColor Red
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host ""
    Write-Host "Configuration:" -ForegroundColor White
    Write-Host "    Skip Privileged Groups: $(if($skipPrivileged){'YES ✅'}else{'NO ❌'})" -ForegroundColor $(if($skipPrivileged){'Green'}else{'Red'})
    Write-Host "    Skip Dynamic Groups: $(if($skipDynamic){'YES ✅'}else{'NO ❌'})" -ForegroundColor $(if($skipDynamic){'Green'}else{'Yellow'})
    Write-Host "    Preview Mode Only: $(if($whatIf){'YES 👁️'}else{'NO ⚡'})" -ForegroundColor $(if($whatIf){'Cyan'}else{'Yellow'})
    Write-Host ""
    
    $groupsToProcess = $sourceGroups
    if ($skipPrivileged) {
        $groupsToProcess = $groupsToProcess | Where-Object { -not ($_.IsPrivileged -or $_.IsRoleAssignable) }
    }
    if ($skipDynamic) {
        $groupsToProcess = $groupsToProcess | Where-Object { -not $_.IsDynamic }
    }
    
    Write-Host "Groups to be processed: $($groupsToProcess.Count) of $($sourceGroups.Count)" -ForegroundColor Cyan
    Write-Host ""
    
    if (-not (Confirm-Action -Message "Proceed with this configuration?" -RequireExactText "COPY-GROUPS")) {
        Write-Log "Operation cancelled by user" -Level "Warning"
        exit 0
    }
    
    # Execute
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "EXECUTING..." -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    
    $executionResults = Invoke-GroupCopy -Groups $groupsToProcess `
        -TargetUserId $targetUser.Id `
        -TargetUserName $targetUser.DisplayName `
        -SkipPrivileged $skipPrivileged `
        -SkipDynamic $skipDynamic `
        -WhatIf $whatIf
    
    Show-FinalReport -Results $executionResults
    
    if ($whatIf -and ($executionResults.Success.Count -gt 0)) {
        Write-Host ""
        Write-Host "👁️  This was a PREVIEW run. No changes were made." -ForegroundColor Cyan
        if (Confirm-Action -Message "Execute for real now?") {
            $executionResults = Invoke-GroupCopy -Groups $groupsToProcess `
                -TargetUserId $targetUser.Id `
                -TargetUserName $targetUser.DisplayName `
                -SkipPrivileged $skipPrivileged `
                -SkipDynamic $skipDynamic `
                -WhatIf $false
            Show-FinalReport -Results $executionResults
        }
    }
    
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "OPERATION COMPLETE" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host "CRITICAL ERROR" -ForegroundColor Red
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host ""
    Write-Log $_.Exception.Message -Level "Critical"
    Write-Log $_.ScriptStackTrace -Level "Error"
    exit 1
}

#endregion
