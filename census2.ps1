<#
.SYNOPSIS
    Search Microsoft Graph for users by department with fallback permission handling.

.DESCRIPTION
    Searches for users in a specified department and retrieves account status and profile information.
    Includes diagnostic mode and fallback options when AuditLog.Read.All permission is unavailable.

.PARAMETER Department
    The department name to search for.

.PARAMETER OutputPath
    Optional path to export results to CSV.

.PARAMETER UseFallbackMode
    Switch to skip sign-in activity lookup (works with basic User.Read.All permission only).

.PARAMETER DiagnosticMode
    Switch to run permission diagnostics without executing search.

.EXAMPLE
    .\Get-DepartmentUsers.ps1 -Department "IT" -UseFallbackMode
    
.EXAMPLE
    .\Get-DepartmentUsers.ps1 -Department "Sales" -DiagnosticMode
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Department,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$UseFallbackMode,

    [Parameter(Mandatory = $false)]
    [switch]$DiagnosticMode
)

#Requires -Modules @{ ModuleName="Microsoft.Graph.Users"; ModuleVersion="2.0.0" }

#region Functions

function Test-MgGraphPermission {
    <#
    Checks current permissions and admin consent status.
    Returns permission status object.
    #>
    $context = Get-MgContext
    
    if (-not $context) {
        return @{ Connected = $false; Message = "Not connected to Microsoft Graph" }
    }

    $scopes = $context.Scopes
    $hasUserRead = $scopes -contains "User.Read.All"
    $hasAuditLog = $scopes -contains "AuditLog.Read.All"
    $hasDirectoryRead = $scopes -contains "Directory.Read.All"

    # Test if AuditLog permission actually works (admin consent check)
    $auditLogWorking = $false
    if ($hasAuditLog -and -not $UseFallbackMode) {
        try {
            # Test query with minimal data
            $testUser = Get-MgUser -Top 1 -Select "Id,SignInActivity" -ErrorAction Stop
            if ($testUser.SignInActivity -or $testUser.Id) {
                $auditLogWorking = $true
            }
        }
        catch {
            $auditLogWorking = $false
        }
    }

    return @{
        Connected = $true
        Account = $context.Account
        TenantId = $context.TenantId
        HasUserReadAll = $hasUserRead
        HasAuditLogReadAll = $hasAuditLog
        HasDirectoryReadAll = $hasDirectoryRead
        AuditLogFunctional = $auditLogWorking
        AllScopes = $scopes
        AuthType = $context.AuthType
    }
}

function Connect-MgGraphWithRetry {
    <#
    Attempts connection with progressive permission levels.
    #>
    param (
        [switch]$BasicOnly
    )

    # Disconnect if already connected
    $existingContext = Get-MgContext
    if ($existingContext) {
        Write-Host "Disconnecting existing session..." -ForegroundColor Yellow
        Disconnect-MgGraph | Out-Null
        Start-Sleep -Seconds 2
    }

    if ($BasicOnly) {
        Write-Host "Connecting with BASIC permissions (User.Read.All only)..." -ForegroundColor Cyan
        try {
            Connect-MgGraph -Scopes "User.Read.All" -NoWelcome
            return $true
        }
        catch {
            Write-Error "Failed to connect with basic permissions: $_"
            return $false
        }
    }

    # Try full permissions first
    Write-Host "Connecting with FULL permissions..." -ForegroundColor Cyan
    $fullScopes = @("User.Read.All", "AuditLog.Read.All", "Directory.Read.All")
    
    try {
        Connect-MgGraph -Scopes $fullScopes -NoWelcome
        return $true
    }
    catch [System.UnauthorizedAccessException] {
        Write-Warning "Full permissions denied. Trying basic permissions..."
        
        try {
            Connect-MgGraph -Scopes "User.Read.All" -NoWelcome
            Write-Host "Connected with BASIC permissions (sign-in data unavailable)" -ForegroundColor Yellow
            return $true
        }
        catch {
            Write-Error "Failed to connect with any permissions: $_"
            return $false
        }
    }
    catch {
        Write-Error "Connection error: $_"
        return $false
    }
}

function Invoke-MgGraphWithFallback {
    <#
    Attempts to query users, falls back to basic query if sign-in activity fails.
    #>
    param (
        [string]$Filter,
        [switch]$SkipSignInActivity
    )

    $selectBasic = "Id,DisplayName,UserPrincipalName,Mail,JobTitle,Department,AccountEnabled,CreatedDateTime,OfficeLocation"
    $selectFull = $selectBasic + ",SignInActivity"

    # Try full query first (with SignInActivity)
    if (-not $SkipSignInActivity) {
        try {
            Write-Verbose "Attempting query WITH SignInActivity..."
            $users = Get-MgUser -Filter $Filter `
                                -Select $selectFull `
                                -ConsistencyLevel eventual `
                                -CountVariable count `
                                -All `
                                -ErrorAction Stop
            return @{
                Users = $users
                Count = $count
                Mode = "Full"
                Success = $true
            }
        }
        catch [System.Exception] {
            $errorMsg = $_.Exception.Message
            
            # Check for specific permission errors
            if ($errorMsg -like "*AllowedRoles*" -or 
                $errorMsg -like "*privileges*" -or 
                $errorMsg -like "*unauthorized*" -or
                $errorMsg -like "*AdminConsentRequired*") {
                
                Write-Warning "Full permissions denied. Error: $errorMsg"
                Write-Host "Falling back to BASIC mode (no sign-in activity)..." -ForegroundColor Yellow
                
                # Recursively call with skip flag
                return Invoke-MgGraphWithFallback -Filter $Filter -SkipSignInActivity
            }
            else {
                throw
            }
        }
    }

    # Fallback: Basic query without SignInActivity
    try {
        Write-Verbose "Executing query WITHOUT SignInActivity..."
        $users = Get-MgUser -Filter $Filter `
                            -Select $selectBasic `
                            -ConsistencyLevel eventual `
                            -CountVariable count `
                            -All `
                            -ErrorAction Stop
        return @{
            Users = $users
            Count = $count
            Mode = "Basic"
            Success = $true
        }
    }
    catch {
        return @{
            Users = $null
            Count = 0
            Mode = "Failed"
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-DepartmentUsersSafe {
    <#
    Safely retrieves users with automatic fallback handling.
    #>
    param (
        [string]$DepartmentName,
        [switch]$ForceBasicMode
    )

    Write-Host "`nSearching for users in department: $DepartmentName" -ForegroundColor Cyan

    # Sanitize department name for OData filter
    $safeDept = $DepartmentName -replace "'", "''"
    $filter = "department eq '$safeDept'"

    # Try query with automatic fallback
    $result = Invoke-MgGraphWithFallback -Filter $filter -SkipSignInActivity:$ForceBasicMode

    if (-not $result.Success) {
        throw "Query failed: $($result.Error)"
    }

    Write-Host "Found $($result.Count) users (Mode: $($result.Mode))" -ForegroundColor $(if ($result.Mode -eq "Full") { "Green" } else { "Yellow" })
    
    if ($result.Mode -eq "Basic") {
        Write-Host "NOTE: Last sign-in data unavailable due to insufficient permissions" -ForegroundColor Yellow
        Write-Host "To enable sign-in data, an admin must grant 'AuditLog.Read.All' consent at:" -ForegroundColor Yellow
        Write-Host "https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade" -ForegroundColor Cyan
    }

    return @{
        Users = $result.Users
        Mode = $result.Mode
    }
}

function Format-UserOutputSafe {
    <#
    Formats user data handling both Full and Basic modes.
    #>
    param (
        [array]$Users,
        [string]$Mode
    )

    $results = foreach ($user in $Users) {
        # Handle sign-in data only if available (Full mode)
        $lastSignIn = $null
        $daysSinceSignIn = $null
        $signInStatus = "N/A - Permission Required"

        if ($Mode -eq "Full" -and $user.SignInActivity) {
            $lastSignIn = if ($user.SignInActivity.LastSignInDateTime) {
                [datetime]$user.SignInActivity.LastSignInDateTime
            } else { $null }

            if ($lastSignIn) {
                $daysSinceSignIn = ((Get-Date) - $lastSignIn).Days
                
                $signInStatus = if ($daysSinceSignIn -gt 90) {
                    "Stale (>90 days)"
                } elseif ($daysSinceSignIn -gt 30) {
                    "Warning (>30 days)"
                } else {
                    "Recent"
                }
            }
            else {
                $signInStatus = "Never signed in"
            }
        }

        [PSCustomObject]@{
            DisplayName       = $user.DisplayName
            Email             = $user.Mail
            UserPrincipalName = $user.UserPrincipalName
            JobTitle          = $user.JobTitle
            Department        = $user.Department
            AccountEnabled    = $user.AccountEnabled
            AccountStatus     = if ($user.AccountEnabled) { "Active" } else { "Disabled" }
            LastSignInDate    = if ($lastSignIn) { 
                $lastSignIn.ToString("yyyy-MM-dd HH:mm:ss") 
            } else { 
                "N/A" 
            }
            DaysSinceSignIn   = $daysSinceSignIn
            LastSignInStatus  = $signInStatus
            DataMode          = $Mode
            UserId            = $user.Id
        }
    }

    return $results
}

function Show-DiagnosticReport {
    <#
    Displays comprehensive permission diagnostics.
    #>
    Write-Host "`n=== MICROSOFT GRAPH DIAGNOSTIC REPORT ===" -ForegroundColor Cyan
    
    $permStatus = Test-MgGraphPermission
    
    if (-not $permStatus.Connected) {
        Write-Host "Status: NOT CONNECTED" -ForegroundColor Red
        Write-Host $permStatus.Message
        return
    }

    Write-Host "`nConnection Details:" -ForegroundColor Yellow
    Write-Host "  Account: $($permStatus.Account)"
    Write-Host "  Tenant: $($permStatus.TenantId)"
    Write-Host "  Auth Type: $($permStatus.AuthType)"

    Write-Host "`nPermission Status:" -ForegroundColor Yellow
    Write-Host "  User.Read.All: $(if ($permStatus.HasUserReadAll) { '✓ GRANTED' } else { '✗ MISSING' })" -ForegroundColor $(if ($permStatus.HasUserReadAll) { "Green" } else { "Red" })
    Write-Host "  AuditLog.Read.All: $(if ($permStatus.HasAuditLogReadAll) { '✓ GRANTED' } else { '✗ MISSING' })" -ForegroundColor $(if ($permStatus.HasAuditLogReadAll) { "Green" } else { "Red" })
    Write-Host "  Directory.Read.All: $(if ($permStatus.HasDirectoryReadAll) { '✓ GRANTED' } else { '✗ MISSING' })" -ForegroundColor $(if ($permStatus.HasDirectoryReadAll) { "Green" } else { "Red" })

    Write-Host "`nFunctional Tests:" -ForegroundColor Yellow
    Write-Host "  SignInActivity Query: $(if ($permStatus.AuditLogFunctional) { '✓ WORKING' } else { '✗ BLOCKED' })" -ForegroundColor $(if ($permStatus.AuditLogFunctional) { "Green" } else { "Red" })

    if (-not $permStatus.HasAuditLogReadAll) {
        Write-Host "`n⚠ RECOMMENDATION: Basic Mode Required" -ForegroundColor Yellow
        Write-Host "   Run script with -UseFallbackMode parameter" -ForegroundColor White
    }
    elseif (-not $permStatus.AuditLogFunctional) {
        Write-Host "`n⚠ RECOMMENDATION: Admin Consent Required" -ForegroundColor Yellow
        Write-Host "   An Azure AD admin must grant consent for AuditLog.Read.All" -ForegroundColor White
        Write-Host "   URL: https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade" -ForegroundColor Cyan
    }
    else {
        Write-Host "`n✓ All permissions functional. Full mode available." -ForegroundColor Green
    }

    Write-Host "`nAll Granted Scopes:" -ForegroundColor Gray
    $permStatus.AllScopes | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
}

#endregion

#region Main Execution

# Diagnostic mode only
if ($DiagnosticMode) {
    # Ensure connection exists for diagnostics
    if (-not (Get-MgContext)) {
        Connect-MgGraph -Scopes "User.Read" -NoWelcome
    }
    Show-DiagnosticReport
    exit 0
}

# Ensure connection with appropriate permissions
$permCheck = Test-MgGraphPermission

if (-not $permCheck.Connected -or 
    -not $permCheck.HasUserReadAll -or 
    ($UseFallbackMode -and $permCheck.HasAuditLogReadAll)) {
    
    # Determine best connection strategy
    $useBasic = $UseFallbackMode -or (-not $permCheck.HasAuditLogReadAll)
    
    if (-not (Connect-MgGraphWithRetry -BasicOnly:$useBasic)) {
        exit 1
    }
}

# Re-check permissions after connection
$finalPermCheck = Test-MgGraphPermission
Write-Host "`nConnected as: $($finalPermCheck.Account)" -ForegroundColor Green

# Determine execution mode
$forceBasic = $UseFallbackMode -or (-not $finalPermCheck.AuditLogFunctional)

if ($forceBasic) {
    Write-Host "Running in BASIC MODE (sign-in data unavailable)" -ForegroundColor Yellow
}

# Execute search
try {
    $searchResult = Get-DepartmentUsersSafe -DepartmentName $Department -ForceBasicMode:$forceBasic
    
    if (-not $searchResult.Users) {
        Write-Host "No users found in department: $Department" -ForegroundColor Yellow
        
        # Suggest fuzzy search
        Write-Host "`nTip: Try exact department name from Active Directory, or check available departments:" -ForegroundColor Cyan
        Write-Host "  Get-MgUser -Select Department -All | Where-Object Department | Group-Object Department | Select-Object Name,Count" -ForegroundColor Gray
        exit 0
    }

    # Format and display results
    $formattedResults = Format-UserOutputSafe -Users $searchResult.Users -Mode $searchResult.Mode
    
    Write-Host "`nResults:" -ForegroundColor Cyan
    Write-Host ("=" * 120) -ForegroundColor Gray
    $formattedResults | Format-Table -AutoSize

    # Summary statistics
    $total = $formattedResults.Count
    $disabled = ($formattedResults | Where-Object { -not $_.AccountEnabled }).Count
    $noSignInData = ($formattedResults | Where-Object { $_.LastSignInStatus -eq "N/A - Permission Required" }).Count

    Write-Host "`nSummary:" -ForegroundColor Cyan
    Write-Host "  Total Users: $total"
    Write-Host "  Disabled Accounts: $disabled" -ForegroundColor $(if ($disabled -gt 0) { "Red" } else { "Green" })
    
    if ($searchResult.Mode -eq "Full") {
        $neverSignedIn = ($formattedResults | Where-Object { $_.LastSignInStatus -eq "Never signed in" }).Count
        $stale = ($formattedResults | Where-Object { $_.LastSignInStatus -eq "Stale (>90 days)" }).Count
        Write-Host "  Never Signed In: $neverSignedIn" -ForegroundColor $(if ($neverSignedIn -gt 0) { "Yellow" } else { "Green" })
        Write-Host "  Stale Accounts (>90 days): $stale" -ForegroundColor $(if ($stale -gt 0) { "Yellow" } else { "Green" })
    }
    else {
        Write-Host "  Sign-in Data: Unavailable (Basic Mode)" -ForegroundColor Yellow
    }

    # Export if requested
    if ($OutputPath) {
        try {
            $formattedResults | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
            Write-Host "`nExported to: $OutputPath" -ForegroundColor Green
        }
        catch {
            Write-Error "Export failed: $_"
        }
    }

    return $formattedResults
}
catch {
    Write-Error "Script failed: $_"
    
    # Provide specific guidance
    if ($_.Exception.Message -like "*AllowedRoles*" -or $_.Exception.Message -like "*unauthorized*") {
        Write-Host "`nTROUBLESHOOTING:" -ForegroundColor Yellow
        Write-Host "1. Run with diagnostic mode: .\Get-DepartmentUsers.ps1 -Department 'IT' -DiagnosticMode" -ForegroundColor White
        Write-Host "2. Run with fallback mode: .\Get-DepartmentUsers.ps1 -Department 'IT' -UseFallbackMode" -ForegroundColor White
        Write-Host "3. Request admin consent for AuditLog.Read.All in Azure Portal" -ForegroundColor White
    }
    
    exit 1
}

#endregion
