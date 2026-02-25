<#
.SYNOPSIS
    Search Microsoft Graph for users by department and export sign-in and account status information.
    
.DESCRIPTION
    Connects to Microsoft Graph with required permissions, searches for users in a specified department,
    and retrieves last sign-in time, account status, name, email, and job title.
    Compatible with Windows PowerShell 5.1.

.PARAMETER Department
    The department name to search for.

.PARAMETER OutputPath
    Optional path to export results to CSV.

.PARAMETER IncludeAllProperties
    Switch to include additional properties.

.PARAMETER UseContains
    Switch to use 'contains' operator instead of exact match.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Department,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeAllProperties,

    [Parameter(Mandatory = $false)]
    [switch]$UseContains
)

#Requires -Version 5.1

#region Main Script

# Always connect with required permissions (forces consent if needed)
Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All","Directory.Read.All" -NoWelcome | Out-Null

Write-Verbose "Connected to Microsoft Graph"

# Build filter
$filterOperator = if ($UseContains) { "contains" } else { "eq" }
$filter = "department $filterOperator '$Department'"

Write-Verbose "Searching with filter: $filter"

# Get users with required properties
try {
    $users = Get-MgUser -Filter $filter `
                        -Select "Id,DisplayName,UserPrincipalName,Mail,JobTitle,Department,AccountEnabled,SignInActivity,CreatedDateTime,OfficeLocation,City,Country" `
                        -ConsistencyLevel eventual `
                        -CountVariable userCount `
                        -All `
                        -ErrorAction Stop

    if (-not $users) {
        Write-Warning "No users found in department: $Department"
        Disconnect-MgGraph | Out-Null
        return
    }

    Write-Host "Found $userCount users in department '$Department'" -ForegroundColor Green
}
catch {
    Write-Error "Failed to retrieve users: $_"
    Disconnect-MgGraph | Out-Null
    return
}

# Process results
$today = Get-Date
$results = foreach ($user in $users) {
    
    # Handle sign-in activity (PS 5.1 compatible)
    $lastSignIn = $null
    $daysSinceSignIn = $null
    
    if ($user.SignInActivity -and $user.SignInActivity.LastSignInDateTime) {
        try {
            $lastSignIn = [datetime]::Parse($user.SignInActivity.LastSignInDateTime)
            $daysSinceSignIn = ($today - $lastSignIn).Days
        }
        catch {
            Write-Verbose "Failed to parse sign-in date for $($user.UserPrincipalName)"
        }
    }

    # Build output object
    $output = [PSCustomObject]@{
        DisplayName       = $user.DisplayName
        Email             = $user.Mail
        UserPrincipalName = $user.UserPrincipalName
        JobTitle          = $user.JobTitle
        Department        = $user.Department
        AccountEnabled    = $user.AccountEnabled
        AccountStatus     = if ($user.AccountEnabled) { "Active" } else { "Disabled" }
        LastSignInDate    = if ($lastSignIn) { $lastSignIn.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never/N/A" }
        DaysSinceSignIn   = $daysSinceSignIn
        LastSignInStatus  = if (-not $lastSignIn) {
                                "No sign-in recorded"
                            } elseif ($daysSinceSignIn -gt 90) {
                                "Stale (>90 days)"
                            } elseif ($daysSinceSignIn -gt 30) {
                                "Warning (>30 days)"
                            } else {
                                "Recent"
                            }
    }

    # Add extended properties if requested
    if ($IncludeAllProperties) {
        $output | Add-Member -NotePropertyName CreatedDate -NotePropertyValue (
            if ($user.CreatedDateTime) { ([datetime]::Parse($user.CreatedDateTime)).ToString("yyyy-MM-dd") } else { "N/A" }
        )
        $output | Add-Member -NotePropertyName Office -NotePropertyValue $user.OfficeLocation
        $output | Add-Member -NotePropertyName City -NotePropertyValue $user.City
        $output | Add-Member -NotePropertyName Country -NotePropertyValue $user.Country
        $output | Add-Member -NotePropertyName UserId -NotePropertyValue $user.Id
    }

    $output
}

# Display results
Write-Host "`nDepartment User Report" -ForegroundColor Cyan
Write-Host ("=" * 100) -ForegroundColor Gray
$results | Format-Table -AutoSize

# Summary
$disabled = ($results | Where-Object { $_.AccountEnabled -eq $false }).Count
$neverSignedIn = ($results | Where-Object { $_.LastSignInDate -eq "Never/N/A" }).Count
$stale = ($results | Where-Object { $_.LastSignInStatus -eq "Stale (>90 days)" }).Count

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "  Total: $($results.Count) | Disabled: $disabled | Never signed in: $neverSignedIn | Stale (>90d): $stale"

# Export if requested
if ($OutputPath) {
    try {
        $dir = Split-Path -Parent $OutputPath
        if ($dir -and -not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -Force
        Write-Host "Exported to: $OutputPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Export failed: $_"
    }
}

# Cleanup
Disconnect-MgGraph | Out-Null

return $results

#endregion
