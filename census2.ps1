<#
.SYNOPSIS
    Get members from a Distribution List (mail-enabled group) and their sign-in details.
    
.DESCRIPTION
    Distribution lists are read-only in Microsoft Graph and synchronize from Exchange Online.
    This script uses Get-MgGroupTransitiveMember to resolve nested memberships.
    
.PARAMETER DistributionListName
    The display name or email address of the distribution list.

.PARAMETER OutputPath
    Optional CSV export path.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$DistributionListName,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

#Requires -Version 5.1

#region Main Script

# Connect with required permissions - Group.Read.All is essential for distribution lists
Connect-MgGraph -Scopes "Group.Read.All","User.Read.All","AuditLog.Read.All","Directory.Read.All" -NoWelcome | Out-Null

Write-Verbose "Connected to Microsoft Graph"

# Find the distribution list
# Distribution lists: mailEnabled=true, securityEnabled=false, groupTypes=[]
try {
    $dl = Get-MgGroup -Filter "mailEnabled eq true and securityEnabled eq false and startsWith(displayName,'$DistributionListName')" `
                      -Top 1 `
                      -Property "Id,DisplayName,Mail,GroupTypes,MailEnabled,SecurityEnabled" `
                      -ErrorAction Stop
    
    if (-not $dl) {
        # Try exact match on mail property
        $dl = Get-MgGroup -Filter "mail eq '$DistributionListName'" `
                          -Top 1 `
                          -Property "Id,DisplayName,Mail,GroupTypes,MailEnabled,SecurityEnabled" `
                          -ErrorAction SilentlyContinue
    }
    
    if (-not $dl) {
        Write-Error "Distribution list '$DistributionListName' not found. Note: Dynamic distribution groups are not accessible via Microsoft Graph."
        Disconnect-MgGraph | Out-Null
        return
    }

    Write-Host "Found distribution list: $($dl.DisplayName) ($($dl.Mail))" -ForegroundColor Green
}
catch {
    Write-Error "Failed to find distribution list: $_"
    Disconnect-MgGraph | Out-Null
    return
}

# Get transitive members (resolves nested groups)
try {
    Write-Verbose "Retrieving members (including nested groups)..."
    
    # Use Get-MgGroupTransitiveMember to expand all nested memberships
    $members = Get-MgGroupTransitiveMember -GroupId $dl.Id -All -ErrorAction Stop
    
    if (-not $members) {
        Write-Warning "No members found in distribution list."
        Disconnect-MgGraph | Out-Null
        return
    }

    Write-Host "Found $($members.Count) total members (including nested)" -ForegroundColor Green
}
catch {
    Write-Error "Failed to retrieve members. Ensure you have Group.Read.All permission and admin consent. Error: $_"
    Disconnect-MgGraph | Out-Null
    return
}

# Process members - filter to users only and get detailed info
$today = Get-Date
$results = @()
$userCount = 0
$skippedCount = 0

foreach ($member in $members) {
    # Check if this is a user (not a group or contact)
    $memberType = $member.AdditionalProperties['@odata.type']
    
    if ($memberType -ne '#microsoft.graph.user') {
        Write-Verbose "Skipping non-user member: $($member.AdditionalProperties.displayName) (Type: $memberType)"
        $skippedCount++
        continue
    }
    
    $userCount++
    $userId = $member.Id
    
    # Get detailed user info including sign-in activity
    try {
        $userDetails = Get-MgUser -UserId $userId `
                                  -Property "DisplayName,UserPrincipalName,Mail,JobTitle,Department,AccountEnabled,SignInActivity,CreatedDateTime,OfficeLocation,City,Country,LastPasswordChangeDateTime" `
                                  -ErrorAction SilentlyContinue
    }
    catch {
        Write-Verbose "Failed to get details for user $userId : $_"
        continue
    }

    if (-not $userDetails) { continue }

    # Parse sign-in activity
    $lastSignIn = $null
    $daysSinceSignIn = $null
    
    if ($userDetails.SignInActivity -and $userDetails.SignInActivity.LastSignInDateTime) {
        try {
            $lastSignIn = [datetime]::Parse($userDetails.SignInActivity.LastSignInDateTime)
            $daysSinceSignIn = ($today - $lastSignIn).Days
        }
        catch {
            Write-Verbose "Failed to parse sign-in date for $($userDetails.UserPrincipalName)"
        }
    }

    # Build output object
    $output = [PSCustomObject]@{
        DisplayName       = $userDetails.DisplayName
        Email             = $userDetails.Mail
        UserPrincipalName = $userDetails.UserPrincipalName
        JobTitle          = $userDetails.JobTitle
        Department        = $userDetails.Department
        Office            = $userDetails.OfficeLocation
        AccountEnabled    = $userDetails.AccountEnabled
        AccountStatus     = if ($userDetails.AccountEnabled) { "Active" } else { "Disabled" }
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
        LastPasswordChange = if ($userDetails.LastPasswordChangeDateTime) { 
                                ([datetime]::Parse($userDetails.LastPasswordChangeDateTime)).ToString("yyyy-MM-dd")
                             } else { 
                                "Unknown" 
                             }
        UserId            = $userDetails.Id
    }

    $results += $output
}

# Display results
Write-Host "`nDistribution List Member Report: $($dl.DisplayName)" -ForegroundColor Cyan
Write-Host ("=" * 100) -ForegroundColor Gray
Write-Host "Total members: $($members.Count) | Users processed: $userCount | Non-user objects skipped: $skippedCount" -ForegroundColor Gray

if ($results.Count -gt 0) {
    $results | Sort-Object DisplayName | Format-Table -AutoSize
    
    # Summary statistics
    $disabled = ($results | Where-Object { $_.AccountEnabled -eq $false }).Count
    $neverSignedIn = ($results | Where-Object { $_.LastSignInDate -eq "Never/N/A" }).Count
    $stale = ($results | Where-Object { $_.LastSignInStatus -eq "Stale (>90 days)" }).Count

    Write-Host "`nSummary:" -ForegroundColor Cyan
    Write-Host "  Total Users: $($results.Count)"
    Write-Host "  Disabled Accounts: $disabled" -ForegroundColor $(if ($disabled -gt 0) { "Red" } else { "Green" })
    Write-Host "  Never Signed In: $neverSignedIn" -ForegroundColor $(if ($neverSignedIn -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Stale Accounts (>90 days): $stale" -ForegroundColor $(if ($stale -gt 0) { "Yellow" } else { "Green" })
}
else {
    Write-Warning "No user members found to display."
}

# Export if requested
if ($OutputPath -and $results.Count -gt 0) {
    try {
        $dir = Split-Path -Parent $OutputPath
        if ($dir -and -not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -Force
        Write-Host "`nExported to: $OutputPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Export failed: $_"
    }
}

# Cleanup
Disconnect-MgGraph | Out-Null

return $results

#endregion
