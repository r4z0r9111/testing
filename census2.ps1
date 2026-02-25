<#
.SYNOPSIS
    Search Microsoft Graph for users by department and export sign-in and account status information.

.DESCRIPTION
    This script connects to Microsoft Graph, searches for users in a specified department,
    and retrieves their last sign-in time, account status, name, email, and job title.
    Requires Microsoft.Graph.Users module and appropriate permissions.

.PARAMETER Department
    The department name to search for (supports wildcards).

.PARAMETER OutputPath
    Optional path to export results to CSV. If not specified, outputs to console.

.PARAMETER IncludeAllProperties
    Switch to include additional properties like created date, office location, etc.

.EXAMPLE
    .\Get-DepartmentUsers.ps1 -Department "IT"
    
.EXAMPLE
    .\Get-DepartmentUsers.ps1 -Department "Sales" -OutputPath "C:\Reports\SalesUsers.csv"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Department,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeAllProperties
)

#Requires -Modules @{ ModuleName="Microsoft.Graph.Users"; ModuleVersion="2.0.0" }

#region Functions

function Connect-MgGraphWithCheck {
    <#
    Checks if already connected to Microsoft Graph, connects if not.
    Requests required permissions for reading user data and sign-in activity.
    #>
    try {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
            
            # Required scopes for this script
            $requiredScopes = @(
                "User.Read.All",                    # Read user profiles
                "AuditLog.Read.All",                # Read sign-in activity (requires admin consent)
                "Directory.Read.All"                # Read directory data
            )
            
            Connect-MgGraph -Scopes $requiredScopes -NoWelcome
            
            # Verify connection
            $context = Get-MgContext
            Write-Host "Connected as: $($context.Account)" -ForegroundColor Green
            Write-Host "Scopes: $($context.Scopes -join ', ')" -ForegroundColor Gray
        } else {
            Write-Host "Already connected to Microsoft Graph as: $($context.Account)" -ForegroundColor Green
        }
        
        # Check if we have the critical AuditLog.Read.All permission
        if (-not ($context.Scopes -contains "AuditLog.Read.All")) {
            Write-Warning "Missing 'AuditLog.Read.All' permission. Last sign-in dates may not be available."
            Write-Warning "Re-connect with: Connect-MgGraph -Scopes 'User.Read.All','AuditLog.Read.All','Directory.Read.All'"
        }
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        exit 1
    }
}

function Get-DepartmentUsers {
    <#
    Retrieves users from specified department with all required properties.
    Uses pagination to handle large result sets.
    #>
    param (
        [string]$DepartmentName
    )

    Write-Host "`nSearching for users in department: $DepartmentName" -ForegroundColor Cyan

    try {
        # Build filter query - exact match or contains depending on input
        # Using OData filter syntax for department
        $filter = "department eq '$DepartmentName'"
        
        # If user wants wildcard search, we can use contains (slower but flexible)
        # $filter = "contains(department,'$DepartmentName')"
        
        Write-Verbose "Using filter: $filter"

        # Define properties to retrieve
        $selectProperties = @(
            "Id",
            "DisplayName",
            "UserPrincipalName", 
            "Mail",
            "JobTitle",
            "Department",
            "AccountEnabled",
            "SignInActivity",      # Contains lastSignInDateTime
            "CreatedDateTime",
            "OfficeLocation",
            "City",
            "Country"
        )

        # Retrieve users with pagination support (-All handles pagination automatically)
        $users = Get-MgUser -Filter $filter `
                            -Select ($selectProperties -join ',') `
                            -ConsistencyLevel eventual `
                            -CountVariable userCount `
                            -All `
                            -ErrorAction Stop

        Write-Host "Found $userCount users in department '$DepartmentName'" -ForegroundColor Green
        
        return $users
    }
    catch {
        Write-Error "Failed to retrieve users: $_"
        
        # Common error handling
        if ($_.Exception.Message -like "*Insufficient privileges*") {
            Write-Host "`nTROUBLESHOOTING: You need admin consent for the required permissions." -ForegroundColor Yellow
            Write-Host "Run: Connect-MgGraph -Scopes 'User.Read.All','AuditLog.Read.All','Directory.Read.All'" -ForegroundColor Yellow
        }
        throw
    }
}

function Format-UserOutput {
    <#
    Transforms raw Graph user objects into clean output format.
    Handles null values and date formatting.
    #>
    param (
        [array]$Users
    )

    $results = foreach ($user in $Users) {
        # Extract last sign-in date from nested property
        $lastSignIn = if ($user.SignInActivity.LastSignInDateTime) {
            [datetime]$user.SignInActivity.LastSignInDateTime
        } else {
            $null
        }

        # Calculate days since last sign-in
        $daysSinceSignIn = if ($lastSignIn) {
            (Get-Date) - $lastSignIn | Select-Object -ExpandProperty Days
        } else {
            $null
        }

        # Create output object
        $output = [PSCustomObject]@{
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
                "Never/N/A" 
            }
            DaysSinceSignIn   = if ($daysSinceSignIn) { 
                $daysSinceSignIn 
            } else { 
                $null 
            }
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
                if ($user.CreatedDateTime) { 
                    ([datetime]$user.CreatedDateTime).ToString("yyyy-MM-dd") 
                } else { 
                    "N/A" 
                }
            )
            $output | Add-Member -NotePropertyName Office -NotePropertyValue ($user.OfficeLocation)
            $output | Add-Member -NotePropertyName City -NotePropertyValue ($user.City)
            $output | Add-Member -NotePropertyName Country -NotePropertyValue ($user.Country)
            $output | Add-Member -NotePropertyName UserId -NotePropertyValue $user.Id
        }

        $output
    }

    return $results
}

#endregion

#region Main Execution

# Connect to Graph
Connect-MgGraphWithCheck

# Retrieve users
try {
    $rawUsers = Get-DepartmentUsers -DepartmentName $Department
    
    if (-not $rawUsers) {
        Write-Host "No users found in department: $Department" -ForegroundColor Yellow
        exit 0
    }

    # Format output
    $formattedResults = Format-UserOutput -Users $rawUsers

    # Display results
    Write-Host "`nResults:" -ForegroundColor Cyan
    Write-Host ("=" * 100) -ForegroundColor Gray
    
    $formattedResults | Format-Table -AutoSize
    
    # Summary statistics
    $total = $formattedResults.Count
    $disabled = ($formattedResults | Where-Object { -not $_.AccountEnabled }).Count
    $neverSignedIn = ($formattedResults | Where-Object { $_.LastSignInDate -eq "Never/N/A" }).Count
    $staleAccounts = ($formattedResults | Where-Object { $_.LastSignInStatus -eq "Stale (>90 days)" }).Count

    Write-Host "`nSummary:" -ForegroundColor Cyan
    Write-Host "  Total Users: $total"
    Write-Host "  Disabled Accounts: $disabled" -ForegroundColor $(if ($disabled -gt 0) { "Red" } else { "Green" })
    Write-Host "  Never Signed In: $neverSignedIn" -ForegroundColor $(if ($neverSignedIn -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Stale Accounts (>90 days): $staleAccounts" -ForegroundColor $(if ($staleAccounts -gt 0) { "Yellow" } else { "Green" })

    # Export if path provided
    if ($OutputPath) {
        try {
            $formattedResults | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
            Write-Host "`nExported to: $OutputPath" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to export to CSV: $_"
        }
    }

    # Return results for pipeline use
    return $formattedResults
}
catch {
    Write-Error "Script execution failed: $_"
    exit 1
}
finally {
    # Optional: Disconnect when done (comment out if running multiple commands)
    # Disconnect-MgGraph | Out-Null
}

#endregion
