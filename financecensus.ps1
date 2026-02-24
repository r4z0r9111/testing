<#
.SYNOPSIS
    Retrieves all users from a specific department using Microsoft Graph.
.DESCRIPTION
    This script connects to Microsoft Graph and retrieves all users who have a specific
    department value in their profile. It handles pagination for large result sets.
.PARAMETER Department
    The department name to search for (e.g., "Sales", "Engineering", "Marketing")
.PARAMETER OutputPath
    Optional path to export results to CSV
.EXAMPLE
    .\Get-UsersByDepartment.ps1 -Department "Engineering"
.EXAMPLE
    .\Get-UsersByDepartment.ps1 -Department "Sales" -OutputPath "C:\Reports\SalesUsers.csv"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Department,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath
)

# Required Microsoft Graph permissions for reading user data
$RequiredScopes = @(
    "User.Read.All",           # Read all users' full profiles
    "Directory.Read.All"       # Read directory data (for department attribute)
)

function Connect-ToGraph {
    try {
        # Check if already connected
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if ($context) {
            Write-Host "Already connected to Microsoft Graph as $($context.Account)" -ForegroundColor Green
            
            # Check if we have required permissions
            $currentScopes = $context.Scopes
            $missingScopes = $RequiredScopes | Where-Object { $_ -notin $currentScopes }
            
            if ($missingScopes) {
                Write-Warning "Missing required permissions. Reconnecting..."
                Disconnect-MgGraph | Out-Null
                Connect-MgGraph -Scopes $RequiredScopes -NoWelcome
            }
        } else {
            Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
            Connect-MgGraph -Scopes $RequiredScopes -NoWelcome
            Write-Host "Successfully connected!" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        exit 1
    }
}

function Get-UsersByDepartment {
    param([string]$DeptName)
    
    Write-Host "`nSearching for users in department: '$DeptName'" -ForegroundColor Cyan
    
    # Filter users by department
    # Note: Department is case-sensitive in some cases, so we use tolower for case-insensitive comparison
    $filter = "department eq '$DeptName'"
    
    $users = [System.Collections.Generic.List[object]]::new()
    $pageCount = 0
    
    try {
        # Get users with pagination handling
        $response = Get-MgUser -Filter $filter -All -Property @(
            "id",
            "displayName",
            "userPrincipalName",
            "mail",
            "department",
            "jobTitle",
            "officeLocation",
            "businessPhones",
            "mobilePhone",
            "accountEnabled",
            "createdDateTime",
            "lastSignInDateTime"
        ) -ErrorAction Stop
        
        foreach ($user in $response) {
            $userInfo = [PSCustomObject]@{
                DisplayName        = $user.DisplayName
                UserPrincipalName  = $user.UserPrincipalName
                Email              = $user.Mail
                Department         = $user.Department
                JobTitle           = $user.JobTitle
                OfficeLocation     = $user.OfficeLocation
                BusinessPhone      = ($user.BusinessPhones -join "; ")
                MobilePhone        = $user.MobilePhone
                AccountEnabled     = $user.AccountEnabled
                CreatedDate        = $user.CreatedDateTime
                LastSignInDate     = $user.LastSignInDateTime
                Id                 = $user.Id
            }
            $users.Add($userInfo)
        }
        
        Write-Host "Found $($users.Count) users in department '$DeptName'" -ForegroundColor Green
        
        return $users
        
    }
    catch {
        Write-Error "Error retrieving users: $_"
        
        # Provide helpful error message for common issues
        if ($_.Exception.Message -like "*Insufficient privileges*") {
            Write-Warning "You may need to request admin consent for the required permissions."
            Write-Warning "Visit: https://portal.azure.com -> Enterprise Applications -> Microsoft Graph PowerShell -> Permissions"
        }
        return $null
    }
}

function Export-Results {
    param(
        [array]$Data,
        [string]$Path
    )
    
    try {
        $Data | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        Write-Host "`nResults exported to: $Path" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to export to CSV: $_"
    }
}

function Show-Results {
    param([array]$Data)
    
    if ($Data.Count -eq 0) {
        Write-Warning "No users found in the specified department."
        return
    }
    
    # Display summary
    Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
    Write-Host " USER SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
    
    $Data | Format-Table -Property DisplayName, UserPrincipalName, JobTitle, OfficeLocation, AccountEnabled -AutoSize
    
    # Show statistics
    $enabledCount = ($Data | Where-Object { $_.AccountEnabled -eq $true }).Count
    $disabledCount = ($Data | Where-Object { $_.AccountEnabled -eq $false }).Count
    
    Write-Host "`nStatistics:" -ForegroundColor Yellow
    Write-Host "  Total Users: $($Data.Count)"
    Write-Host "  Enabled Accounts: $enabledCount" -ForegroundColor Green
    Write-Host "  Disabled Accounts: $disabledCount" -ForegroundColor Red
    
    # Show unique job titles
    $jobTitles = $Data | Where-Object { $_.JobTitle } | Select-Object -ExpandProperty JobTitle -Unique | Sort-Object
    if ($jobTitles) {
        Write-Host "`nJob Titles in Department:" -ForegroundColor Yellow
        $jobTitles | ForEach-Object { Write-Host "  • $_" }
    }
}

# ==================== MAIN EXECUTION ====================

# Connect to Microsoft Graph
Connect-ToGraph

# Get users from specified department
$results = Get-UsersByDepartment -DeptName $Department

if ($results) {
    # Display results in console
    Show-Results -Data $results
    
    # Export if path provided
    if ($OutputPath) {
        Export-Results -Data $results -Path $OutputPath
    }
    
    # Return results for pipeline use
    return $results
}

# Disconnect (optional - comment out if you want to keep the session)
# Disconnect-MgGraph | Out-Null
