<#
.SYNOPSIS
    Search Microsoft Graph for users by department and export sign-in and account status information.
    
.DESCRIPTION
    This script connects to Microsoft Graph, searches for users in a specified department,
    and retrieves their last sign-in time, account status, name, email, and job title.
    Compatible with Windows PowerShell 5.1.
    
.PARAMETER Department
    The department name to search for (exact match by default).

.PARAMETER OutputPath
    Optional path to export results to CSV. If not specified, outputs to console.

.PARAMETER IncludeAllProperties
    Switch to include additional properties like created date, office location, etc.

.PARAMETER UseContains
    Switch to use 'contains' operator instead of exact match for department search.

.EXAMPLE
    .\Get-DepartmentUsers.ps1 -Department "IT"
    
.EXAMPLE
    .\Get-DepartmentUsers.ps1 -Department "Sales" -OutputPath "C:\Reports\SalesUsers.csv"
#>

[CmdletBinding(SupportsShouldProcess = $true)]
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
#Requires -Modules @{ ModuleName="Microsoft.Graph.Authentication"; ModuleVersion="2.0.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Users"; ModuleVersion="2.0.0" }

#region Functions

function Connect-MgGraphWithCheck {
    <#
    .SYNOPSIS
        Ensures connection to Microsoft Graph with required permissions.
    #>
    [CmdletBinding()]
    param()

    try {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            Write-Verbose "No existing Graph connection found. Initiating authentication..."
            
            $requiredScopes = @(
                "User.Read.All"
                "AuditLog.Read.All"
                "Directory.Read.All"
            )
            
            $connectParams = @{
                Scopes = $requiredScopes
                NoWelcome = $true
                ErrorAction = "Stop"
            }

            # Check for non-interactive environment
            if ($env:CI -or $env:TF_BUILD -or -not $Host.UI.RawUI) {
                Write-Verbose "Non-interactive environment detected. Using device code flow."
                $connectParams["UseDeviceCode"] = $true
            }

            Connect-MgGraph @connectParams | Out-Null
            
            $context = Get-MgContext
            Write-Host "Connected to Microsoft Graph as: $($context.Account)" -ForegroundColor Green
            Write-Verbose "Tenant: $($context.TenantId)"
            Write-Verbose "Scopes: $($context.Scopes -join ", ")"
        } else {
            Write-Verbose "Using existing Graph connection: $($context.Account)"
        }
        
        # Validate critical permissions
        $missingScopes = @("AuditLog.Read.All") | Where-Object { $context.Scopes -notcontains $_ }
        if ($missingScopes) {
            Write-Warning "Missing critical permissions: $($missingScopes -join ", ")"
            Write-Warning "Last sign-in dates will not be available. Run: Connect-MgGraph -Scopes 'User.Read.All','AuditLog.Read.All','Directory.Read.All'"
        }

        return $context
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        exit 1
    }
}

function Get-DepartmentUsers {
    <#
    .SYNOPSIS
        Retrieves users from specified department with pagination support.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DepartmentName,

        [Parameter(Mandatory = $false)]
        [bool]$UseContainsFilter = $false
    )

    Write-Verbose "Searching for users in department: $DepartmentName"

    try {
        # Build filter query
        $filterOperator = if ($UseContainsFilter) { "contains" } else { "eq" }
        $filter = "department $filterOperator '$DepartmentName'"
        
        Write-Debug "Using OData filter: $filter"

        # Define properties to retrieve
        $selectProperties = @(
            "Id"
            "DisplayName"
            "UserPrincipalName"
            "Mail"
            "JobTitle"
            "Department"
            "AccountEnabled"
            "SignInActivity"
            "CreatedDateTime"
            "OfficeLocation"
            "City"
            "Country"
            "EmployeeType"
        )

        # Build parameters for Get-MgUser
        $mgUserParams = @{
            Filter = $filter
            Select = ($selectProperties -join ",")
            ConsistencyLevel = "eventual"
            CountVariable = "userCount"
            All = $true
            ErrorAction = "Stop"
        }

        $users = Get-MgUser @mgUserParams

        Write-Host "Found $userCount users in department '$DepartmentName'" -ForegroundColor Green
        
        return $users
    }
    catch {
        if ($_.Exception.Message -like "*Insufficient privileges*") {
            Write-Error "Authorization failed. Ensure admin consent is granted for required permissions. Original error: $_"
        }
        elseif ($_.Exception.Message -like "*Bad request*") {
            Write-Error "Invalid filter syntax. Try using -UseContains for partial matches. Original error: $_"
        }
        else {
            Write-Error "Failed to retrieve users: $_"
        }
        exit 1
    }
}

function Format-UserOutput {
    <#
    .SYNOPSIS
        Transforms raw Graph user objects into standardized output format.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$Users,

        [Parameter(Mandatory = $false)]
        [switch]$ExtendedProperties
    )

    $results = @()
    $today = Get-Date

    foreach ($user in $Users) {
        # Extract last sign-in with null safety (PS 5.1 compatible)
        $lastSignIn = $null
        $daysSinceSignIn = $null
        
        if ($user.SignInActivity -and $user.SignInActivity.LastSignInDateTime) {
            try {
                $lastSignIn = [datetime]::Parse($user.SignInActivity.LastSignInDateTime)
                $daysSinceSignIn = ($today - $lastSignIn).Days
            }
            catch {
                Write-Verbose "Failed to parse sign-in date for $($user.UserPrincipalName): $_"
            }
        }

        # Build output object (PS 5.1 compatible ordered hashtable)
        $output = New-Object PSObject -Property @{
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
        if ($ExtendedProperties) {
            $createdDate = if ($user.CreatedDateTime) { 
                ([datetime]::Parse($user.CreatedDateTime)).ToString("yyyy-MM-dd")
            } else { 
                "N/A" 
            }
            
            $output | Add-Member -NotePropertyName CreatedDate -NotePropertyValue $createdDate
            $output | Add-Member -NotePropertyName Office -NotePropertyValue $user.OfficeLocation
            $output | Add-Member -NotePropertyName City -NotePropertyValue $user.City
            $output | Add-Member -NotePropertyName Country -NotePropertyValue $user.Country
            $output | Add-Member -NotePropertyName EmployeeType -NotePropertyValue $user.EmployeeType
            $output | Add-Member -NotePropertyName UserId -NotePropertyValue $user.Id
        }

        $results += $output
    }

    return $results
}

#endregion

#region Main Execution

# Validate output path if provided
if ($OutputPath) {
    if (-not ($OutputPath -match "\.csv$")) {
        Write-Error "OutputPath must end with .csv extension"
        exit 1
    }
}

# Connect to Graph
$graphContext = Connect-MgGraphWithCheck

# Retrieve and process users
try {
    $rawUsers = Get-DepartmentUsers -DepartmentName $Department -UseContainsFilter $UseContains
    
    if (-not $rawUsers) {
        Write-Warning "No users found in department: $Department"
        exit 0
    }

    # Process results
    $formattedResults = Format-UserOutput -Users $rawUsers -ExtendedProperties:$IncludeAllProperties

    # Display results
    Write-Host "`nDepartment User Report" -ForegroundColor Cyan
    Write-Host ("=" * 100) -ForegroundColor Gray
    
    $formattedResults | Format-Table -AutoSize

    # Summary statistics
    $totalCount = $formattedResults.Count
    $disabledCount = ($formattedResults | Where-Object { $_.AccountEnabled -eq $false }).Count
    $neverSignedInCount = ($formattedResults | Where-Object { $_.LastSignInDate -eq "Never/N/A" }).Count
    $staleCount = ($formattedResults | Where-Object { $_.LastSignInStatus -eq "Stale (>90 days)" }).Count

    Write-Host "`nSummary Statistics:" -ForegroundColor Cyan
    Write-Host "  Total Users: $totalCount"
    Write-Host "  Disabled Accounts: $disabledCount" -ForegroundColor $(if ($disabledCount -gt 0) { "Red" } else { "Green" })
    Write-Host "  Never Signed In: $neverSignedInCount" -ForegroundColor $(if ($neverSignedInCount -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Stale Accounts (>90 days): $staleCount" -ForegroundColor $(if ($staleCount -gt 0) { "Yellow" } else { "Green" })

    # Export if requested
    if ($OutputPath) {
        if ($PSCmdlet.ShouldProcess($OutputPath, "Export to CSV")) {
            try {
                $directory = Split-Path -Parent $OutputPath
                if ($directory -and -not (Test-Path $directory)) {
                    New-Item -ItemType Directory -Path $directory -Force | Out-Null
                }

                $formattedResults | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -Force
                Write-Host "Successfully exported $($formattedResults.Count) records to: $OutputPath" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to export to CSV: $_"
            }
        }
    }

    # Return results for pipeline use
    return $formattedResults
}
catch {
    Write-Error "Script execution failed: $_"
    exit 1
}

#endregion
