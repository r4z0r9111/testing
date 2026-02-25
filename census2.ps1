<#
.SYNOPSIS
    Search Microsoft Graph for users by department and export sign-in and account status information.

.DESCRIPTION
    This script connects to Microsoft Graph, searches for users in a specified department,
    and retrieves their last sign-in time, account status, name, email, and job title.
    Requires Microsoft.Graph.Users module and appropriate permissions.

.PARAMETER Department
    The department name to search for (supports wildcards with -Like operator).

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

.EXAMPLE
    .\Get-DepartmentUsers.ps1 -Department "HR" -UseContains -IncludeAllProperties -Verbose
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Department,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('\.csv$')]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeAllProperties,

    [Parameter(Mandatory = $false)]
    [switch]$UseContains
)

#Requires -Version 7.2
#Requires -Modules @{ ModuleName="Microsoft.Graph.Authentication"; ModuleVersion="2.25.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Users"; ModuleVersion="2.25.0" }

#region Configuration
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'Continue'
#endregion

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
            
            # Required scopes for this script (least privilege principle)
            $requiredScopes = @(
                'User.Read.All'                    # Read user profiles
                'AuditLog.Read.All'                # Read sign-in activity (requires admin consent)
                'Directory.Read.All'               # Read directory data
            )
            
            $connectParams = @{
                Scopes = $requiredScopes
                NoWelcome = $true
                ErrorAction = 'Stop'
            }

            # Use device code flow in non-interactive environments
            if ($env:CI -or $env:TF_BUILD -or -not $Host.UI.RawUI) {
                Write-Verbose "Non-interactive environment detected. Using device code flow."
                $connectParams['UseDeviceCode'] = $true
            }

            Connect-MgGraph @connectParams | Out-Null
            
            $context = Get-MgContext
            Write-Host "Connected to Microsoft Graph as: $($context.Account)" -ForegroundColor Green
            Write-Verbose "Tenant: $($context.TenantId)"
            Write-Verbose "Scopes: $($context.Scopes -join ', ')"
        } else {
            Write-Verbose "Using existing Graph connection: $($context.Account)"
        }
        
        # Validate critical permissions
        $missingScopes = @('AuditLog.Read.All') | Where-Object { $context.Scopes -notcontains $_ }
        if ($missingScopes) {
            Write-Warning "Missing critical permissions: $($missingScopes -join ', ')"
            Write-Warning "Last sign-in dates will not be available. Run: Connect-MgGraph -Scopes 'User.Read.All','AuditLog.Read.All','Directory.Read.All'"
        }

        return $context
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_" -ErrorAction Stop
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
        # Build filter query using splatting for readability
        $filterOperator = if ($UseContainsFilter) { 'contains' } else { 'eq' }
        $filter = "department $filterOperator '$DepartmentName'"
        
        Write-Debug "Using OData filter: $filter"

        # Define properties to retrieve (optimize payload)
        $selectProperties = @(
            'Id'
            'DisplayName'
            'UserPrincipalName'
            'Mail'
            'JobTitle'
            'Department'
            'AccountEnabled'
            'SignInActivity'
            'CreatedDateTime'
            'OfficeLocation'
            'City'
            'Country'
            'EmployeeType'
        )

        # Build parameter splat for Get-MgUser
        $mgUserParams = @{
            Filter = $filter
            Select = $selectProperties
            ConsistencyLevel = 'eventual'
            CountVariable = 'userCount'
            All = $true
            ErrorAction = 'Stop'
        }

        # Retrieve users with automatic pagination
        $users = Get-MgUser @mgUserParams

        Write-Host "Found $userCount users in department '$DepartmentName'" -ForegroundColor Green
        
        return $users
    }
    catch {
        # Handle specific Graph errors
        if ($_.Exception.Message -like '*Insufficient privileges*') {
            Write-Error "Authorization failed. Ensure admin consent is granted for required permissions. Original error: $_" -ErrorAction Stop
        }
        elseif ($_.Exception.Message -like '*Bad request*') {
            Write-Error "Invalid filter syntax. Try using -UseContains for partial matches. Original error: $_" -ErrorAction Stop
        }
        else {
            Write-Error "Failed to retrieve users: $_" -ErrorAction Stop
        }
    }
}

function Format-UserOutput {
    <#
    .SYNOPSIS
        Transforms raw Graph user objects into standardized output format.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [array]$Users,

        [Parameter(Mandatory = $false)]
        [switch]$ExtendedProperties
    )

    begin {
        $results = [System.Collections.Generic.List[object]]::new()
        $today = Get-Date
    }

    process {
        foreach ($user in $Users) {
            # Extract last sign-in with null safety
            $lastSignIn = $null
            $daysSinceSignIn = $null
            
            if ($user.SignInActivity?.LastSignInDateTime) {
                try {
                    $lastSignIn = [datetime]::Parse($user.SignInActivity.LastSignInDateTime)
                    $daysSinceSignIn = ($today - $lastSignIn).Days
                }
                catch {
                    Write-Verbose "Failed to parse sign-in date for $($user.UserPrincipalName): $_"
                }
            }

            # Build output object using ordered hashtable for consistent property ordering
            $output = [ordered]@{
                DisplayName       = $user.DisplayName
                Email             = $user.Mail
                UserPrincipalName = $user.UserPrincipalName
                JobTitle          = $user.JobTitle
                Department        = $user.Department
                AccountEnabled    = $user.AccountEnabled
                AccountStatus     = if ($user.AccountEnabled) { 'Active' } else { 'Disabled' }
                LastSignInDate    = if ($lastSignIn) { 
                    $lastSignIn.ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
                } else { 
                    'Never/N/A' 
                }
                DaysSinceSignIn   = $daysSinceSignIn
                LastSignInStatus  = if (-not $lastSignIn) {
                    'No sign-in recorded'
                } elseif ($daysSinceSignIn -gt 90) {
                    'Stale (>90 days)'
                } elseif ($daysSinceSignIn -gt 30) {
                    'Warning (>30 days)'
                } else {
                    'Recent'
                }
            }

            # Add extended properties if requested
            if ($ExtendedProperties) {
                $output['CreatedDate'] = if ($user.CreatedDateTime) { 
                    ([datetime]::Parse($user.CreatedDateTime)).ToString('yyyy-MM-dd')
                } else { 
                    'N/A' 
                }
                $output['Office'] = $user.OfficeLocation
                $output['City'] = $user.City
                $output['Country'] = $user.Country
                $output['EmployeeType'] = $user.EmployeeType
                $output['UserId'] = $user.Id
            }

            [void]$results.Add([pscustomobject]$output)
        }
    }

    end {
        return $results
    }
}

function Export-Results {
    <#
    .SYNOPSIS
        Exports results to CSV with error handling.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [array]$Data,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($PSCmdlet.ShouldProcess($Path, 'Export to CSV')) {
        try {
            # Ensure directory exists
            $directory = Split-Path -Parent $Path
            if ($directory -and -not (Test-Path $directory)) {
                New-Item -ItemType Directory -Path $directory -Force | Out-Null
            }

            $Data | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -Force
            Write-Host "Successfully exported $($Data.Count) records to: $Path" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to export to CSV: $_" -ErrorAction Stop
        }
    }
}

#endregion

#region Main Execution

# Handle pipeline input
if ($MyInvocation.ExpectingInput) {
    $Department = $input
}

# Validate module version (avoid known buggy v2.26)
$mgGraphModule = Get-Module Microsoft.Graph.Authentication -ListAvailable | Select-Object -First 1
if ($mgGraphModule.Version -eq [version]'2.26.0') {
    Write-Warning "Detected Microsoft Graph SDK v2.26.0 which has known critical bugs. Consider updating to v2.26.1 or later."
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

    # Process results using pipeline for memory efficiency
    $formattedResults = $rawUsers | Format-UserOutput -ExtendedProperties:$IncludeAllProperties

    # Display results
    Write-Host "`nDepartment User Report" -ForegroundColor Cyan
    Write-Host ("=" * 100) -ForegroundColor Gray
    
    $formattedResults | Format-Table -AutoSize

    # Summary statistics using Measure-Object
    $stats = $formattedResults | Measure-Object
    $disabledCount = ($formattedResults | Where-Object AccountEnabled -eq $false).Count
    $neverSignedInCount = ($formattedResults | Where-Object LastSignInDate -eq 'Never/N/A').Count
    $staleCount = ($formattedResults | Where-Object LastSignInStatus -eq 'Stale (>90 days)').Count

    Write-Host "`nSummary Statistics:" -ForegroundColor Cyan
    Write-Host "  Total Users: $($stats.Count)"
    Write-Host "  Disabled Accounts: $disabledCount" -ForegroundColor $(if ($disabledCount -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  Never Signed In: $neverSignedInCount" -ForegroundColor $(if ($neverSignedInCount -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  Stale Accounts (>90 days): $staleCount" -ForegroundColor $(if ($staleCount -gt 0) { 'Yellow' } else { 'Green' })

    # Export if requested
    if ($OutputPath) {
        Export-Results -Data $formattedResults -Path $OutputPath
    }

    # Return results for pipeline use
    return $formattedResults
}
catch {
    Write-Error "Script execution failed: $_" -ErrorAction Stop
}
finally {
    # Cleanup (optional disconnect)
    Disconnect-MgGraph | Out-Null
}

#endregion
