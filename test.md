# Connect to Exchange Online first
Connect-ExchangeOnline

# Check your Exchange admin roles
Get-AdminRole | Where-Object { 
    $_.RoleAssignees -match (Get-ConnectionInformation).UserPrincipalName 
} | Select-Object Name, Description, RoleAssignees
