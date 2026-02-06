# Connect using EXOv3
Connect-ExchangeOnline -UserPrincipalName your-email@domain.com

# Get connection info (EXOv3 specific)
$Connection = Get-ConnectionInformation
$Connection | Format-List

# EXOv3 uses Get-ManagementRoleAssignment with ExchangeOnlineManagement module
Get-ManagementRoleAssignment -GetEffectiveUsers | 
    Where-Object { $_.EffectiveUserName -eq (Get-ConnectionInformation).UserPrincipalName } |
    Select-Object Role, RoleAssigneeType, AssignmentMethod, CustomRecipientWriteScope |
    Sort-Object Role -Unique |
    Format-Table -AutoSize
