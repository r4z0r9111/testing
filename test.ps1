# Connect using EXOv3
Connect-ExchangeOnline -UserPrincipalName your-email@domain.com

# Get connection info (EXOv3 specific)
$Connection = Get-ConnectionInformation
$Connection | Format-List
