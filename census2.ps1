param(
 [Parameter(Mandatory=$true)]$Department,
 [Parameter(Mandatory=$false)]$OutputPath = ".\$Department-Users.csv"
)

Connect-MgGraph -Scopes User.Read.All,AuditLog.Read.All,Directory.Read.All -NoWelcome | Out-Null

$users = Get-MgUser -Filter "department eq '$Department'" -All -Property mail,displayName,accountEnabled,userPrincipalName,jobTitle,country,officeLocation

if($users){
 $results = @()
 foreach($u in $users){
     $lastSignIn = Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$($u.userPrincipalName)'" -Top 1 -Property createdDateTime -ErrorAction SilentlyContinue | Select-Object -ExpandProperty createdDateTime -First 1
     
     $results += [PSCustomObject]@{
         Name = $u.displayName
         Email = $u.mail
         JobTitle = $u.jobTitle
         Office = $u.officeLocation
         Country = $u.country
         Status = if($u.accountEnabled){"Active"}else{"Disabled"}
         LastSignIn = if($lastSignIn){$lastSignIn}else{"Never"}
     }
 }
 
 $results | Sort-Object Name | Format-Table -AutoSize
 
 $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
 Write-Host "Exported to: $OutputPath" -ForegroundColor Green
} else {
 Write-Host "No users found in department: $Department"
}

Disconnect-MgGraph | Out-Null
