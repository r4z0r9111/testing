$groupName = Read-Host "Enter group name"

$group = Get-MgGroup -Filter "displayName eq '$groupName'" -Top 1

if (-not $group) {
    Write-Host "Group '$groupName' not found." -ForegroundColor Red
    exit
}

Write-Host "`nFound group: $($group.DisplayName)" -ForegroundColor Green
Write-Host "Fetching all members..." -ForegroundColor Cyan

$members = Get-MgGroupMember -GroupId $group.Id -All | ForEach-Object {
    $props = $_.AdditionalProperties
    [PSCustomObject]@{
        DisplayName = $props['displayName']
        Mail        = $props['mail']
        UserType    = $props['userType']
        JobTitle    = $props['jobTitle']
        Department  = $props['department']
    }
}

$safeGroupName = $group.DisplayName -replace '[\\/:*?"<>|]', '_'
$outputPath = ".\$safeGroupName`_members.csv"

$members | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

Write-Host "`nExported $($members.Count) members to: $outputPath" -ForegroundColor Green
