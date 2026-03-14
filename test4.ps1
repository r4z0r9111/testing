Get-MgGroup -Top 1 | ForEach-Object { $g=$_; Write-Host "`nGroup: $($g.DisplayName)" -ForegroundColor Green; Get-MgGroupMember -GroupId $g.Id | Select-Object -ExpandProperty AdditionalProperties | Select-Object displayName,mail }

Get-MgGroup -Top 1 | ForEach-Object {
    $g = $_
    Write-Host "`nGroup: $($g.DisplayName)" -ForegroundColor Green
    Get-MgGroupMember -GroupId $g.Id | ForEach-Object {
        $props = $_.AdditionalProperties
        [PSCustomObject]@{
            DisplayName = $props['displayName']
            Mail        = $props['mail']
        }
    }
}
