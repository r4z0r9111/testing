Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Groups
Import-Module Microsoft.Graph.Authentication

# ── Check / install required modules ──────────────────────────────────────────
$requiredModules = @(
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Groups", 
    "Microsoft.Graph.Authentication",
    "ExchangeOnlineManagement"
)

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "Installing $module..." -ForegroundColor Cyan
        Install-Module $module -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module $module -ErrorAction Stop
}

# ── Collect inputs before connecting ──────────────────────────────────────────
$sourceUPN = Read-Host "Enter source user UPN"
$targetUPN = Read-Host "Enter target user UPN"

# ── Connect ────────────────────────────────────────────────────────────────────
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All","Directory.Read.All" -NoWelcome | Out-Null

Write-Host "Connecting to Exchange Online..." -ForegroundColor Cyan
Connect-ExchangeOnline -ShowBanner:$false

# ── Resolve both users up front ────────────────────────────────────────────────
try {
    $sourceUser = Get-MgUser -UserId $sourceUPN -ErrorAction Stop
    $targetUser = Get-MgUser -UserId $targetUPN -ErrorAction Stop
} catch {
    Write-Host "Could not resolve one or both UPNs: $_" -ForegroundColor Red
    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
    Disconnect-MgGraph | Out-Null
    exit 1
}

Write-Host "Source : $($sourceUser.DisplayName) ($sourceUPN)" -ForegroundColor Green
Write-Host "Target : $($targetUser.DisplayName) ($targetUPN)" -ForegroundColor Green

# ── Fetch assignable groups from source user ───────────────────────────────────
Write-Host "`nFetching group memberships..." -ForegroundColor Cyan

$groups = Get-MgUserMemberOf -UserId $sourceUser.Id -All |
    Where-Object {
        $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' -and
        $_.AdditionalProperties.groupTypes -notcontains 'DynamicMembership'
    } |
    ForEach-Object {
        [PSCustomObject]@{
            Id          = $_.Id
            DisplayName = $_.AdditionalProperties.displayName
            MailEnabled = $_.AdditionalProperties.mailEnabled
        }
    }

Write-Host "Found $($groups.Count) eligible group(s).`n" -ForegroundColor Cyan

# ── Copy memberships to target ─────────────────────────────────────────────────
$successCount = 0
$skipCount    = 0
$failCount    = 0

$groups | ForEach-Object {
    $group = $_

    if ($group.MailEnabled) {
        # Mail-enabled: must go through Exchange
        try {
            Add-DistributionGroupMember -Identity $group.Id -Member $targetUser.UserPrincipalName `
                -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction Stop
            Write-Host "  [EXO]   Added  : $($group.DisplayName)" -ForegroundColor Green
            $successCount++
        } catch {
            if ($_.Exception.Message -match "groupMailbox|already a member|already exist") {
                Write-Host "  [EXO]   Skipped: $($group.DisplayName) (already a member or unsupported type)" -ForegroundColor Yellow
                $skipCount++
            } else {
                Write-Host "  [EXO]   Failed : $($group.DisplayName) — $($_.Exception.Message)" -ForegroundColor Red
                $failCount++
            }
        }
    } else {
        # Non-mail-enabled security group: use Graph
        try {
            New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $targetUser.Id -ErrorAction Stop
            Write-Host "  [Graph] Added  : $($group.DisplayName)" -ForegroundColor Green
            $successCount++
        } catch {
            if ($_.Exception.Message -match "already exist|One or more added object references") {
                Write-Host "  [Graph] Skipped: $($group.DisplayName) (already a member)" -ForegroundColor Yellow
                $skipCount++
            } else {
                Write-Host "  [Graph] Failed : $($group.DisplayName) — $($_.Exception.Message)" -ForegroundColor Red
                $failCount++
            }
        }
    }
}

# ── Summary ────────────────────────────────────────────────────────────────────
Write-Host "`n── Summary ──────────────────────────────────────" -ForegroundColor Cyan
Write-Host "  Added   : $successCount" -ForegroundColor Green
Write-Host "  Skipped : $skipCount"    -ForegroundColor Yellow
Write-Host "  Failed  : $failCount"    -ForegroundColor Red
Write-Host "─────────────────────────────────────────────────`n" -ForegroundColor Cyan

# ── Disconnect ─────────────────────────────────────────────────────────────────
Disconnect-ExchangeOnline -Confirm:$false | Out-Null
Disconnect-MgGraph | Out-Null
