<#
File: step2-systemcheck-and-firewall.ps1
Purpose:
  1. Verify we're running on Windows 7, 64-bit.
  2. If valid, create inbound firewall rule for SMB (TCP 445) for lab use.

Warning:
    This script is intended for controlled, isolated lab environments only.
    It is provided strictly for educational and defensive testing use.
    The author is not responsible for misuse or for any action performed
    on systems or networks you do not own or have explicit permission to test.

Run:
    Open PowerShell as Administrator
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    .\step2-systemcheck-and-firewall.ps1
#>

Write-Host "=== MS17-010 Lab Prep Script (Step 2) ==="
Write-Host ""

# ----------------------------
# 1. Environment / system check
# ----------------------------

$osInfo     = Get-CimInstance -ClassName Win32_OperatingSystem
$osCaption  = $osInfo.Caption          # e.g. "Microsoft Windows 7 Ultimate"
$osVersion  = $osInfo.Version          # e.g. "6.1.7601"
$is64bitOS  = $osInfo.OSArchitecture   # e.g. "64-bit" or "32-bit"

# Basic checks
$looksLikeWin7   = $false
$is64bitRequired = $false

if ($osCaption -match "Windows 7") { $looksLikeWin7 = $true }
if ($is64bitOS -match "64")        { $is64bitRequired = $true }

Write-Host "Detected system:"
Write-Host "  OS Name:      $osCaption"
Write-Host "  OS Version:   $osVersion"
Write-Host "  Architecture: $is64bitOS"
Write-Host ""

if (-not $looksLikeWin7) {
    Write-Warning "This host is not detected as Windows 7. Aborting. No firewall rules were created."
    exit 1
}

if (-not $is64bitRequired) {
    Write-Warning "This host is not 64-bit. Aborting. No firewall rules were created."
    exit 1
}

Write-Host "Check passed: Windows 7 (any edition) on 64-bit architecture."
Write-Host ""

# ----------------------------
# 2. Create inbound TCP/445 rule
# ----------------------------

$ruleDisplayName = "MS17 (Eternal Blue)"
$ruleInternalName = "MS17_EternalBlue_In"
$ruleDescription  = "Allow inbound SMB (TCP 445) for MS17-010 style lab testing. Use only in a controlled environment. Author is not responsible for misuse."

Write-Host "Creating / verifying inbound firewall rule for TCP 445 on all profiles..."
Write-Host ""

# Check if the rule already exists by display name
$existingRule = Get-NetFirewallRule -DisplayName $ruleDisplayName -ErrorAction SilentlyContinue

if ($existingRule) {
    Write-Host "Rule '$ruleDisplayName' already exists. No new rule created."
} else {
    New-NetFirewallRule `
        -Name $ruleInternalName `
        -DisplayName $ruleDisplayName `
        -Description $ruleDescription `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort 445 `
        -Profile Domain,Private,Public `
        -Enabled True | Out-Null

    Write-Host "Created inbound firewall rule:"
    Write-Host "  Name:          $ruleInternalName"
    Write-Host "  Display Name:  $ruleDisplayName"
    Write-Host "  Port:          TCP 445"
    Write-Host "  Profiles:      Domain, Private, Public"
    Write-Host "  Status:        Enabled"
}

Write-Host ""
Write-Host "Step 2 complete."