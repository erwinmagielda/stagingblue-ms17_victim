<#
File: step6-win7x64-firewall-elev-netsh.ps1
Purpose:
  1. Elevate to Administrator on Windows 7 / PowerShell 2
  2. Confirm OS is Windows 7, 64-bit
  3. Create inbound allow rule for TCP 445 on all profiles using netsh

Warning:
  This script is intended for isolated / controlled lab environments only.
  Educational and defensive testing use only.
  The author is not responsible for misuse or use on systems you do not own.
#>

############################
# 0. Self-elevate if needed
############################

# Build principal for current user (PS2-safe)
$currIdentity      = [Security.Principal.WindowsIdentity]::GetCurrent()
$currPrincipal     = New-Object Security.Principal.WindowsPrincipal($currIdentity)
$currUserIsAdmin   = $currPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $currUserIsAdmin) {
    Write-Host "Re-launching as Administrator with ExecutionPolicy Bypass..."

    # PowerShell 2 doesn't have $PSCommandPath, use this:
    $scriptPath = $MyInvocation.MyCommand.Path

    # Relaunch elevated and KEEP WINDOW OPEN (-NoExit) so you can see output
    $argList = "-NoProfile -NoExit -ExecutionPolicy Bypass -File `"$scriptPath`""

    Start-Process powershell.exe -ArgumentList $argList -Verb RunAs
    exit
}

Write-Host "=== MS17-010 Lab Prep Script (Step 6) ==="
Write-Host "(Running elevated as admin)"
Write-Host ""

########################################
# 1. Detect Windows 7 64-bit (PS2-safe)
########################################

$osInfo = Get-WmiObject -Class Win32_OperatingSystem

$osCaption      = $osInfo.Caption        # ex: "Microsoft Windows 7 Ultimate"
$osVersion      = $osInfo.Version        # ex: "6.1.7601"
$osArchitecture = $osInfo.OSArchitecture # ex: "64-bit" or "32-bit"

$looksLikeWin7   = $false
$is64bitRequired = $false

if ($osCaption -match "Windows 7") { $looksLikeWin7 = $true }
if ($osArchitecture -match "64")   { $is64bitRequired = $true }

Write-Host "Detected system:"
Write-Host "  OS Name:      $osCaption"
Write-Host "  OS Version:   $osVersion"
Write-Host "  Architecture: $osArchitecture"
Write-Host ""

if (-not $looksLikeWin7) {
    Write-Warning "This host is not detected as Windows 7. Aborting. No firewall rules were created."
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

if (-not $is64bitRequired) {
    Write-Warning "This host is not 64-bit. Aborting. No firewall rules were created."
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

Write-Host "Check passed: Windows 7 (any edition) on 64-bit architecture."
Write-Host ""

#######################################################
# 2. Create inbound TCP/445 firewall rule using netsh
#######################################################

# We'll use netsh advfirewall because PS2 on Win7 doesn't have New-NetFirewallRule

$ruleDisplayName = 'MS17 (Eternal Blue)'
$ruleDescription = 'Allow inbound SMB (TCP 445) for MS17-010 style lab testing. Use only in a controlled environment. Author is not responsible for misuse.'

Write-Host "Creating / verifying inbound firewall rule for TCP 445 on all profiles..."
Write-Host ""

# Check if the rule already exists via netsh
# 'netsh advfirewall firewall show rule name="blah"' prints either the rule
# or "No rules match the specified criteria."
$checkOutput = netsh advfirewall firewall show rule name="$ruleDisplayName"

$ruleExists = $true
if ($checkOutput -match "No rules match the specified criteria.") {
    $ruleExists = $false
}

if ($ruleExists) {
    Write-Host "Rule '$ruleDisplayName' already exists. No new rule created."
} else {
    # Add the inbound rule
    # dir=in action=allow protocol=TCP localport=445 profile=any enables it across Domain,Private,Public
    # enable=yes turns it on immediately
    netsh advfirewall firewall add rule `
        name="$ruleDisplayName" `
        dir=in `
        action=allow `
        protocol=TCP `
        localport=445 `
        profile=any `
        enable=yes `
        description="$ruleDescription" | Out-Null

    Write-Host "Created inbound firewall rule:"
    Write-Host "  Display Name:  $ruleDisplayName"
    Write-Host "  Port:          TCP 445"
    Write-Host "  Direction:     Inbound"
    Write-Host "  Profiles:      Domain, Private, Public"
    Write-Host "  Status:        Enabled"
}

Write-Host ""
Write-Host "Done. Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
