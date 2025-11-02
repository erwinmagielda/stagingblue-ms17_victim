<#
script.ps1  —  MS17-010 Lab Environment Prep (PowerShell 2 safe)

What it does:
  1. Confirms: PowerShell 2.x, Windows 7, 64-bit
  2. Elevates to Administrator if needed (UAC)
  3. Asks user to confirm
  4. Creates / verifies inbound and outbound TCP 445 firewall rules using netsh

How to run:
  Double-click run_script.bat (same folder). That .bat forces ExecutionPolicy Bypass
  so this script can run even if scripts are normally blocked.

Scope / Warning:
  For isolated lab use only. Educational / defensive testing. The author is not
  responsible for misuse or any deployment to systems you do not own/control.
#>

Write-Host "======================================================="
Write-Host "   MS17-010 Lab Environment Prep (SMB 445 Rules)"
Write-Host "======================================================="
Write-Host ""
Write-Host "INFO: If you launched this through run_script.bat, you're doing it right."
Write-Host ""

#########################################################
# 0. PowerShell version check (must be PowerShell 2.x)
#########################################################

# Default to 2.0 in case PSVersionTable is weird/missing fields
$psMajor = 2
$psMinor = 0

if ($PSVersionTable -and $PSVersionTable.PSVersion) {
    $psMajor = $PSVersionTable.PSVersion.Major
    $psMinor = $PSVersionTable.PSVersion.Minor
}

$psVersionString = $psMajor.ToString() + "." + $psMinor.ToString()

Write-Host ("INFO: PowerShell version detected: " + $psVersionString)

if ($psMajor -ne 2) {
    Write-Host "WARNING: This tool is designed for PowerShell 2.0 on Windows 7."
    Write-Host ("WARNING: Your version is " + $psVersionString + " which may behave differently.")
    Write-Host "ERROR: Stopping for safety. Please run on Windows 7 with PowerShell 2.0."
    Write-Host ""
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

Write-Host "OK: PowerShell 2.x confirmed. Continuing."
Write-Host ""

#########################################################
# 1. Self-elevate to Administrator if needed (UAC)
#########################################################

Write-Host "INFO: Checking Administrator privileges..."

$currIdentity    = [Security.Principal.WindowsIdentity]::GetCurrent()
$currPrincipal   = New-Object Security.Principal.WindowsPrincipal($currIdentity)
$currUserIsAdmin = $currPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $currUserIsAdmin) {
    Write-Host "WARNING: Script is not running as Administrator. Requesting elevation via UAC..."
    $scriptPath = $MyInvocation.MyCommand.Path
    $argList    = "-NoProfile -NoExit -ExecutionPolicy Bypass -File `"$scriptPath`""

    Start-Process powershell.exe -ArgumentList $argList -Verb RunAs

    Write-Host ""
    Write-Host "INFO: You should see a UAC prompt. After you click Yes, an elevated PowerShell"
    Write-Host "INFO: window will continue running this script. This non-admin window will now exit."
    Write-Host ""
    exit
}

Write-Host "OK: Administrator privileges confirmed."
Write-Host ""

#########################################################
# 2. Detect Windows version and architecture
#########################################################

Write-Host "INFO: Collecting OS details..."

$osInfo         = Get-WmiObject -Class Win32_OperatingSystem
$osCaption      = $osInfo.Caption          # e.g. "Microsoft Windows 7 Ultimate"
$osVersion      = $osInfo.Version          # e.g. "6.1.7601"
$osArchitecture = $osInfo.OSArchitecture   # e.g. "64-bit" or "32-bit"

Write-Host ""
Write-Host ("    OS Name:        " + $osCaption)
Write-Host ("    OS Version:     " + $osVersion)
Write-Host ("    Architecture:   " + $osArchitecture)
Write-Host ""

$looksLikeWin7   = $false
$is64bitRequired = $false

if ($osCaption -match "Windows 7") { $looksLikeWin7 = $true }
if ($osArchitecture -match "64")   { $is64bitRequired = $true }

if (-not $looksLikeWin7) {
    Write-Host "WARNING: This host is NOT detected as Windows 7. Aborting, no changes made."
    Write-Host ""
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

if (-not $is64bitRequired) {
    Write-Host "WARNING: This host is NOT 64-bit. Aborting, no changes made."
    Write-Host ""
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

Write-Host "OK: Windows 7 64-bit confirmed."
Write-Host ""

#########################################################
# 3. Tell user what we're about to do and confirm
#########################################################

Write-Host "INFO: Next step:"
Write-Host "      We will make sure TWO firewall rules exist for TCP 445 (SMB):"
Write-Host "        1) INBOUND  allow (so the machine accepts SMB on 445)"
Write-Host "        2) OUTBOUND allow (so the machine can initiate SMB on 445)"
Write-Host ""
Write-Host "      Both rules will apply to Domain, Private and Public profiles."
Write-Host "      This is ONLY for isolated lab use. Do NOT expose this config"
Write-Host "      to untrusted networks."
Write-Host ""

$answer = Read-Host "Type Y to continue, anything else to cancel"
if ($answer -notmatch '^[Yy]') {
    Write-Host ""
    Write-Host "CANCELLED: You chose not to continue. No firewall changes were made."
    Write-Host ""
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 0
}

Write-Host ""
Write-Host "OK: Proceeding with firewall configuration..."
Write-Host ""

#########################################################
# 4. Create / verify firewall rules using netsh
#    (netsh works on Windows 7 / PS2, New-NetFirewallRule does not)
#########################################################

$ruleInName  = "MS17 (Eternal Blue) INBOUND"
$ruleOutName = "MS17 (Eternal Blue) OUTBOUND"

$ruleDesc = "Allow SMB (TCP 445) for MS17-010 lab testing. Use only in a controlled environment. Author not responsible for misuse."

# Inbound rule check
$msgInCheck = "INFO: Checking inbound rule: " + $ruleInName
Write-Host $msgInCheck

$chkIn = netsh advfirewall firewall show rule name="$ruleInName"
$inExists = $true
if ($chkIn -match "No rules match the specified criteria.") {
    $inExists = $false
}

if ($inExists) {
    Write-Host "NOTE: Inbound rule already exists. Skipping creation."
} else {
    Write-Host "INFO: Inbound rule not found. Creating inbound allow rule for TCP 445 on all profiles..."
    netsh advfirewall firewall add rule `
        name="$ruleInName" `
        dir=in `
        action=allow `
        protocol=TCP `
        localport=445 `
        profile=any `
        enable=yes `
        description="$ruleDesc" | Out-Null
    Write-Host "OK: Inbound rule created."
}

Write-Host ""

# Outbound rule check
$msgOutCheck = "INFO: Checking outbound rule: " + $ruleOutName
Write-Host $msgOutCheck

$chkOut = netsh advfirewall firewall show rule name="$ruleOutName"
$outExists = $true
if ($chkOut -match "No rules match the specified criteria.") {
    $outExists = $false
}

if ($outExists) {
    Write-Host "NOTE: Outbound rule already exists. Skipping creation."
} else {
    Write-Host "INFO: Outbound rule not found. Creating outbound allow rule for TCP 445 on all profiles..."
    netsh advfirewall firewall add rule `
        name="$ruleOutName" `
        dir=out `
        action=allow `
        protocol=TCP `
        localport=445 `
        profile=any `
        enable=yes `
        description="$ruleDesc" | Out-Null
    Write-Host "OK: Outbound rule created."
}

#########################################################
# 5. Summary / final output
#########################################################

if ($inExists)  { $inResult  = "(pre-existing)" } else { $inResult  = "(created now)" }
if ($outExists) { $outResult = "(pre-existing)" } else { $outResult = "(created now)" }

Write-Host ""
Write-Host "==================== SUMMARY ===================="
Write-Host ("  PowerShell version : " + $psVersionString)
Write-Host ("  OS Name            : " + $osCaption)
Write-Host ("  OS Version         : " + $osVersion)
Write-Host ("  Architecture       : " + $osArchitecture)
Write-Host ("  Admin rights       : YES")
Write-Host ("  Inbound rule       : " + $ruleInName  + " " + $inResult)
Write-Host ("  Outbound rule      : " + $ruleOutName + " " + $outResult)
Write-Host ""
Write-Host "WARNING: SMB (TCP 445) is now allowed IN and OUT on all profiles."
Write-Host "         Only use this inside a controlled, isolated lab network."
Write-Host "         Do NOT expose this machine to untrusted networks."
Write-Host "================================================="
Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
exit 0
