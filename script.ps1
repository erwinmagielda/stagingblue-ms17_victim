<#
script.ps1 — MS17-010 Lab Environment Prep (PS2-safe)

What it does:
  1. Checks environment:
      - PowerShell 2.x
      - Windows 7
      - 64-bit
      - Admin (auto UAC elevate if not)
  2. Asks operator to confirm
  3. Ensures SMB rules:
      - "MS17 (Eternal Blue) INBOUND"   TCP 445 allow in
      - "MS17 (Eternal Blue) OUTBOUND"  TCP 445 allow out
  4. Enables ONLY these built-in Windows Firewall rules if they exist:
      - File and Printer Sharing (Echo Request - ICMPv4-In)
      - File and Printer Sharing (Echo Request - ICMPv4-Out)
      - File and Printer Sharing (Echo Request - ICMPv6-In)
      - File and Printer Sharing (Echo Request - ICMPv6-Out)
     That automatically flips Domain / Private / Public variants for each.
     We do NOT create new firewall rules. We do NOT touch any other rules.
  5. Prints summary and waits for keypress

Usage:
  run via run_script.bat which calls:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0script.ps1"

Warning:
  For isolated lab use only. This opens SMB and enables ping both directions.
#>

Write-Host "======================================================="
Write-Host "   MS17-010 Lab Environment Prep"
Write-Host "   (SMB 445 rules + Echo Req v4/v6 In+Out)"
Write-Host "======================================================="
Write-Host ""
Write-Host "INFO: Recommended launcher: run_script.bat (ExecutionPolicy Bypass)."
Write-Host ""

# 0. PowerShell version check (must be PS2.x)
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

Write-Host "OK: PowerShell 2.x confirmed."
Write-Host ""

# 1. Self-elevate if needed (UAC)
Write-Host "INFO: Checking Administrator privileges..."

$currIdentity    = [Security.Principal.WindowsIdentity]::GetCurrent()
$currPrincipal   = New-Object Security.Principal.WindowsPrincipal($currIdentity)
$currUserIsAdmin = $currPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $currUserIsAdmin) {
    Write-Host "WARNING: Not running as Administrator. Requesting elevation (UAC)..."
    $scriptPath = $MyInvocation.MyCommand.Path
    $argList    = "-NoProfile -NoExit -ExecutionPolicy Bypass -File `"$scriptPath`""
    Start-Process powershell.exe -ArgumentList $argList -Verb RunAs

    Write-Host ""
    Write-Host "INFO: A UAC prompt should appear. After approval, an elevated PowerShell"
    Write-Host "INFO: window will continue this script. This non-admin window will exit now."
    Write-Host ""
    exit
}

Write-Host "OK: Administrator privileges confirmed."
Write-Host ""

# 2. Confirm Windows 7 x64
Write-Host "INFO: Collecting OS details..."

$osInfo         = Get-WmiObject -Class Win32_OperatingSystem
$osCaption      = $osInfo.Caption
$osVersion      = $osInfo.Version
$osArchitecture = $osInfo.OSArchitecture

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

# 3. Confirm operator wants to proceed
Write-Host "INFO: Planned changes:"
Write-Host "  - Ensure inbound and outbound allow rules for TCP 445 (SMB)."
Write-Host "  - Enable ONLY these File and Printer Sharing Echo Request rules for ALL profiles:"
Write-Host "        File and Printer Sharing (Echo Request - ICMPv4-In)"
Write-Host "        File and Printer Sharing (Echo Request - ICMPv4-Out)"
Write-Host "        File and Printer Sharing (Echo Request - ICMPv6-In)"
Write-Host "        File and Printer Sharing (Echo Request - ICMPv6-Out)"
Write-Host ""
$answer = Read-Host "Type Y to continue, anything else to cancel"
if ($answer -notmatch '^[Yy]') {
    Write-Host ""
    Write-Host "CANCELLED: Operator aborted. No changes made."
    Write-Host ""
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 0
}

Write-Host "OK: Proceeding with requested changes..."
Write-Host ""

# 4. Ensure inbound/outbound TCP 445 rules exist and are enabled
$ruleInName  = "MS17 (Eternal Blue) INBOUND"
$ruleOutName = "MS17 (Eternal Blue) OUTBOUND"
$ruleDesc    = "Allow SMB (TCP 445) for MS17-010 lab testing. Use only in a controlled environment. Author not responsible for misuse."

# Inbound rule
$msgInboundCheck = "INFO: Checking inbound rule: " + $ruleInName
Write-Host $msgInboundCheck
$chkIn = netsh advfirewall firewall show rule name="$ruleInName"
$inExists = $true
if ($chkIn -match "No rules match the specified criteria.") {
    $inExists = $false
}

if ($inExists) {
    Write-Host "NOTE: Inbound SMB rule already exists."
} else {
    Write-Host "INFO: Creating inbound allow rule for TCP 445 on all profiles..."
    netsh advfirewall firewall add rule `
        name="$ruleInName" `
        dir=in `
        action=allow `
        protocol=TCP `
        localport=445 `
        profile=any `
        enable=yes `
        description="$ruleDesc" | Out-Null
    Write-Host "OK: Inbound SMB rule created."
}

# Outbound rule
Write-Host ""
$msgOutboundCheck = "INFO: Checking outbound rule: " + $ruleOutName
Write-Host $msgOutboundCheck
$chkOut = netsh advfirewall firewall show rule name="$ruleOutName"
$outExists = $true
if ($chkOut -match "No rules match the specified criteria.") {
    $outExists = $false
}

if ($outExists) {
    Write-Host "NOTE: Outbound SMB rule already exists."
} else {
    Write-Host "INFO: Creating outbound allow rule for TCP 445 on all profiles..."
    netsh advfirewall firewall add rule `
        name="$ruleOutName" `
        dir=out `
        action=allow `
        protocol=TCP `
        localport=445 `
        profile=any `
        enable=yes `
        description="$ruleDesc" | Out-Null
    Write-Host "OK: Outbound SMB rule created."
}

# 5. Enable ONLY the 4 Echo Request rules (ICMPv4/ICMPv6, In/Out)
Write-Host ""
Write-Host "INFO: Enabling built-in File and Printer Sharing (Echo Request) rules."
Write-Host "INFO: Target list is limited to 4 rule names (v4/v6, In/Out)."
Write-Host "INFO: This will affect Domain / Private / Public copies of those rules."
Write-Host ""

# These are the ONLY rule names we are allowed to touch.
$targetEchoRules = @(
    "File and Printer Sharing (Echo Request - ICMPv4-In)",
    "File and Printer Sharing (Echo Request - ICMPv4-Out)",
    "File and Printer Sharing (Echo Request - ICMPv6-In)",
    "File and Printer Sharing (Echo Request - ICMPv6-Out)"
)

# We'll dump firewall rules once
$tmpFile = $env:TEMP + "\netsh_rules_dump.txt"
if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force }
netsh advfirewall firewall show rule name=all > "$tmpFile"
$allLines = Get-Content "$tmpFile"

# Find which of the target names actually exist on this system
$foundEchoRuleNames = @()

foreach ($line in $allLines) {
    $trim = $line.Trim()
    if ($trim -ne "" -and ($trim.ToLower()).StartsWith("rule name")) {
        $parts = $trim.Split(":", 2)
        if ($parts.Length -ge 2) {
            $name = $parts[1].Trim()
            foreach ($wanted in $targetEchoRules) {
                if ($name -eq $wanted) {
                    if ($foundEchoRuleNames -notcontains $name) {
                        $foundEchoRuleNames += $name
                    }
                }
            }
        }
    }
}

$echoEnabledNow = 0
$echoAlreadyOK  = 0
$echoMissing    = 0

foreach ($wanted in $targetEchoRules) {

    if ($foundEchoRuleNames -notcontains $wanted) {
        Write-Host ("NOTE: Echo rule not found on this system -> " + $wanted)
        $echoMissing = $echoMissing + 1
        continue
    }

    # Show / check current enable status of ALL instances of this rule name
    $tempBlock = $env:TEMP + "\netsh_rule_block.txt"
    if (Test-Path $tempBlock) { Remove-Item $tempBlock -Force }

    netsh advfirewall firewall show rule name="$wanted" > "$tempBlock"
    $blockLines = Get-Content "$tempBlock"

    $needsEnable = $false
    foreach ($ln in $blockLines) {
        $tln = $ln.Trim()
        if ($tln -ne "" -and ($tln.ToLower()).StartsWith("enabled")) {
            $p2 = $tln.Split(":", 2)
            if ($p2.Length -ge 2) {
                $val = $p2[1].Trim().ToLower()
                if ($val -eq "no") {
                    $needsEnable = $true
                    break
                }
            }
        }
    }

    if (-not $needsEnable) {
        Write-Host ("SKIP: Echo rule already enabled -> " + $wanted)
        $echoAlreadyOK = $echoAlreadyOK + 1
    } else {
        Write-Host ("ACTION: Enabling Echo rule -> " + $wanted)
        $safeName = $wanted.Replace('"', "'")
        $cmd = 'netsh advfirewall firewall set rule name="' + $safeName + '" new enable=yes'
        try {
            iex $cmd
            Write-Host ("OK: Enabled -> " + $wanted)
            $echoEnabledNow = $echoEnabledNow + 1
        } catch {
            Write-Host ("ERROR: Failed to enable -> " + $wanted)
        }
    }

    if (Test-Path $tempBlock) { Remove-Item $tempBlock -Force }
}

# cleanup temp
if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force }
if (Test-Path ($env:TEMP + "\netsh_rule_block.txt")) { Remove-Item ($env:TEMP + "\netsh_rule_block.txt") -Force }

# 6. Final summary
if ($inExists)  { $inResult  = "(pre-existing)" } else { $inResult  = "(created now)" }
if ($outExists) { $outResult = "(pre-existing)" } else { $outResult = "(created now)" }

Write-Host ""
Write-Host "==================== SUMMARY ===================="
Write-Host ("  PowerShell version        : " + $psVersionString)
Write-Host ("  OS Name                   : " + $osCaption)
Write-Host ("  OS Version                : " + $osVersion)
Write-Host ("  Architecture              : " + $osArchitecture)
Write-Host ("  Admin rights              : YES")
Write-Host ("  SMB Inbound rule status   : " + $ruleInName  + " " + $inResult)
Write-Host ("  SMB Outbound rule status  : " + $ruleOutName + " " + $outResult)
Write-Host ("  Echo rules newly enabled  : " + $echoEnabledNow.ToString())
Write-Host ("  Echo rules already active : " + $echoAlreadyOK.ToString())
Write-Host ("  Echo rules missing        : " + $echoMissing.ToString())
Write-Host ""
Write-Host "WARNING: SMB (TCP 445) is now allowed inbound AND outbound on all profiles."
Write-Host "WARNING: ICMP Echo Request is enabled both inbound and outbound (IPv4 + IPv6)."
Write-Host "Use ONLY in a sealed, isolated lab network you control."
Write-Host "================================================="
Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
exit 0
