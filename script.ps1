<#
StagingBlue 1.0 :: MS17-010 Victim Prep (Win7 x64 / PowerShell 2.0)
- Colors used instead of textual prefixes.
- Completed/major actions = MAGENTA (ALL CAPS)
- Notes = CYAN (teal)
- IPv4 highlighted in YELLOW (closest to orange available in PS2)
- Prints only requested network fields at the end
#>

# ---------------------------
# Colour Helpers
# ---------------------------
function WriteWhite([string]$t)   { Write-Host $t -ForegroundColor White }
function WriteGood([string]$t)    { Write-Host $t -ForegroundColor Green }
function WriteBad([string]$t)     { Write-Host $t -ForegroundColor Red }
function WritePrompt([string]$t)  { Write-Host $t -ForegroundColor Yellow }
function WriteDone([string]$t)    { Write-Host $t -ForegroundColor Magenta }  # "pink"
function WriteNote([string]$t)    { Write-Host $t -ForegroundColor Cyan }     # "teal"

# Accept optional self-path argument (so the script can delete itself).
$stagingBlueSelfPath = $null
if ($args.Length -ge 1) {
    $stagingBlueSelfPath = $args[0]
}

WriteWhite "======================================================"
WriteWhite " StagingBlue :: MS17-010 Victim Prep (Win7 x64 / PS2) "
WriteWhite "======================================================"
WriteWhite ""

# ---------------------------
# STEP 1: POWERSHELL CHECK
# ---------------------------
$psMajorDetected = 2
$psMinorDetected = 0
if ($PSVersionTable -and $PSVersionTable.PSVersion) {
    $psMajorDetected = $PSVersionTable.PSVersion.Major
    $psMinorDetected = $PSVersionTable.PSVersion.Minor
}
$psVersionString = $psMajorDetected.ToString() + "." + $psMinorDetected.ToString()
WriteWhite ("PowerShell version detected: " + $psVersionString)

if ($psMajorDetected -ne 2) {
    WriteBad "[ERROR]: This tool expects PowerShell 2.0. Aborting."
    WritePrompt "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    if ($stagingBlueSelfPath -ne $null -and $stagingBlueSelfPath -ne "") { cmd /c del "$stagingBlueSelfPath" >$null 2>&1 }
    exit 1
}

WriteGood "PowerShell 2.0 confirmed."
WriteDone "STEP 1 COMPLETE: POWERSHELL CHECKED"
WriteWhite ""

# ---------------------------
# STEP 2: ELEVATION CHECK
# ---------------------------
WriteWhite "Checking administrative privileges..."

$currentIdentity    = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal   = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
$currentUserIsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $currentUserIsAdmin) {
    WritePrompt "Not running as administrator - relaunching elevated..."
    $thisScriptPath = $MyInvocation.MyCommand.Path
    $argline = "-NoProfile -ExecutionPolicy Bypass -File `"$thisScriptPath`" `"$thisScriptPath`""
    Start-Process powershell.exe -ArgumentList $argline -Verb RunAs

    WriteNote "Accept the User Account Control (UAC) prompt in the new window."
    WriteNote "This window will now exit (attempting to delete itself)."
    if ($stagingBlueSelfPath -ne $null -and $stagingBlueSelfPath -ne "") { cmd /c del "$stagingBlueSelfPath" >$null 2>&1 }
    exit
}

WriteGood "Running as administrator."
WriteDone "STEP 2 COMPLETE: ELEVATION CHECKED"
WriteWhite ""

# ---------------------------
# STEP 3: OS CHECK
# ---------------------------
WriteWhite "Collecting operating system (OS) details..."
$osInfoObject   = Get-WmiObject -Class Win32_OperatingSystem
$osCaption      = $osInfoObject.Caption
$osVersion      = $osInfoObject.Version
$osArchitecture = $osInfoObject.OSArchitecture

WriteWhite ("OS: " + $osCaption + "  |  Version: " + $osVersion + "  |  Architecture: " + $osArchitecture)

$hostIsWin7  = ($osCaption -match "Windows 7")
$hostIs64Bit = ($osArchitecture -match "64")

if (-not $hostIsWin7) {
    WriteBad "[ERROR]: Host is not Windows 7. Aborting."
    WritePrompt "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    if ($stagingBlueSelfPath -ne $null -and $stagingBlueSelfPath -ne "") { cmd /c del "$stagingBlueSelfPath" >$null 2>&1 }
    exit 1
}
if (-not $hostIs64Bit) {
    WriteBad "[ERROR]: Host is not 64-bit. Aborting."
    WritePrompt "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    if ($stagingBlueSelfPath -ne $null -and $stagingBlueSelfPath -ne "") { cmd /c del "$stagingBlueSelfPath" >$null 2>&1 }
    exit 1
}

WriteGood "Windows 7 64-bit confirmed."
WriteDone "STEP 3 COMPLETE: OS CHECKED"
WriteWhite ""

# ---------------------------
# STEP 4: OPERATOR CONFIRMATION
# ---------------------------
WriteWhite "Planned actions:"
WriteNote " - Allow SMB TCP/445 (MS17; In & Out)"
WriteNote " - Enable Echo Request rules (ICMPv4/ICMPv6; In & Out)"
WriteNote " - Append 'samr' to NullSessionPipes if missing"
WriteWhite ""
WriteBad "THIS WILL WEAKEN THE HOST ☠ DO NOT RUN ON PRODUCTION OR UNTRUSTED NETWORKS"
WriteWhite ""
$continueAnswer = Read-Host "Type [Y] to continue, anything else to cancel:"
if ($continueAnswer -notmatch '^[Yy]') {
    WriteWhite ""
    WritePrompt "Cancelled - no changes made. Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    if ($stagingBlueSelfPath -ne $null -and $stagingBlueSelfPath -ne "") { cmd /c del "$stagingBlueSelfPath" >$null 2>&1 }
    exit 0
}

WriteWhite ""
WriteWhite "Proceeding..."
WriteDone "STEP 4 COMPLETE: OPERATOR CONFIRMED"
WriteWhite ""

# ---------------------------
# STEP 5: ALLOW SMB
# ---------------------------
$inboundRuleName  = "MS17 (Eternal Blue) INBOUND"
$outboundRuleName = "MS17 (Eternal Blue) OUTBOUND"
$ruleDescription  = "Allow SMB (TCP 445) for MS17-010 lab testing."

WriteWhite "Checking inbound SMB firewall rule: $inboundRuleName..."
$inboundQuery = netsh advfirewall firewall show rule name="$inboundRuleName" 2>&1
$inboundExists = -not ($inboundQuery -match "No rules match the specified criteria.")

if ($inboundExists) {
    WriteWhite "Inbound SMB rule exists."
} else {
    WriteWhite "Creating inbound SMB rule..."
    netsh advfirewall firewall add rule `
        name="$inboundRuleName" `
        dir=in `
        action=allow `
        protocol=TCP `
        localport=445 `
        profile=any `
        enable=yes `
        description="$ruleDescription" | Out-Null
    WriteDone "Inbound SMB rule created."
}

WriteWhite ""
WriteWhite "Checking outbound SMB firewall rule: $outboundRuleName..."
$outboundQuery = netsh advfirewall firewall show rule name="$outboundRuleName" 2>&1
$outboundExists = -not ($outboundQuery -match "No rules match the specified criteria.")

if ($outboundExists) {
    WriteWhite "Outbound SMB rule exists."
} else {
    WriteWhite "Creating outbound SMB rule..."
    netsh advfirewall firewall add rule `
        name="$outboundRuleName" `
        dir=out `
        action=allow `
        protocol=TCP `
        localport=445 `
        profile=any `
        enable=yes `
        description="$ruleDescription" | Out-Null
    WriteDone "Outbound SMB rule created."
}

WriteDone "STEP 5 COMPLETE: SMB ALLOWED"
WriteWhite ""

# ---------------------------
# STEP 6: ENABLE ECHO
# ---------------------------
WriteWhite "Auditing Echo Request firewall rules..."

$targetEchoNames = @(
    "File and Printer Sharing (Echo Request - ICMPv4-In)",
    "File and Printer Sharing (Echo Request - ICMPv4-Out)",
    "File and Printer Sharing (Echo Request - ICMPv6-In)",
    "File and Printer Sharing (Echo Request - ICMPv6-Out)"
)

$tempDump = $env:TEMP + "\stagingblue_fw_dump.txt"
if (Test-Path $tempDump) { Remove-Item $tempDump -Force }
netsh advfirewall firewall show rule name=all > "$tempDump"
$dumpLines = Get-Content "$tempDump"

$blocks = @(); $curr = @(); $have = $false
foreach ($L in $dumpLines) {
    $t = $L.Trim()
    if ($t -eq "") { continue }
    $low = $t.ToLower()
    if ($low.StartsWith("rule name")) {
        if ($have -eq $true) { $blocks += ,@($curr) }
        $curr = @()
        $curr += $t
        $have = $true
    } else {
        if ($have -eq $true) { $curr += $t }
    }
}
if ($have -eq $true) { $blocks += ,@($curr) }

$changedCount = 0
foreach ($target in $targetEchoNames) {
    $instances = 0; $enabled = 0; $disabled = 0
    foreach ($blk in $blocks) {
        $first = $blk[0]; $parts = $first.Split(":",2)
        if ($parts.Length -lt 2) { continue }
        $name = $parts[1].Trim()
        if ($name -eq $target) {
            $instances = $instances + 1
            $thisEnabled = $false
            foreach ($ln in $blk) {
                if ($ln.ToLower().StartsWith("enabled")) {
                    $pv = $ln.Split(":",2); if ($pv.Length -ge 2) {
                        if ($pv[1].Trim().ToLower() -eq "yes") { $thisEnabled = $true }
                    }
                    break
                }
            }
            if ($thisEnabled) { $enabled = $enabled + 1 } else { $disabled = $disabled + 1 }
        }
    }

    if ($instances -eq 0) {
        WriteWhite ("[MISSING]: " + $target)
        continue
    }

    if ($disabled -eq 0) {
        WriteWhite ("[ALREADY ENABLED]: " + $target + " (" + $instances + " instances)")
        continue
    }

    WriteWhite ("[ENABLING]: " + $target + "  -> enabling all instances with this name...")
    $safe = $target.Replace('"', "'")
    $cmd = 'netsh advfirewall firewall set rule name="' + $safe + '" new enable=yes'
    try {
        iex $cmd
        WriteGood ("[ENABLED]: " + $target)
        $changedCount = $changedCount + 1
    } catch {
        WriteBad ("[FAILED TO ENABLE]: " + $target)
    }
}

if (Test-Path $tempDump) { Remove-Item $tempDump -Force }

WriteDone "STEP 6 COMPLETE: ECHO ENABLED"
WriteWhite ""

# ---------------------------
# STEP 7: APPEND SAMR
# ---------------------------
WriteWhite "Checking NullSessionPipes registry value..."
WriteNote "HKLM\\SYSTEM\\CurrentControlSet\\services\\LanmanServer\\Parameters\\NullSessionPipes"
$regPath = "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters"
$regName = "NullSessionPipes"
$need = "samr"

$currentList = @(); $hadSamr = $false; $regOk = $false; $addedSamr = $false

$raw = cmd /c "reg query `"$regPath`" /v $regName 2>&1"
$exists = $true
foreach ($r in $raw) { if ($r -match "ERROR:") { $exists = $false } }

if ($exists) {
    foreach ($r in $raw) {
        $t = $r.Trim()
        if ($t -match "^$regName") {
            $parts = $t -split "\s{2,}"
            if ($parts.Length -ge 3) {
                $data = $parts[2]
                $currentList = $data -split "\\0"
            }
        }
    }
} else {
    WriteNote "No NullSessionPipes defined: empty list assumed."
}

$clean = @()
foreach ($e in $currentList) {
    if ($e -ne $null -and $e.Trim() -ne "") { $clean += $e.Trim() }
}
$currentList = $clean

if ($currentList.Count -gt 0) {
    WriteWhite "Current NullSessionPipes:"
    foreach ($x in $currentList) { WriteWhite (" - " + $x) }
} else {
    WriteWhite "Current NullSessionPipes: no records present."
}

foreach ($x in $currentList) { if ($x.ToLower() -eq $need.ToLower()) { $hadSamr = $true } }

if ($hadSamr) {
    WriteGood "'samr' already present. Aborting."
    $regOk = $true
} else {
    WriteWhite "Adding 'samr' to NullSessionPipes..."
    $newList = @(); foreach ($x in $currentList) { $newList += $x }; $newList += $need
    $multi = ""
    for ($i=0; $i -lt $newList.Count; $i++) {
        if ($i -gt 0) { $multi = $multi + "\0" }
        $multi = $multi + $newList[$i]
    }
    $multi = $multi + "\0"
    $cmdline = "reg add `"$regPath`" /v $regName /t REG_MULTI_SZ /d `"$multi`" /f"
    $out = cmd /c $cmdline
    $ok = $false
    foreach ($o in $out) { if ($o -match "successfully") { $ok = $true } }
    if ($ok) {
        WriteGood "'samr' appended to NullSessionPipes."
        WriteDone "STEP 7 COMPLETE: APPENDED SAMR"
        $regOk = $true; $addedSamr = $true
    } else {
        WriteBad "[ERROR]: Failed to add 'samr' to registry."
        $regOk = $false
    }
}

WriteWhite ""

# ---------------------------
# STEP 8: PRINT SUMMARY
# ---------------------------
WriteWhite "==================== STAGINGBLUE 1.0 SUMMARY ===================="
WriteWhite ("PS Version : " + $psVersionString)
WriteWhite ("OS Version : " + $osCaption + "  |  " + $osArchitecture)
if ($inboundExists) { WriteWhite ("SMB Inbound : exists") } else { WriteWhite ("SMB INBOUND : created") }
if ($outboundExists) { WriteWhite ("SMB Outbound: exists") } else { WriteWhite ("SMB OUTBOUND: created") }

if ($regOk -and $addedSamr) { WriteWhite "Registry: 'samr' was added." }
elseif ($regOk) { WriteWhite "Registry: 'samr' already present." }
else { WriteWhite "Registry: modification failed or not attempted." }

WriteWhite ""
WriteWhite "---------- NETWORK INFO ----------"

try {
    $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
} catch {
    $adapters = @()
}

if ($adapters.Length -eq 0) {
    WriteNote "No IP-enabled adapters found."
} else {
    $hostname = $env:COMPUTERNAME
    foreach ($nic in $adapters) {
        WriteWhite ("Adapter: " + ($nic.Description -replace "`r`n"," "))
        WriteWhite ("Host Name: " + $hostname)

        # separate IPv4 vs IPv6
        $ipv4s = @(); $ipv6s = @()
        if ($nic.IPAddress) {
            foreach ($ip in $nic.IPAddress) {
                if ($ip -match "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$") { $ipv4s += $ip } else { $ipv6s += $ip }
            }
        }

        if ($ipv4s.Count -gt 0) {
            # highlight IPv4 in YELLOW (closest to orange)
            WritePrompt ("IPv4 Address(es) : " + ($ipv4s -join ", "))
        } else {
            WriteWhite "IPv4 Address(es) : (none)"
        }

        if ($ipv6s.Count -gt 0) {
            WriteWhite ("IPv6 Address(es) : " + ($ipv6s -join ", "))
        } else {
            WriteWhite "IPv6 Address(es) : (none)"
        }

        if ($nic.MACAddress) { WriteWhite ("Physical Address : " + $nic.MACAddress) } else { WriteWhite "Physical address : (none)" }

        if ($nic.IPSubnet) { WriteWhite ("Subnet(s)        : " + ($nic.IPSubnet -join ", ")) } else { WriteWhite "Subnet(s)        : (none)" }

        if ($nic.DefaultIPGateway) { WriteWhite ("Gateway(s)       : " + ($nic.DefaultIPGateway -join ", ")) } else { WriteWhite "Gateway(s)       : (none)" }

        if ($nic.DHCPServer) { WriteWhite ("DHCP Server      : " + $nic.DHCPServer) } else { WriteWhite "DHCP server      : (none)" }

        WriteWhite "------------------------------------------------------"
    }
}
WriteWhite "------------------------------------------------------"
WriteWhite ""

# ---------------------------
# FINAL: Reboot prompt, cleanup & self-delete
# ---------------------------
$rebootAnswer = Read-Host "Reboot now to lock in changes? (Y/N)"
if ($rebootAnswer -match '^[Yy]') {
    WriteWhite "REBOOTING NOW..."
    if ($stagingBlueSelfPath -ne $null -and $stagingBlueSelfPath -ne "") { cmd /c del "$stagingBlueSelfPath" >$null 2>&1 }
    shutdown /r /t 0
    exit 0
}

WriteGood "STAGING COMPLETE - REBOOT RECOMMENDED"
WritePrompt "Press any key to exit (this window will close)..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# cleanup if path provided
if ($stagingBlueSelfPath -ne $null -and $stagingBlueSelfPath -ne "") {
    cmd /c del "$stagingBlueSelfPath" >$null 2>&1
}

exit 0
