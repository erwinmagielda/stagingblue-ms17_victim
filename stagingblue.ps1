<#
StagingBlue 1.0 :: MS17-010 Victim Prep (Win7 x64 / PowerShell 2.0)
Author: Erwin Magielda (https://www.erwinmagielda.com)
#>

# ---------------------------
# Colour Helpers
# ---------------------------
function WriteWhite([string]$t)   { Write-Host $t -ForegroundColor White }
function WriteGood([string]$t)    { Write-Host $t -ForegroundColor Green }
function WriteBad([string]$t)     { Write-Host $t -ForegroundColor Red }
function WritePrompt([string]$t)  { Write-Host $t -ForegroundColor Yellow }
function WriteDone([string]$t)    { Write-Host $t -ForegroundColor Magenta }   
function WriteNote([string]$t)    { Write-Host $t -ForegroundColor Cyan }      

WriteWhite "======================================================"
WriteWhite " StagingBlue :: MS17-010 Victim Prep (Win7 x64 / PS2) "
WriteWhite "======================================================"
WriteWhite ""

# ---------------------------
# STEP 1: POWERSHELL CHECK
# ---------------------------
WriteWhite "Checking PowerShell version..."
$psMajorDetected = 2
$psMinorDetected = 0
if ($PSVersionTable -and $PSVersionTable.PSVersion) {
    $psMajorDetected = $PSVersionTable.PSVersion.Major
    $psMinorDetected = $PSVersionTable.PSVersion.Minor
}
$psVersionString = $psMajorDetected.ToString() + "." + $psMinorDetected.ToString()

if ($psMajorDetected -ne 2) {
    WriteBad "This tool expects PowerShell 2.0. Aborting."
    WritePrompt "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}
WriteGood "PowerShell 2.0 confirmed."
WriteDone "STEP 1 COMPLETE: POWERSHELL CHECKED"
WriteWhite ""

# ---------------------------
# STEP 2: ELEVATION CHECK
# ---------------------------
WriteWhite "Checking account privileges..."
$currentIdentity    = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal   = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
$currentUserIsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $currentUserIsAdmin) {
    WritePrompt "Not running as administrator - relaunching elevated..."
    $thisScriptPath = $MyInvocation.MyCommand.Path
    $argline = "-NoProfile -ExecutionPolicy Bypass -File `"$thisScriptPath`""
    Start-Process powershell.exe -ArgumentList $argline -Verb RunAs
    WriteNote "Accept the UAC prompt in the new window. This window will now close."
    exit
}
WriteGood "Administrator privileges confirmed."
WriteDone "STEP 2 COMPLETE: ELEVATION CHECKED"
WriteWhite ""

# ---------------------------
# STEP 3: OS CHECK
# ---------------------------
WriteWhite "Collecting operating system details..."
$osInfoObject   = Get-WmiObject -Class Win32_OperatingSystem
$osCaption      = $osInfoObject.Caption
$osVersion      = $osInfoObject.Version
$osArchitecture = $osInfoObject.OSArchitecture
WriteNote ("OS: " + $osCaption + "  |  Version: " + $osVersion + "  |  Architecture: " + $osArchitecture)

$hostIsWin7  = ($osCaption -match "Windows 7")
$hostIs64Bit = ($osArchitecture -match "64")

if (-not $hostIsWin7) {
    WriteBad "Host is not Windows 7. Aborting."
    WritePrompt "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}
if (-not $hostIs64Bit) {
    WriteBad "Host is not 64-bit. Aborting."
    WritePrompt "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}
WriteGood "Windows 7 64-bit confirmed."
WriteDone "STEP 3 COMPLETE: OS CHECKED"
WriteWhite ""

# ---------------------------
# STEP 4: OPERATOR CONFIRMATION
# ---------------------------
WriteWhite "Awaiting operator confirmation..."
WriteNote " - Enable SMB TCP/445 rules (MS17; In & Out)"
WriteNote " - Enable Echo Request rules (ICMPv4/ICMPv6; In & Out)"
WriteNote " - Append 'samr' to NullSessionPipes if missing"
WriteWhite ""
WriteBad "THIS WILL WEAKEN THE HOST | USE ONLY IN LAB ENVIRONMENTS"
WriteWhite ""
$continueAnswer = Read-Host "Proceed? [Y/N]"
if ($continueAnswer -notmatch '^[Yy]') {
    WritePrompt "Cancelled - no changes made. Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 0
}
WriteDone "STEP 4 COMPLETE: OPERATOR CONFIRMED"
WriteWhite ""

# ---------------------------
# STEP 5: ALLOW SMB
# ---------------------------
$inboundRuleName  = "MS17 (Eternal Blue) Inbound"
$outboundRuleName = "MS17 (Eternal Blue) Outbound"
$ruleDescription  = "Allow SMB (TCP 445) for MS17-010."

WriteWhite "Checking inbound SMB firewall rule..."
$inboundQuery = netsh advfirewall firewall show rule name="$inboundRuleName" 2>&1
$inboundExists = -not ($inboundQuery -match "No rules match the specified criteria.")
if ($inboundExists) {
    WriteWhite "Inbound SMB rule exists."
} else {
    WriteWhite "Creating inbound SMB rule..."
    netsh advfirewall firewall add rule name="$inboundRuleName" dir=in action=allow protocol=TCP localport=445 profile=any enable=yes description="$ruleDescription" | Out-Null
    WriteDone "Inbound SMB rule created."
}

WriteWhite "Checking outbound SMB firewall rule..."
$outboundQuery = netsh advfirewall firewall show rule name="$outboundRuleName" 2>&1
$outboundExists = -not ($outboundQuery -match "No rules match the specified criteria.")
if ($outboundExists) {
    WriteWhite "Outbound SMB rule exists."
} else {
    WriteWhite "Creating outbound SMB rule..."
    netsh advfirewall firewall add rule name="$outboundRuleName" dir=out action=allow protocol=TCP localport=445 profile=any enable=yes description="$ruleDescription" | Out-Null
    WriteDone "Outbound SMB rule created."
}
WriteDone "STEP 5 COMPLETE: SMB ALLOWED"
WriteWhite ""

# ---------------------------
# STEP 6: ALLOW ECHO
# ---------------------------
WriteWhite "Checking Echo Request rules..."

$echoTargets = @(
    @{ Name="File and Printer Sharing (Echo Request - ICMPv4-In)";  Dir="in";  Proto="icmpv4:8,any"  },
    @{ Name="File and Printer Sharing (Echo Request - ICMPv4-Out)"; Dir="out"; Proto="icmpv4:8,any"  },
    @{ Name="File and Printer Sharing (Echo Request - ICMPv6-In)";  Dir="in";  Proto="icmpv6:128,any"},
    @{ Name="File and Printer Sharing (Echo Request - ICMPv6-Out)"; Dir="out"; Proto="icmpv6:128,any"}
)

foreach ($t in $echoTargets) {
    $n = $t.Name; $d = $t.Dir; $p = $t.Proto

    $chk = netsh advfirewall firewall show rule name="$n" 2>&1
    $exists = -not ($chk -match "No rules match the specified criteria.")

    if ($exists) {
        WriteWhite ("[RULE EXISTS]:" + $n)
    } else {
        WriteWhite ("[CREATING RULE]:" + $n)
        netsh advfirewall firewall add rule name="$n" dir=$d action=allow protocol=$p profile=any enable=yes | Out-Null
        WriteDone ("[CREATED]:" + $n)
    }

    $safe = $n.Replace('"', "'")
    $cmd  = 'netsh advfirewall firewall set rule name="' + $safe + '" new enable=yes'
    try {
        iex $cmd
        WriteGood ("[ENABLED]:" + $n)
    } catch {
        WriteBad  ("[FAILED TO ENABLE]:" + $n)
    }
}
WriteDone "STEP 6 COMPLETE: ALLOWED ECHO"
WriteWhite ""

# ---------------------------
# STEP 7: MODIFY REGISTRY
# ---------------------------
WriteWhite "Checking NullSessionPipes registry value..."

$regPath = "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters"
$regName = "NullSessionPipes"
$need    = "samr"

$current = @(); $hadSamr = $false; $regOK = $false; $added = $false

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
                $current = $data -split "\\0"
            }
        }
    }
} else {
    WriteNote "No NullSessionPipes value present. Creating."
}

$clean = @()
foreach ($e in $current) { if ($e -ne $null -and $e.Trim() -ne "") { $clean += $e.Trim() } }
$current = $clean

foreach ($e in $current) { if ($e.ToLower() -eq $need.ToLower()) { $hadSamr = $true } }

if ($hadSamr) {
    WriteGood "Value already present."
    $regOK = $true
} else {
    WriteWhite "Appending 'samr' to NullSessionPipes..."
    $newList = @(); foreach ($e in $current) { $newList += $e }; $newList += $need

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
    if ($ok) { WriteGood "Value added."; WriteDone "STEP 7 COMPLETE: MODIFIED REGISTRY"; $regOK=$true; $added=$true }
    else     { WriteBad  "Registry write failed."; $regOK=$false }
}
WriteWhite ""

# ---------------------------
# STEP 8: SUMMARY REPORT
# ---------------------------
WriteWhite "==================== STAGINGBLUE SUMMARY ===================="
WriteWhite ("PS Version : " + $psVersionString)
WriteWhite ("OS Version : " + $osCaption + "  |  " + $osArchitecture)
if ($inboundExists)  { WriteWhite "SMB Inbound : exists" }  else { WriteWhite "SMB Inbound : created"  }
if ($outboundExists) { WriteWhite "SMB Outbound: exists" } else { WriteWhite "SMB Outbound: created" }

if ($regOK -and $added) { WriteWhite "Registry: 'samr' was added." }
elseif ($regOK)         { WriteWhite "Registry: 'samr' already present." }
else                    { WriteWhite "Registry: modification failed or not attempted." }

WriteWhite ""
WriteWhite "---------- NETWORK INFO ----------"

try {
    $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
} catch { $adapters = @() }

if ($adapters.Length -eq 0) {
    WriteNote "No IP-enabled adapters found."
} else {
    $hostname = $env:COMPUTERNAME
    foreach ($nic in $adapters) {
        WriteWhite ("Adapter          : " + ($nic.Description -replace "`r`n"," "))
        WriteWhite ("Host Name        : " + $hostname)

        $ipv4s = @(); $ipv6s = @()
        if ($nic.IPAddress) {
            foreach ($ip in $nic.IPAddress) {
                if ($ip -match "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$") { $ipv4s += $ip } else { $ipv6s += $ip }
            }
        }

        if ($ipv4s.Count -gt 0) { WritePrompt ("IPv4 Address(es) : " + ($ipv4s -join ", ")) } else { WriteWhite "IPv4 Address(es) : (none)" }
        if ($ipv6s.Count -gt 0) { WriteWhite  ("IPv6 Address(es) : " + ($ipv6s -join ", ")) } else { WriteWhite "IPv6 Address(es) : (none)" }

        if ($nic.MACAddress)        { WriteWhite ("Physical Address : " + $nic.MACAddress) }           else { WriteWhite "Physical Address : (none)" }
        if ($nic.IPSubnet)          { WriteWhite ("Subnet(s)        : " + ($nic.IPSubnet -join ", ")) } else { WriteWhite "Subnet(s)        : (none)" }
        if ($nic.DefaultIPGateway)  { WriteWhite ("Gateway(s)       : " + ($nic.DefaultIPGateway -join ", ")) } else { WriteWhite "Gateway(s)       : (none)" }
        if ($nic.DHCPServer)        { WriteWhite ("DHCP Server      : " + $nic.DHCPServer) }           else { WriteWhite "DHCP Server      : (none)" }
        WriteWhite "------------------------------------------------------"
    }
}
WriteWhite "------------------------------------------------------"
WriteWhite ""

# ---------------------------
# FINAL: REBOOT PROMPT
# ---------------------------
WriteGood "[OK] Staging complete."
$rebootAnswer = Read-Host "Reboot now to lock in changes? [Y/N]"
if ($rebootAnswer -match '^[Yy]') {
    WritePrompt "Rebooting now..."
    shutdown /r /t 0
    exit 0
}

WritePrompt "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
exit 0