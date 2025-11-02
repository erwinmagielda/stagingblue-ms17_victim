<#
StagingBlue :: MS17-010 Victim Prep (Win7 x64 / PowerShell 2.0)
- Adds SMB allow rules, enables ping echo rules, appends 'samr' to NullSessionPipes
- Prints a summary and ipconfig /all
- Self-deletes when provided its own temp path as the first argument
- Colors:
    Info  = White
    OK    = Green
    Fail  = Red
    Prompt= Yellow
#>

# ---------------------------
# Small color helpers (PS2 safe)
# ---------------------------
function Write-Info([string]$text) {
    Write-Host $text -ForegroundColor White
}
function Write-Success([string]$text) {
    Write-Host $text -ForegroundColor Green
}
function Write-Failure([string]$text) {
    Write-Host $text -ForegroundColor Red
}
function Write-Prompt([string]$text) {
    Write-Host $text -ForegroundColor Yellow
}

# Accept optional self-path argument (so the script can delete itself).
$stagingBlueSelfPath = $null
if ($args.Length -ge 1) {
    $stagingBlueSelfPath = $args[0]
}

Write-Info "======================================================="
Write-Info "   StagingBlue :: MS17-010 Victim Prep (Win7 x64 / PS2)"
Write-Info "======================================================="
Write-Info ""

# ---------------------------
# Step 0: PowerShell version check
# ---------------------------
$psMajorDetected = 2
$psMinorDetected = 0
if ($PSVersionTable -and $PSVersionTable.PSVersion) {
    $psMajorDetected = $PSVersionTable.PSVersion.Major
    $psMinorDetected = $PSVersionTable.PSVersion.Minor
}
$psVersionString = $psMajorDetected.ToString() + "." + $psMinorDetected.ToString()

Write-Info ("INFO: PowerShell version detected: " + $psVersionString)

if ($psMajorDetected -ne 2) {
    Write-Failure "ERROR: This tool expects PowerShell 2.0 (Windows 7 default)."
    Write-Failure "ERROR: Different PS version detected. Aborting to avoid unsafe behavior."
    Write-Info ""
    Write-Prompt "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

    if ($stagingBlueSelfPath -ne $null -and $stagingBlueSelfPath -ne "") {
        cmd /c del "$stagingBlueSelfPath" >$null 2>&1
    }
    exit 1
}

Write-Success "OK: PowerShell 2.x confirmed."
Write-Info ""

# ---------------------------
# Step 1: Ensure we're running elevated (Admin)
# ---------------------------
Write-Info "INFO: Checking Administrator privileges..."

$currentIdentity    = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal   = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
$currentUserIsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $currentUserIsAdmin) {
    Write-Prompt "INFO: Not running as Administrator."
    Write-Prompt "INFO: Relaunching self elevated (UAC) with ExecutionPolicy Bypass..."

    $thisScriptPath = $MyInvocation.MyCommand.Path
    # Pass the script path as an argument so the elevated instance knows where it lives
    $argline = "-NoProfile -ExecutionPolicy Bypass -File `"$thisScriptPath`" `"$thisScriptPath`""

    Start-Process powershell.exe -ArgumentList $argline -Verb RunAs

    Write-Info ""
    Write-Prompt "INFO: Accept the UAC prompt. Elevated window will continue."
    Write-Prompt "INFO: This non-admin window will now exit (it will attempt to delete itself)."
    Write-Info ""

    if ($stagingBlueSelfPath -ne $null -and $stagingBlueSelfPath -ne "") {
        cmd /c del "$stagingBlueSelfPath" >$null 2>&1
    }
    exit
}

Write-Success "OK: Running as Administrator."
Write-Info ""

# ---------------------------
# Step 2: Confirm OS is Windows 7 x64
# ---------------------------
Write-Info "INFO: Collecting OS details..."

$osInfoObject   = Get-WmiObject -Class Win32_OperatingSystem
$osCaption      = $osInfoObject.Caption
$osVersion      = $osInfoObject.Version
$osArchitecture = $osInfoObject.OSArchitecture

Write-Info ("    OS Name:        " + $osCaption)
Write-Info ("    OS Version:     " + $osVersion)
Write-Info ("    Architecture:   " + $osArchitecture)
Write-Info ""

$hostIsWin7   = $false
$hostIs64Bit  = $false

if ($osCaption -match "Windows 7") { $hostIsWin7  = $true }
if ($osArchitecture -match "64")   { $hostIs64Bit = $true }

if (-not $hostIsWin7) {
    Write-Failure "ERROR: Host is not Windows 7. StagingBlue only supports Win7 targets."
    Write-Failure "ERROR: No changes were made."
    Write-Info ""
    Write-Prompt "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

    if ($stagingBlueSelfPath -ne $null -and $stagingBlueSelfPath -ne "") {
        cmd /c del "$stagingBlueSelfPath" >$null 2>&1
    }
    exit 1
}

if (-not $hostIs64Bit) {
    Write-Failure "ERROR: Host is not 64-bit Windows 7. No changes made."
    Write-Info ""
    Write-Prompt "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

    if ($stagingBlueSelfPath -ne $null -and $stagingBlueSelfPath -ne "") {
        cmd /c del "$stagingBlueSelfPath" >$null 2>&1
    }
    exit 1
}

Write-Success "OK: Windows 7 64-bit confirmed."
Write-Info ""

# ---------------------------
# Step 3: Operator confirmation
# ---------------------------
Write-Info "StagingBlue will now do the following to this VM:"
Write-Info " - Ensure SMB (TCP 445) is allowed INBOUND and OUTBOUND so exploitation paths stay reachable."
Write-Info " - Enable only the built-in Echo Request (ping) rules for IPv4 and IPv6, inbound and outbound."
Write-Info " - Add 'samr' to NullSessionPipes to weaken anonymous access to SAMR."
Write-Info ""
Write-Failure "This WILL make the machine less secure. Do not use this outside a controlled lab VLAN."
Write-Info ""

$continueAnswer = Read-Host "Type Y to continue, anything else to cancel"
if ($continueAnswer -notmatch '^[Yy]') {
    Write-Info ""
    Write-Prompt "CANCELLED: You chose not to continue. Nothing was changed."
    Write-Info ""
    Write-Prompt "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

    if ($stagingBlueSelfPath -ne $null -and $stagingBlueSelfPath -ne "") {
        cmd /c del "$stagingBlueSelfPath" >$null 2>&1
    }
    exit 0
}

Write-Info ""
Write-Info "Proceeding with StagingBlue victim setup..."
Write-Info ""

# ---------------------------
# Step 4: Ensure SMB (TCP 445) rules exist
# ---------------------------
$inboundRuleName   = "MS17 (Eternal Blue) INBOUND"
$outboundRuleName  = "MS17 (Eternal Blue) OUTBOUND"
$stagingRuleDesc   = "Allow SMB (TCP 445) for MS17-010 style lab testing. Isolated environment only."

Write-Info "INFO: Checking inbound SMB firewall rule: $inboundRuleName"
$inboundRuleQueryResult = netsh advfirewall firewall show rule name="$inboundRuleName"
$inboundRuleExists = $true
if ($inboundRuleQueryResult -match "No rules match the specified criteria.") {
    $inboundRuleExists = $false
}

if ($inboundRuleExists) {
    Write-Info "NOTE: Inbound SMB rule already exists."
} else {
    Write-Info "ACTION: Creating inbound SMB rule (TCP 445 allow, all profiles)..."
    netsh advfirewall firewall add rule `
        name="$inboundRuleName" `
        dir=in `
        action=allow `
        protocol=TCP `
        localport=445 `
        profile=any `
        enable=yes `
        description="$stagingRuleDesc" | Out-Null
    Write-Success "OK: Inbound SMB rule created."
}

Write-Info ""
Write-Info "INFO: Checking outbound SMB firewall rule: $outboundRuleName"
$outboundRuleQueryResult = netsh advfirewall firewall show rule name="$outboundRuleName"
$outboundRuleExists = $true
if ($outboundRuleQueryResult -match "No rules match the specified criteria.") {
    $outboundRuleExists = $false
}

if ($outboundRuleExists) {
    Write-Info "NOTE: Outbound SMB rule already exists."
} else {
    Write-Info "ACTION: Creating outbound SMB rule (TCP 445 allow, all profiles)..."
    netsh advfirewall firewall add rule `
        name="$outboundRuleName" `
        dir=out `
        action=allow `
        protocol=TCP `
        localport=445 `
        profile=any `
        enable=yes `
        description="$stagingRuleDesc" | Out-Null
    Write-Success "OK: Outbound SMB rule created."
}

Write-Info ""

# ---------------------------
# Step 5: Enable Echo Request rules (ICMPv4/v6 In+Out)
# ---------------------------
Write-Info "INFO: Auditing and enabling Echo Request rules (ICMPv4 & ICMPv6, inbound & outbound)..."
Write-Info "INFO: Only these four built-in names are touched. Nothing else."
Write-Info ""

$echoTargetRuleNames = @(
    "File and Printer Sharing (Echo Request - ICMPv4-In)",
    "File and Printer Sharing (Echo Request - ICMPv4-Out)",
    "File and Printer Sharing (Echo Request - ICMPv6-In)",
    "File and Printer Sharing (Echo Request - ICMPv6-Out)"
)

$tempFirewallDumpPath = $env:TEMP + "\stagingblue_firewall_dump.txt"
if (Test-Path $tempFirewallDumpPath) { Remove-Item $tempFirewallDumpPath -Force }
netsh advfirewall firewall show rule name=all > "$tempFirewallDumpPath"
$firewallDumpLines = Get-Content "$tempFirewallDumpPath"

$ruleBlocks            = @()
$currentRuleBlock      = @()
$currentRuleBlockValid = $false

foreach ($lineRaw in $firewallDumpLines) {

    $lineTrimmed = $lineRaw.Trim()
    if ($lineTrimmed -eq "") {
        continue
    }

    $lineLower = $lineTrimmed.ToLower()

    if ($lineLower.StartsWith("rule name")) {
        if ($currentRuleBlockValid -eq $true) {
            $ruleBlocks += ,@($currentRuleBlock)
        }
        $currentRuleBlock      = @()
        $currentRuleBlock     += $lineTrimmed
        $currentRuleBlockValid = $true
    } else {
        if ($currentRuleBlockValid -eq $true) {
            $currentRuleBlock += $lineTrimmed
        }
    }
}
if ($currentRuleBlockValid -eq $true) {
    $ruleBlocks += ,@($currentRuleBlock)
}

$echoRuleReport = @()

foreach ($targetRuleName in $echoTargetRuleNames) {

    $totalInstancesForName    = 0
    $enabledInstancesForName  = 0
    $disabledInstancesForName = 0

    foreach ($block in $ruleBlocks) {

        $firstLineOfBlock = $block[0]
        $partsSplit       = $firstLineOfBlock.Split(":", 2)
        if ($partsSplit.Length -lt 2) { continue }

        $thisBlockRuleName = $partsSplit[1].Trim()

        if ($thisBlockRuleName -eq $targetRuleName) {

            $totalInstancesForName = $totalInstancesForName + 1

            $thisInstanceEnabled = $false
            foreach ($blockLine in $block) {
                $blockLineLower = $blockLine.ToLower()
                if ($blockLineLower.StartsWith("enabled")) {
                    $enabledSplit = $blockLine.Split(":", 2)
                    if ($enabledSplit.Length -ge 2) {
                        $enabledValue = $enabledSplit[1].Trim().ToLower()
                        if ($enabledValue -eq "yes") {
                            $thisInstanceEnabled = $true
                        }
                    }
                    break
                }
            }

            if ($thisInstanceEnabled) {
                $enabledInstancesForName  = $enabledInstancesForName  + 1
            } else {
                $disabledInstancesForName = $disabledInstancesForName + 1
            }
        }
    }

    $ruleStatusObject = New-Object PSObject
    $ruleStatusObject | Add-Member NoteProperty Name                  $targetRuleName
    $ruleStatusObject | Add-Member NoteProperty TotalInstances        $totalInstancesForName
    $ruleStatusObject | Add-Member NoteProperty EnabledCount          $enabledInstancesForName
    $ruleStatusObject | Add-Member NoteProperty DisabledCount         $disabledInstancesForName
    $echoRuleReport   += $ruleStatusObject

    if ($totalInstancesForName -eq 0) {
        Write-Info ("NOTE: " + $targetRuleName + " -> no instances found on this system.")
    } else {
        Write-Info ("NOTE: " + $targetRuleName + " -> " +
            $totalInstancesForName.ToString() + " instance(s) found. Enabled: " +
            $enabledInstancesForName.ToString() + "  Disabled: " +
            $disabledInstancesForName.ToString())
    }
}

$echoRuleNamesWeChanged   = 0
$echoRuleNamesAlreadyGood = 0
$echoRuleNamesMissing     = 0

foreach ($ruleStatus in $echoRuleReport) {
    $thisRuleName   = $ruleStatus.Name
    $instancesFound = $ruleStatus.TotalInstances
    $disabledCount  = $ruleStatus.DisabledCount

    if ($instancesFound -eq 0) {
        $echoRuleNamesMissing = $echoRuleNamesMissing + 1
        continue
    }

    if ($disabledCount -eq 0) {
        Write-Info ("SKIP: All instances already enabled for -> " + $thisRuleName)
        $echoRuleNamesAlreadyGood = $echoRuleNamesAlreadyGood + 1
        continue
    }

    Write-Info ("ACTION: Enabling -> " + $thisRuleName + " (enables all profile copies)")
    $safeDisplayName = $thisRuleName.Replace('"', "'")
    $enableCmd       = 'netsh advfirewall firewall set rule name="' + $safeDisplayName + '" new enable=yes'
    try {
        iex $enableCmd
        Write-Success ("OK: Enabled -> " + $thisRuleName)
        $echoRuleNamesWeChanged = $echoRuleNamesWeChanged + 1
    } catch {
        Write-Failure ("ERROR: Failed to enable -> " + $thisRuleName)
    }
}

if (Test-Path $tempFirewallDumpPath) { Remove-Item $tempFirewallDumpPath -Force }

Write-Info ""
Write-Info "INFO: Echo Request firewall step complete."
Write-Info ""

# ---------------------------
# Step 6: Registry prep (NullSessionPipes -> ensure 'samr')
# ---------------------------
Write-Info "INFO: Preparing registry (NullSessionPipes -> ensure 'samr' is present)..."
Write-Info "     HKLM\\SYSTEM\\CurrentControlSet\\services\\LanmanServer\\Parameters\\NullSessionPipes"
Write-Info ""

$registryLanmanPath      = "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters"
$registryValueName       = "NullSessionPipes"
$pipeWeNeed              = "samr"

$currentPipesOnSystem    = @()
$registryAlreadyHadSamr  = $false
$registryWriteWorked     = $false
$registryWeAddedSamr     = $false

$rawRegistryQuery = cmd /c "reg query `"$registryLanmanPath`" /v $registryValueName 2>&1"

$nullSessionPipesExists = $true
foreach ($regLine in $rawRegistryQuery) {
    if ($regLine -match "ERROR:") {
        $nullSessionPipesExists = $false
    }
}

if ($nullSessionPipesExists -eq $true) {
    foreach ($regLine in $rawRegistryQuery) {
        $lineTrim = $regLine.Trim()
        if ($lineTrim -match "^$registryValueName") {
            $pieces = $lineTrim -split "\s{2,}"
            if ($pieces.Length -ge 3) {
                $dataJoined = $pieces[2]
                $currentPipesOnSystem = $dataJoined -split "\\0"
            }
        }
    }
} else {
    Write-Info "NOTE: NullSessionPipes currently not defined (no entries)."
}

$cleanList = @()
foreach ($entry in $currentPipesOnSystem) {
    if ($entry -ne $null -and $entry.Trim() -ne "") {
        $cleanList += $entry.Trim()
    }
}
$currentPipesOnSystem = $cleanList

if ($currentPipesOnSystem.Count -eq 0) {
    Write-Info "Current NullSessionPipes entries: (none)"
} else {
    Write-Info "Current NullSessionPipes entries:"
    foreach ($pipeEntry in $currentPipesOnSystem) {
        Write-Info ("  - " + $pipeEntry)
    }
}

foreach ($pipeEntry in $currentPipesOnSystem) {
    if ($pipeEntry.ToLower() -eq $pipeWeNeed.ToLower()) {
        $registryAlreadyHadSamr = $true
    }
}

if ($registryAlreadyHadSamr) {
    Write-Info "SKIP: 'samr' already present. Registry not modified."
    $registryWriteWorked = $true
    $registryWeAddedSamr = $false
} else {
    Write-Info "ACTION: Adding 'samr' to NullSessionPipes..."

    $updatedPipeList = @()
    foreach ($pipeEntry in $currentPipesOnSystem) { $updatedPipeList += $pipeEntry }
    $updatedPipeList += $pipeWeNeed

    $regMultiString = ""
    for ($i = 0; $i -lt $updatedPipeList.Count; $i++) {
        if ($i -gt 0) {
            $regMultiString = $regMultiString + "\0"
        }
        $regMultiString = $regMultiString + $updatedPipeList[$i]
    }
    $regMultiString = $regMultiString + "\0"

    $regAddCommand = "reg add `"$registryLanmanPath`" /v $registryValueName /t REG_MULTI_SZ /d `"$regMultiString`" /f"
    $regAddOutput  = cmd /c $regAddCommand

    $writeLookedOK = $false
    foreach ($outLine in $regAddOutput) {
        if ($outLine -match "successfully") { $writeLookedOK = $true }
    }

    if ($writeLookedOK) {
        Write-Success "OK: 'samr' appended to NullSessionPipes."
        $registryWriteWorked = $true
        $registryWeAddedSamr = $true
    } else {
        Write-Failure "ERROR: Registry write did not confirm success."
        $registryWriteWorked = $false
        $registryWeAddedSamr = $false
    }
}

Write-Info ""
Write-Info "Registry prep complete."
Write-Info ""

# ---------------------------
# Step 7: Final summary + IP info
# ---------------------------
$inboundRuleStatus  = ""
$outboundRuleStatus = ""
if ($inboundRuleExists)  { $inboundRuleStatus  = "(pre-existing)" } else { $inboundRuleStatus  = "(created now)" }
if ($outboundRuleExists) { $outboundRuleStatus = "(pre-existing)" } else { $outboundRuleStatus = "(created now)" }

Write-Info "==================== STAGINGBLUE SUMMARY ===================="
Write-Info ("PowerShell version : " + $psVersionString)
Write-Info ("OS Name            : " + $osCaption)
Write-Info ("OS Version         : " + $osVersion)
Write-Info ("Architecture       : " + $osArchitecture)
Write-Info ""
Write-Info ("SMB inbound rule   : " + $inboundRuleName  + "  " + $inboundRuleStatus)
Write-Info ("SMB outbound rule  : " + $outboundRuleName + "  " + $outboundRuleStatus)
Write-Info ""
Write-Info "Echo Request rule targets processed (4 total):"
foreach ($ruleStatus in $echoRuleReport) {
    $summaryLine  = "  - " + $ruleStatus.Name
    $summaryLine += " | Instances: " + $ruleStatus.TotalInstances.ToString()
    $summaryLine += " | Enabled: "   + $ruleStatus.EnabledCount.ToString()
    $summaryLine += " | Disabled: "  + $ruleStatus.DisabledCount.ToString()
    Write-Info $summaryLine
}
Write-Info ""
Write-Info ("Echo rule names we had to touch     : " + $echoRuleNamesWeChanged.ToString())
Write-Info ("Echo rule names already good        : " + $echoRuleNamesAlreadyGood.ToString())
Write-Info ("Echo rule names missing on this box : " + $echoRuleNamesMissing.ToString())
Write-Info ""
if ($registryWriteWorked) {
    if ($registryAlreadyHadSamr) {
        Write-Info "Registry NullSessionPipes: 'samr' was already present (no change)."
    } else {
        if ($registryWeAddedSamr) {
            Write-Success "Registry NullSessionPipes: 'samr' was added."
        } else {
            Write-Failure "Registry NullSessionPipes: tried to add 'samr' but write failed."
        }
    }
} else {
    Write-Failure "Registry NullSessionPipes: could not be modified."
}
Write-Info ""
Write-Info "WARNING:"
Write-Failure " - SMB (TCP 445) is now allowed inbound and outbound on all profiles."
Write-Info " - Ping echo (ICMPv4 + ICMPv6, inbound + outbound) is enabled so the victim is easier to find."
Write-Info " - NullSessionPipes now includes 'samr' (or already had it)."
Write-Info ""
Write-Info "This host is now staged as a soft victim for MS17-010 style exploitation."
Write-Info "Do NOT bridge this VM onto anything you don't fully control."
Write-Info "=============================================================="
Write-Info ""

Write-Info "---------- NETWORK INFO (ipconfig /all) ----------"
cmd /c ipconfig /all
Write-Info "--------------------------------------------------"
Write-Info ""

# ---------------------------
# Step 8: Reboot prompt / exit with cleanup & self-delete
# ---------------------------
$rebootAnswer = Read-Host "Reboot now to lock in changes? (Y/N)"
if ($rebootAnswer -match '^[Yy]') {
    Write-Info "INFO: Rebooting now..."

    if ($stagingBlueSelfPath -ne $null -and $stagingBlueSelfPath -ne "") {
        cmd /c del "$stagingBlueSelfPath" >$null 2>&1
    }

    shutdown /r /t 0
    exit 0
}

Write-Info ""
Write-Success "StagingBlue finished. A reboot is still recommended."
Write-Prompt "This window will now close. Press any key to exit."

$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# final cleanup - try to delete the temp ps1 before we exit
if ($stagingBlueSelfPath -ne $null -and $stagingBlueSelfPath -ne "") {
    cmd /c del "$stagingBlueSelfPath" >$null 2>&1
}

exit 0
