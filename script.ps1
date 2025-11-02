<#
StagingBlue / MS17-010 Victim Prep
Windows 7 x64 / PowerShell 2.0

What this does (for lab use only):
 - Confirms we're on a Windows 7 64-bit box running PowerShell 2.0, and that we are Admin.
   If not Admin, it UAC re-launches itself with ExecutionPolicy bypass so it can continue.

 - Makes the machine easier to hit with MS17-010 style exploits in an isolated lab.
   It does that by:
     1. Making sure TCP 445 (SMB) is open both inbound and outbound on all firewall profiles.
        We create/ensure two rules:
          "MS17 (Eternal Blue) INBOUND"
          "MS17 (Eternal Blue) OUTBOUND"

     2. Enabling ONLY the "File and Printer Sharing (Echo Request ...)" rules for ICMPv4/ICMPv6,
        both inbound and outbound. These are the built-in Windows firewall rules that control ping.
        We DO NOT touch any other File and Printer Sharing rules.
        We just make sure the Echo Request rules are enabled across Domain/Private/Public profiles
        so the target is discoverable/diagnosable in the lab.

        Specifically we operate on these four rule names:
          - "File and Printer Sharing (Echo Request - ICMPv4-In)"
          - "File and Printer Sharing (Echo Request - ICMPv4-Out)"
          - "File and Printer Sharing (Echo Request - ICMPv6-In)"
          - "File and Printer Sharing (Echo Request - ICMPv6-Out)"

        For each of those names:
          • Count how many rule instances exist on this box
            (Windows creates separate per-profile copies)
          • Count how many are Enabled vs Disabled
          • If any instance is disabled, we enable that rule name which flips them all on

     3. Updating the registry under:
        HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters\NullSessionPipes
        We make sure "samr" is listed there.
        That weakens access control to allow anonymous pipe access to SAMR. This is
        deliberate for staging the host as a soft target during exploitation testing.

        - If "samr" is already there, we do nothing.
        - If it's missing, we append it without removing what's already there.

 - At the end we print a summary of what happened and offer to reboot.
   Reboot is recommended so all services pick up the new state.

This script is NOT for production, NOT for internet-connected systems, NOT for use
on machines you don't fully control. This is purely for controlled lab ranges.
If you're running this anywhere else, you're doing it wrong.
#>

Write-Host "======================================================="
Write-Host "   StagingBlue :: MS17-010 Victim Prep (Win7 x64 / PS2)"
Write-Host "======================================================="
Write-Host ""

#########################################################
# Step 0: Check PowerShell version
# We expect Windows 7 default which is PowerShell 2.x.
# If it's not PS2, we bail, because later syntax and assumptions are PS2-safe.
#########################################################

$psMajorDetected = 2
$psMinorDetected = 0
if ($PSVersionTable -and $PSVersionTable.PSVersion) {
    $psMajorDetected = $PSVersionTable.PSVersion.Major
    $psMinorDetected = $PSVersionTable.PSVersion.Minor
}
$psVersionString = $psMajorDetected.ToString() + "." + $psMinorDetected.ToString()

Write-Host ("INFO: PowerShell version detected: " + $psVersionString)

if ($psMajorDetected -ne 2) {
    Write-Host "ERROR: This tool targets PowerShell 2.0 (Windows 7 default)."
    Write-Host "ERROR: You're not on PS2, so to avoid breaking anything we stop here."
    Write-Host ""
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

Write-Host "OK: PowerShell 2.x confirmed."
Write-Host ""

#########################################################
# Step 1: Ensure we're running elevated
# We need admin because we're editing firewall rules + HKLM registry.
# If we're not admin, we re-launch ourselves with RunAs and ExecutionPolicy Bypass.
#########################################################

Write-Host "INFO: Checking Administrator privileges..."

$currentIdentity    = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal   = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
$currentUserIsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $currentUserIsAdmin) {
    Write-Host "INFO: Not running as Administrator."
    Write-Host "INFO: Re-launching self elevated via UAC (ExecutionPolicy: Bypass)..."

    $thisScriptPath = $MyInvocation.MyCommand.Path
    $elevatedArgs   = "-NoProfile -NoExit -ExecutionPolicy Bypass -File `"$thisScriptPath`""

    Start-Process powershell.exe -ArgumentList $elevatedArgs -Verb RunAs

    Write-Host ""
    Write-Host "INFO: You should see a UAC prompt. After you accept, a new elevated"
    Write-Host "INFO: PowerShell window continues the script. This non-admin window exits."
    Write-Host ""
    exit
}

Write-Host "OK: We are running with Administrator rights."
Write-Host ""

#########################################################
# Step 2: Confirm OS is Windows 7 x64
# We only stage Windows 7 64-bit victims here.
#########################################################

Write-Host "INFO: Collecting OS details..."

$osInfoObject   = Get-WmiObject -Class Win32_OperatingSystem
$osCaption      = $osInfoObject.Caption
$osVersion      = $osInfoObject.Version
$osArchitecture = $osInfoObject.OSArchitecture

Write-Host ("    OS Name:        " + $osCaption)
Write-Host ("    OS Version:     " + $osVersion)
Write-Host ("    Architecture:   " + $osArchitecture)
Write-Host ""

$hostIsWin7   = $false
$hostIs64Bit  = $false

if ($osCaption -match "Windows 7") { $hostIsWin7  = $true }
if ($osArchitecture -match "64")   { $hostIs64Bit = $true }

if (-not $hostIsWin7) {
    Write-Host "ERROR: Host is not Windows 7. StagingBlue only supports Win7 victims."
    Write-Host "ERROR: No changes were made."
    Write-Host ""
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

if (-not $hostIs64Bit) {
    Write-Host "ERROR: Host is not 64-bit Windows 7."
    Write-Host "ERROR: No changes were made."
    Write-Host ""
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

Write-Host "OK: Windows 7 64-bit confirmed."
Write-Host ""

#########################################################
# Step 3: Ask operator for confirmation
# Be loud about impact so we don't brick random laptops by accident.
#########################################################

Write-Host "This will modify the current machine for exploitation testing:"
Write-Host " - Open SMB (TCP 445) both inbound and outbound using custom rules:"
Write-Host "     MS17 (Eternal Blue) INBOUND"
Write-Host "     MS17 (Eternal Blue) OUTBOUND"
Write-Host " - Make sure ping Echo Request rules (ICMPv4 / ICMPv6, In / Out)"
Write-Host "   are enabled in Windows Firewall so the host is discoverable."
Write-Host "   Only those four built-in Echo Request rules are touched."
Write-Host " - Add 'samr' to NullSessionPipes in HKLM so anonymous pipe"
Write-Host "   access is easier for testing."
Write-Host ""
Write-Host "This weakens the box on purpose. Only run this in an isolated lab segment."
Write-Host ""

$continueAnswer = Read-Host "Type Y to continue, anything else to cancel"
if ($continueAnswer -notmatch '^[Yy]') {
    Write-Host ""
    Write-Host "CANCELLED: You chose not to continue. Nothing was changed."
    Write-Host ""
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 0
}

Write-Host ""
Write-Host "Proceeding with StagingBlue victim setup..."
Write-Host ""

#########################################################
# Step 4: Ensure SMB (TCP 445) rules exist
# We want guaranteed inbound/outbound SMB so the exploit path is reachable.
# We'll create rules if they're missing, otherwise leave them alone.
#########################################################

$inboundRuleName   = "MS17 (Eternal Blue) INBOUND"
$outboundRuleName  = "MS17 (Eternal Blue) OUTBOUND"
$stagingRuleDesc   = "Allow SMB (TCP 445) for MS17-010 style lab testing. Isolated environment only."

Write-Host "INFO: Checking inbound SMB firewall rule: $inboundRuleName"
$inboundRuleQueryResult = netsh advfirewall firewall show rule name="$inboundRuleName"
$inboundRuleExists = $true
if ($inboundRuleQueryResult -match "No rules match the specified criteria.") {
    $inboundRuleExists = $false
}

if ($inboundRuleExists) {
    Write-Host "NOTE: Inbound SMB rule already exists."
} else {
    Write-Host "ACTION: Creating inbound SMB rule (TCP 445 allow, all profiles)..."
    netsh advfirewall firewall add rule `
        name="$inboundRuleName" `
        dir=in `
        action=allow `
        protocol=TCP `
        localport=445 `
        profile=any `
        enable=yes `
        description="$stagingRuleDesc" | Out-Null
    Write-Host "OK: Inbound SMB rule created."
}

Write-Host ""
Write-Host "INFO: Checking outbound SMB firewall rule: $outboundRuleName"
$outboundRuleQueryResult = netsh advfirewall firewall show rule name="$outboundRuleName"
$outboundRuleExists = $true
if ($outboundRuleQueryResult -match "No rules match the specified criteria.") {
    $outboundRuleExists = $false
}

if ($outboundRuleExists) {
    Write-Host "NOTE: Outbound SMB rule already exists."
} else {
    Write-Host "ACTION: Creating outbound SMB rule (TCP 445 allow, all profiles)..."
    netsh advfirewall firewall add rule `
        name="$outboundRuleName" `
        dir=out `
        action=allow `
        protocol=TCP `
        localport=445 `
        profile=any `
        enable=yes `
        description="$stagingRuleDesc" | Out-Null
    Write-Host "OK: Outbound SMB rule created."
}

Write-Host ""

#########################################################
# Step 5: Enable ping Echo Request rules for IPv4/IPv6, In/Out
#
# Windows creates multiple copies of these rules (Domain / Private / Public
# profiles). We don't create new firewall rules here. We only locate the four
# rule names below, count how many copies exist, count enabled/disabled,
# and if any are disabled we enable that rule name via netsh.
#
# This only touches Echo Request rules. We do NOT touch other File and Printer
# Sharing rules (like actual file sharing). We just want ping to work both ways.
#########################################################

Write-Host "INFO: Auditing and enabling Echo Request rules (ICMPv4 & ICMPv6, inbound & outbound)..."
Write-Host "INFO: Only these four built-in rule names are touched. Nothing else."
Write-Host ""

$echoTargetRuleNames = @(
    "File and Printer Sharing (Echo Request - ICMPv4-In)",
    "File and Printer Sharing (Echo Request - ICMPv4-Out)",
    "File and Printer Sharing (Echo Request - ICMPv6-In)",
    "File and Printer Sharing (Echo Request - ICMPv6-Out)"
)

# Pull the full firewall rule dump to a temp file once so we can parse locally.
$tempFirewallDumpPath = $env:TEMP + "\stagingblue_firewall_dump.txt"
if (Test-Path $tempFirewallDumpPath) { Remove-Item $tempFirewallDumpPath -Force }
netsh advfirewall firewall show rule name=all > "$tempFirewallDumpPath"
$firewallDumpLines = Get-Content "$tempFirewallDumpPath"

# We'll break that dump into rule "blocks".
# Each block will be an array of lines describing a single firewall rule instance.
# We have to be careful in PS2 so we don't accidentally flatten arrays.
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
        # This is the start of a new rule block.
        # If we were already collecting a previous block, push it first.
        if ($currentRuleBlockValid -eq $true) {
            $ruleBlocks += ,@($currentRuleBlock)
        }

        # Start a new block with this line.
        $currentRuleBlock      = @()
        $currentRuleBlock     += $lineTrimmed
        $currentRuleBlockValid = $true
    } else {
        if ($currentRuleBlockValid -eq $true) {
            $currentRuleBlock += $lineTrimmed
        }
    }
}

# Flush last collected block.
if ($currentRuleBlockValid -eq $true) {
    $ruleBlocks += ,@($currentRuleBlock)
}

# We’ll build a report for each of the 4 rule names:
#   - how many instances exist
#   - how many are enabled
#   - how many are disabled
$echoRuleReport = @()

foreach ($targetRuleName in $echoTargetRuleNames) {

    $totalInstancesForName    = 0
    $enabledInstancesForName  = 0
    $disabledInstancesForName = 0

    foreach ($block in $ruleBlocks) {

        # First line in block should be "Rule Name: <actual name>"
        $firstLineOfBlock = $block[0]
        $partsSplit       = $firstLineOfBlock.Split(":", 2)
        if ($partsSplit.Length -lt 2) { continue }

        $thisBlockRuleName = $partsSplit[1].Trim()

        if ($thisBlockRuleName -eq $targetRuleName) {

            $totalInstancesForName = $totalInstancesForName + 1

            # Default assume disabled unless we read "Enabled: Yes"
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

    # Store the counts for summary and next step.
    $ruleStatusObject = New-Object PSObject
    $ruleStatusObject | Add-Member NoteProperty Name                  $targetRuleName
    $ruleStatusObject | Add-Member NoteProperty TotalInstances        $totalInstancesForName
    $ruleStatusObject | Add-Member NoteProperty EnabledCount          $enabledInstancesForName
    $ruleStatusObject | Add-Member NoteProperty DisabledCount         $disabledInstancesForName
    $echoRuleReport   += $ruleStatusObject

    # Live output so the operator sees what state the box was in before changes.
    if ($totalInstancesForName -eq 0) {
        Write-Host ("NOTE: " + $targetRuleName + " -> no instances found on this system.")
    } else {
        Write-Host ("NOTE: " + $targetRuleName + " -> " +
            $totalInstancesForName.ToString() + " instance(s) found. Enabled: " +
            $enabledInstancesForName.ToString() + "  Disabled: " +
            $disabledInstancesForName.ToString())
    }
}

# For each of the 4 target rule names:
#   If any instance is disabled, we run netsh "set rule ... enable=yes" ONCE for that rule name.
#   That flips all the profiles for that rule to enabled.
$echoRuleNamesWeChanged   = 0
$echoRuleNamesAlreadyGood = 0
$echoRuleNamesMissing     = 0

foreach ($ruleStatus in $echoRuleReport) {
    $ruleNameThis = $ruleStatus.Name
    $instances    = $ruleStatus.TotalInstances
    $disabledCnt  = $ruleStatus.DisabledCount

    if ($instances -eq 0) {
        # no such rule on this box
        $echoRuleNamesMissing = $echoRuleNamesMissing + 1
        continue
    }

    if ($disabledCnt -eq 0) {
        # All copies already enabled
        Write-Host ("SKIP: All instances already enabled for -> " + $ruleNameThis)
        $echoRuleNamesAlreadyGood = $echoRuleNamesAlreadyGood + 1
        continue
    }

    # Some copies were disabled. We'll enable the whole rule name.
    Write-Host ("ACTION: Enabling -> " + $ruleNameThis + " (enables all profile copies)")
    $safeDisplayName = $ruleNameThis.Replace('"', "'")
    $enableCmd       = 'netsh advfirewall firewall set rule name="' + $safeDisplayName + '" new enable=yes'
    try {
        Invoke-Expression $enableCmd
        Write-Host ("OK: Enabled -> " + $ruleNameThis)
        $echoRuleNamesWeChanged = $echoRuleNamesWeChanged + 1
    } catch {
        Write-Host ("ERROR: Failed to enable -> " + $ruleNameThis)
    }
}

# firewall dump we created is no longer needed
if (Test-Path $tempFirewallDumpPath) { Remove-Item $tempFirewallDumpPath -Force }

Write-Host ""
Write-Host "INFO: Echo Request firewall step complete."
Write-Host ""

#########################################################
# Step 6: Registry prep (NullSessionPipes -> add 'samr')
#
# The idea:
#   HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters\NullSessionPipes
# is a REG_MULTI_SZ. Adding "samr" there weakens access control so anonymous
# sessions can talk to the SAMR pipe. That helps during exploit / post-exploit
# enumeration in lab conditions.
#
# We DO NOT wipe whatever's already in there.
# We:
#   1. Read current entries (if any).
#   2. If "samr" is already present -> do nothing.
#   3. Otherwise write a new REG_MULTI_SZ that includes previous entries + "samr".
#
# We use reg.exe instead of direct .NET registry APIs here. On Win7,
# this makes sure we're hitting the correct 64-bit HKLM hive and writing
# REG_MULTI_SZ in a way regedit will show properly.
#########################################################

Write-Host "INFO: Preparing registry (NullSessionPipes -> include 'samr' if missing)..."
Write-Host "     HKLM\\SYSTEM\\CurrentControlSet\\services\\LanmanServer\\Parameters\\NullSessionPipes"
Write-Host ""

$registryLanmanPath    = "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters"
$registryValueName     = "NullSessionPipes"
$pipeWeNeed            = "samr"

$currentPipesOnSystem  = @()
$registryAlreadyHadSamr = $false
$registryWriteWorked    = $false
$registryWeAddedSamr    = $false

# Query current state
$rawRegistryQuery = cmd /c "reg query `"$registryLanmanPath`" /v $registryValueName 2>&1"

# If reg query prints "ERROR:" then the value doesn't exist yet.
$nullSessionPipesExists = $true
foreach ($regLine in $rawRegistryQuery) {
    if ($regLine -match "ERROR:") {
        $nullSessionPipesExists = $false
    }
}

if ($nullSessionPipesExists -eq $true) {
    # Parse output lines to get existing REG_MULTI_SZ data.
    # Expect something like:
    #   NullSessionPipes    REG_MULTI_SZ    samr\0whatever\0...
    foreach ($regLine in $rawRegistryQuery) {
        $lineTrim = $regLine.Trim()
        if ($lineTrim -match "^$registryValueName") {

            # Split by large gaps of spaces.
            $pieces = $lineTrim -split "\s{2,}"

            # pieces[0] = NullSessionPipes
            # pieces[1] = REG_MULTI_SZ
            # pieces[2] = data (backslash-zero separated)

            if ($pieces.Length -ge 3) {
                $dataJoined = $pieces[2]
                $currentPipesOnSystem = $dataJoined -split "\\0"
            }
        }
    }
} else {
    Write-Host "NOTE: NullSessionPipes is not defined yet (no entries)."
}

# Remove blanks, normalize
$cleanedList = @()
foreach ($entry in $currentPipesOnSystem) {
    if ($null -ne $entry -and $entry.Trim() -ne "") {
        $cleanedList += $entry.Trim()
    }
}
$currentPipesOnSystem = $cleanedList

# Show operator what's currently allowed
if ($currentPipesOnSystem.Count -eq 0) {
    Write-Host "Current NullSessionPipes entries: (none)"
} else {
    Write-Host "Current NullSessionPipes entries:"
    foreach ($pipeEntry in $currentPipesOnSystem) {
        Write-Host ("  - " + $pipeEntry)
    }
}

# Check if "samr" already in list (case-insensitive)
foreach ($pipeEntry in $currentPipesOnSystem) {
    if ($pipeEntry.ToLower() -eq $pipeWeNeed.ToLower()) {
        $registryAlreadyHadSamr = $true
    }
}

if ($registryAlreadyHadSamr) {
    Write-Host "SKIP: 'samr' already present. Registry not modified."
    $registryWriteWorked = $true
    $registryWeAddedSamr = $false
} else {
    Write-Host "ACTION: Adding 'samr' to NullSessionPipes..."

    # Build the new full list of pipes we want to persist
    $updatedPipeList = @()
    foreach ($pipeEntry in $currentPipesOnSystem) { $updatedPipeList += $pipeEntry }
    $updatedPipeList += $pipeWeNeed

    # REG_MULTI_SZ needs "\0" separation and a trailing "\0".
    $regMultiString = ""
    for ($i = 0; $i -lt $updatedPipeList.Count; $i++) {
        if ($i -gt 0) {
            $regMultiString = $regMultiString + "\0"
        }
        $regMultiString = $regMultiString + $updatedPipeList[$i]
    }
    $regMultiString = $regMultiString + "\0"

    # Write the updated REG_MULTI_SZ using reg.exe
    $regAddCommand = "reg add `"$registryLanmanPath`" /v $registryValueName /t REG_MULTI_SZ /d `"$regMultiString`" /f"
    $regAddOutput  = cmd /c $regAddCommand

    # crude success check: look for "The operation completed successfully."
    $writeLookedOK = $false
    foreach ($outLine in $regAddOutput) {
        if ($outLine -match "successfully") { $writeLookedOK = $true }
    }

    if ($writeLookedOK) {
        Write-Host "OK: 'samr' appended to NullSessionPipes."
        $registryWriteWorked = $true
        $registryWeAddedSamr = $true
    } else {
        Write-Host "ERROR: Registry write did not confirm success."
        $registryWriteWorked = $false
        $registryWeAddedSamr = $false
    }
}

Write-Host ""
Write-Host "Registry prep complete."
Write-Host ""

#########################################################
# Step 7: Final summary for operator
# We print everything we did, because you'll screenshot this
# for documentation / coursework.
#########################################################

# Build nicer readable status for SMB rules
$inboundRuleStatus  = ""
$outboundRuleStatus = ""
if ($inboundRuleExists)  { $inboundRuleStatus  = "(pre-existing)" } else { $inboundRuleStatus  = "(created now)" }
if ($outboundRuleExists) { $outboundRuleStatus = "(pre-existing)" } else { $outboundRuleStatus = "(created now)" }

Write-Host "==================== STAGINGBLUE SUMMARY ===================="
Write-Host ("PowerShell version : " + $psVersionString)
Write-Host ("OS Name            : " + $osCaption)
Write-Host ("OS Version         : " + $osVersion)
Write-Host ("Architecture       : " + $osArchitecture)
Write-Host ""
Write-Host ("SMB inbound rule   : " + $inboundRuleName  + "  " + $inboundRuleStatus)
Write-Host ("SMB outbound rule  : " + $outboundRuleName + "  " + $outboundRuleStatus)
Write-Host ""
Write-Host "Echo Request rule targets processed (4 total):"
foreach ($ruleStatus in $echoRuleReport) {
    $summaryLine  = "  - " + $ruleStatus.Name
    $summaryLine += " | Instances: " + $ruleStatus.TotalInstances.ToString()
    $summaryLine += " | Enabled: "   + $ruleStatus.EnabledCount.ToString()
    $summaryLine += " | Disabled: "  + $ruleStatus.DisabledCount.ToString()
    Write-Host $summaryLine
}
Write-Host ""
Write-Host ("Echo rule names we had to touch     : " + $echoRuleNamesWeChanged.ToString())
Write-Host ("Echo rule names already good        : " + $echoRuleNamesAlreadyGood.ToString())
Write-Host ("Echo rule names missing on this box : " + $echoRuleNamesMissing.ToString())
Write-Host ""
if ($registryWriteWorked) {
    if ($registryAlreadyHadSamr) {
        Write-Host "Registry NullSessionPipes: 'samr' was already present (no change)."
    } else {
        if ($registryWeAddedSamr) {
            Write-Host "Registry NullSessionPipes: 'samr' was added."
        } else {
            Write-Host "Registry NullSessionPipes: tried to add 'samr' but write failed."
        }
    }
} else {
    Write-Host "Registry NullSessionPipes: could not be modified."
}
Write-Host ""
Write-Host "WARNING:"
Write-Host " - SMB (TCP 445) is now allowed inbound and outbound on all profiles."
Write-Host " - Ping echo (ICMPv4 + ICMPv6, inbound + outbound) is enabled so the target is easy to find."
Write-Host " - NullSessionPipes now includes 'samr' or was confirmed to already include it."
Write-Host ""
Write-Host "This host is now staged as a soft victim for MS17-010 style testing."
Write-Host "Do not connect this VM to anything you don't fully own and control."
Write-Host "=============================================================="
Write-Host ""

#########################################################
# Step 8: Offer reboot
# Reboot is recommended because some changes (especially LanmanServer behavior)
# won't fully apply until services restart.
#########################################################

$rebootAnswer = Read-Host "Reboot now to lock in changes? (Y/N)"
if ($rebootAnswer -match '^[Yy]') {
    Write-Host "INFO: Rebooting now..."
    shutdown /r /t 0
    exit 0
}

Write-Host "INFO: Reboot skipped. Manual reboot later is recommended."
Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
exit 0
