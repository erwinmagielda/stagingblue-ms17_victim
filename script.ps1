<#
MS17-010 Lab Prep Script (PS2-safe, Windows 7 x64)

What this script does:
  1. Verifies environment:
     - PowerShell 2.x
     - Running as Administrator (auto-UAC elevate if not)
     - Windows 7, 64-bit
  2. Asks operator to continue
  3. Firewall:
     - Ensure inbound and outbound TCP 445 allow rules for SMB:
         "MS17 (Eternal Blue) INBOUND"
         "MS17 (Eternal Blue) OUTBOUND"
     - For each of these four rule NAMES:
         "File and Printer Sharing (Echo Request - ICMPv4-In)"
         "File and Printer Sharing (Echo Request - ICMPv4-Out)"
         "File and Printer Sharing (Echo Request - ICMPv6-In)"
         "File and Printer Sharing (Echo Request - ICMPv6-Out)"
       • Count how many instances exist (Domain / Private / Public)
       • Count enabled vs disabled
       • Enable them if any instance is disabled
  4. Registry:
     - Append "samr" to HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters\NullSessionPipes
       if it's not already present (REG_MULTI_SZ)
  5. Print summary
  6. Offer reboot

This intentionally weakens the box for lab exploitation. Do not run on anything real.
#>

Write-Host "======================================================="
Write-Host "   MS17-010 Lab Prep Tool (Windows 7 x64 / PS2)"
Write-Host "======================================================="
Write-Host ""

#########################################################
# 0. PowerShell version check
#########################################################

$psMajor = 2
$psMinor = 0
if ($PSVersionTable -and $PSVersionTable.PSVersion) {
    $psMajor = $PSVersionTable.PSVersion.Major
    $psMinor = $PSVersionTable.PSVersion.Minor
}
$psVersionString = $psMajor.ToString() + "." + $psMinor.ToString()

Write-Host ("INFO: PowerShell version detected: " + $psVersionString)

if ($psMajor -ne 2) {
    Write-Host "ERROR: This tool targets PowerShell 2.0. Aborting for safety."
    Write-Host ""
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

Write-Host "OK: PowerShell 2.x confirmed."
Write-Host ""

#########################################################
# 1. UAC / Admin elevation
#########################################################

Write-Host "INFO: Checking Administrator privileges..."

$currIdentity    = [Security.Principal.WindowsIdentity]::GetCurrent()
$currPrincipal   = New-Object Security.Principal.WindowsPrincipal($currIdentity)
$currUserIsAdmin = $currPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $currUserIsAdmin) {
    Write-Host "INFO: Script is NOT running as Administrator. Requesting elevation via UAC..."
    $scriptPath = $MyInvocation.MyCommand.Path
    $argList    = "-NoProfile -NoExit -ExecutionPolicy Bypass -File `"$scriptPath`""

    Start-Process powershell.exe -ArgumentList $argList -Verb RunAs

    Write-Host ""
    Write-Host "INFO: A UAC prompt should appear. After approval, an elevated PowerShell"
    Write-Host "INFO: window will continue running this script. This non-admin window will now exit."
    Write-Host ""
    exit
}

Write-Host "OK: Administrator privileges confirmed."
Write-Host ""

#########################################################
# 2. OS check (Windows 7 x64 only)
#########################################################

Write-Host "INFO: Collecting OS details..."

$osInfo         = Get-WmiObject -Class Win32_OperatingSystem
$osCaption      = $osInfo.Caption
$osVersion      = $osInfo.Version
$osArchitecture = $osInfo.OSArchitecture

Write-Host ("    OS Name:        " + $osCaption)
Write-Host ("    OS Version:     " + $osVersion)
Write-Host ("    Architecture:   " + $osArchitecture)
Write-Host ""

$looksLikeWin7   = $false
$is64bitRequired = $false

if ($osCaption -match "Windows 7") { $looksLikeWin7 = $true }
if ($osArchitecture -match "64")   { $is64bitRequired = $true }

if (-not $looksLikeWin7) {
    Write-Host "ERROR: Host is not Windows 7. Aborting. No changes made."
    Write-Host ""
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

if (-not $is64bitRequired) {
    Write-Host "ERROR: Host is not 64-bit. Aborting. No changes made."
    Write-Host ""
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

Write-Host "OK: Windows 7 64-bit confirmed."
Write-Host ""

#########################################################
# 3. Operator confirmation
#########################################################

Write-Host "Planned actions:"
Write-Host " - Ensure SMB 445 allow rules:"
Write-Host "     MS17 (Eternal Blue) INBOUND"
Write-Host "     MS17 (Eternal Blue) OUTBOUND"
Write-Host " - Check and (if needed) enable these 4 firewall rule names:"
Write-Host "     File and Printer Sharing (Echo Request - ICMPv4-In)"
Write-Host "     File and Printer Sharing (Echo Request - ICMPv4-Out)"
Write-Host "     File and Printer Sharing (Echo Request - ICMPv6-In)"
Write-Host "     File and Printer Sharing (Echo Request - ICMPv6-Out)"
Write-Host "   We'll report per rule name: instances, enabled count, disabled count."
Write-Host " - Add 'samr' to NullSessionPipes if missing"
Write-Host ""
Write-Host "WARNING: This intentionally weakens the machine for lab exploitation."
Write-Host ""

$answer = Read-Host "Type Y to continue, anything else to cancel"
if ($answer -notmatch '^[Yy]') {
    Write-Host ""
    Write-Host "CANCELLED: User chose not to continue. No changes made."
    Write-Host ""
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 0
}

Write-Host ""
Write-Host "OK: Proceeding..."
Write-Host ""

#########################################################
# 4. Ensure SMB inbound/outbound TCP 445 rules exist
#########################################################

$ruleInName  = "MS17 (Eternal Blue) INBOUND"
$ruleOutName = "MS17 (Eternal Blue) OUTBOUND"
$ruleDesc    = "Allow SMB (TCP 445) for MS17-010 lab testing. Use only in a controlled environment. Author not responsible for misuse."

Write-Host "INFO: Checking inbound SMB rule: " + $ruleInName
$chkIn = netsh advfirewall firewall show rule name="$ruleInName"
$inExists = $true
if ($chkIn -match "No rules match the specified criteria.") {
    $inExists = $false
}

if ($inExists) {
    Write-Host "NOTE: Inbound SMB rule already exists."
} else {
    Write-Host "ACTION: Creating inbound SMB rule (TCP 445 allow, all profiles)..."
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

Write-Host ""
Write-Host "INFO: Checking outbound SMB rule: " + $ruleOutName
$chkOut = netsh advfirewall firewall show rule name="$ruleOutName"
$outExists = $true
if ($chkOut -match "No rules match the specified criteria.") {
    $outExists = $false
}

if ($outExists) {
    Write-Host "NOTE: Outbound SMB rule already exists."
} else {
    Write-Host "ACTION: Creating outbound SMB rule (TCP 445 allow, all profiles)..."
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

Write-Host ""

#########################################################
# 5. Echo Request firewall rules (ICMPv4/v6 In/Out)
#########################################################

Write-Host "INFO: Auditing and enabling Echo Request rules (ICMPv4 & ICMPv6, In & Out)..."
Write-Host "INFO: This affects only the specific rule names below. Nothing else."
Write-Host ""

# These are the only firewall rule names we care about.
$targetEchoRules = @(
    "File and Printer Sharing (Echo Request - ICMPv4-In)",
    "File and Printer Sharing (Echo Request - ICMPv4-Out)",
    "File and Printer Sharing (Echo Request - ICMPv6-In)",
    "File and Printer Sharing (Echo Request - ICMPv6-Out)"
)

# Dump firewall rules to a temp file once
$tmpFile = $env:TEMP + "\netsh_rules_dump.txt"
if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force }
netsh advfirewall firewall show rule name=all > "$tmpFile"
$allLines = Get-Content "$tmpFile"

# Build $blocks as an array of "rule blocks".
# Each $block is itself an array of lines.
# We must be careful to append using ,$block so PowerShell 2 does not flatten it.

$blocks = @()
$currentBlock = @()
$haveCurrentBlock = $false

foreach ($rawLine in $allLines) {

    $t = $rawLine.Trim()
    if ($t -eq "") {
        continue
    }

    $lower = $t.ToLower()

    if ($lower.StartsWith("rule name")) {
        # starting a new block
        if ($haveCurrentBlock -eq $true) {
            # push the previous block
            $blocks += ,@($currentBlock)
        }
        # start a fresh block
        $currentBlock = @()
        $currentBlock += $t
        $haveCurrentBlock = $true
    } else {
        if ($haveCurrentBlock -eq $true) {
            $currentBlock += $t
        }
    }
}

# after the loop, flush the last block
if ($haveCurrentBlock -eq $true) {
    $blocks += ,@($currentBlock)
}

# We'll collect per-rule-name status so we can summarize and then act.
$echoReport = @()  # array of objects: Name / TotalInstances / EnabledCount / DisabledCount

foreach ($targetName in $targetEchoRules) {

    $totalInst      = 0
    $enabledCount   = 0
    $disabledCount  = 0

    foreach ($blk in $blocks) {

        # The first line of each block should look like:
        # "Rule Name: <actual rule name>"
        $firstLine = $blk[0]
        $parts = $firstLine.Split(":", 2)
        if ($parts.Length -lt 2) { continue }

        $ruleDisplayName = $parts[1].Trim()

        if ($ruleDisplayName -eq $targetName) {

            $totalInst = $totalInst + 1

            # default assume disabled unless we see "Enabled: Yes"
            $isEnabledHere = $false
            foreach ($ln in $blk) {
                $lnLower = $ln.ToLower()
                if ($lnLower.StartsWith("enabled")) {
                    $p2 = $ln.Split(":", 2)
                    if ($p2.Length -ge 2) {
                        $val = $p2[1].Trim().ToLower()
                        if ($val -eq "yes") {
                            $isEnabledHere = $true
                        }
                    }
                    break
                }
            }

            if ($isEnabledHere) {
                $enabledCount  = $enabledCount + 1
            } else {
                $disabledCount = $disabledCount + 1
            }
        }
    }

    # record this target's status
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name           $targetName
    $obj | Add-Member NoteProperty TotalInstances $totalInst
    $obj | Add-Member NoteProperty EnabledCount   $enabledCount
    $obj | Add-Member NoteProperty DisabledCount  $disabledCount
    $echoReport += $obj

    # tell the user what we saw for this name
    if ($totalInst -eq 0) {
        Write-Host ("NOTE: " + $targetName + " -> no instances found on this system.")
    } else {
        Write-Host ("NOTE: " + $targetName + " -> " +
            $totalInst.ToString() + " instance(s) found. Enabled: " +
            $enabledCount.ToString() + "  Disabled: " +
            $disabledCount.ToString())
    }
}

# Now actually enable where needed.
$echoEnabledNow = 0
$echoAlreadyOK  = 0
$echoMissing    = 0

foreach ($rep in $echoReport) {
    $tName         = $rep.Name
    $tTotal        = $rep.TotalInstances
    $tDisabled     = $rep.DisabledCount

    if ($tTotal -eq 0) {
        # rule name not present on this system
        $echoMissing = $echoMissing + 1
        continue
    }

    if ($tDisabled -eq 0) {
        # all instances already on
        Write-Host ("SKIP: All instances already enabled for -> " + $tName)
        $echoAlreadyOK = $echoAlreadyOK + 1
        continue
    }

    Write-Host ("ACTION: Enabling rule name -> " + $tName + " (this turns ON all profile instances with that name)")
    $safeName = $tName.Replace('"', "'")
    $cmd = 'netsh advfirewall firewall set rule name="' + $safeName + '" new enable=yes'
    try {
        iex $cmd
        Write-Host ("OK: Enabled -> " + $tName)
        $echoEnabledNow = $echoEnabledNow + 1
    } catch {
        Write-Host ("ERROR: Failed to enable -> " + $tName)
    }
}

# cleanup temp firewall dump file
if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force }

Write-Host ""
Write-Host "INFO: Firewall echo rule step complete."
Write-Host ""

#########################################################
# 6. Registry: add 'samr' into NullSessionPipes (Reporting first)
#########################################################

Write-Host "INFO: Checking registry for NullSessionPipes 'samr' entry..."
Write-Host "     HKLM\\SYSTEM\\CurrentControlSet\\services\\LanmanServer\\Parameters\\NullSessionPipes"
Write-Host ""

# We'll use reg.exe so we hit the real 64-bit hive and set proper REG_MULTI_SZ.

$regPathFull = "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters"
$regValueName = "NullSessionPipes"
$mustInclude  = "samr"

# Step 1: read current value (if any)
# reg query will exit non-zero if value doesn't exist, so we wrap in try/catch

$currentEntries = @()
$regHadSamr     = $false
$regWorked      = $false
$regAddedSamr   = $false

# query:
$rawQuery = cmd /c "reg query `"$regPathFull`" /v $regValueName 2>&1"

# $rawQuery will be array of lines. If it contains "ERROR:" then value doesn't exist.
$nullSessionExists = $true
foreach ($l in $rawQuery) {
    if ($l -match "ERROR:") {
        $nullSessionExists = $false
    }
}

if ($nullSessionExists -eq $true) {
    # Parse the reg query output to extract the data portion.
    # Typical line looks like:
    #     NullSessionPipes    REG_MULTI_SZ    samr\0whatever\0...
    #
    # We'll look for a line containing our value name and REG_MULTI_SZ
    foreach ($l in $rawQuery) {
        $triml = $l.Trim()
        if ($triml -match "^$regValueName") {
            # split on whitespace but only first 2 gaps are name/type, rest is data
            # PowerShell 2 doesn't have -split with maxcount param in older syntax,
            # so we'll do manual.
            # We'll try splitting on multiple spaces.
            $pieces = $triml -split "\s{2,}"
            # Expect: [0]=NullSessionPipes [1]=REG_MULTI_SZ [2]=data... (may include spaces joined by \0)
            if ($pieces.Length -ge 3) {
                $dataJoined = $pieces[2]
                # REG_MULTI_SZ formats entries separated by \0
                $currentEntries = $dataJoined -split "\\0"
            }
        }
    }
} else {
    Write-Host "NOTE: NullSessionPipes does not currently exist or is empty."
}

# Clean current entries (remove empty strings)
$cleaned = @()
foreach ($e in $currentEntries) {
    if ($e -ne $null -and $e.Trim() -ne "") {
        $cleaned += $e.Trim()
    }
}
$currentEntries = $cleaned

# Report what we found
if ($currentEntries.Count -eq 0) {
    Write-Host "Current NullSessionPipes entries: (none)"
} else {
    Write-Host "Current NullSessionPipes entries:"
    foreach ($c in $currentEntries) {
        Write-Host ("  - " + $c)
    }
}

# Check if samr is already present (case-insensitive)
foreach ($c in $currentEntries) {
    if ($c.ToLower() -eq $mustInclude.ToLower()) {
        $regHadSamr = $true
    }
}

if ($regHadSamr) {
    Write-Host "SKIP: 'samr' already present. Registry unchanged."
    $regWorked = $true
    $regAddedSamr = $false
} else {
    Write-Host "ACTION: Adding 'samr' to NullSessionPipes..."

    # Build new list
    $newList = @()
    foreach ($c in $currentEntries) { $newList += $c }
    $newList += $mustInclude

    # We need to feed REG_MULTI_SZ to reg add like: "val1\0val2\0val3\0"
    # We'll join with \0 and ensure trailing \0
    $multiBody = ""
    for ($i=0; $i -lt $newList.Count; $i++) {
        if ($i -gt 0) {
            $multiBody = $multiBody + "\0"
        }
        $multiBody = $multiBody + $newList[$i]
    }
    $multiBody = $multiBody + "\0"

    # Now write it
    # /f to force overwrite without interactive prompt
    $cmdline = "reg add `"$regPathFull`" /v $regValueName /t REG_MULTI_SZ /d `"$multiBody`" /f"
    $result = cmd /c $cmdline

    # naive success check: look for "The operation completed successfully."
    $writeOK = $false
    foreach ($rline in $result) {
        if ($rline -match "successfully") { $writeOK = $true }
    }

    if ($writeOK) {
        Write-Host "OK: 'samr' added to NullSessionPipes."
        $regWorked = $true
        $regAddedSamr = $true
    } else {
        Write-Host "ERROR: Registry write attempt did not confirm success."
        $regWorked = $false
        $regAddedSamr = $false
    }
}

Write-Host ""
Write-Host "INFO: Registry step complete."
Write-Host ""

#########################################################
# 7. Final summary
#########################################################

# figure out status strings for SMB rules without inline if/else in expressions
$inRuleStatus  = ""
$outRuleStatus = ""
if ($inExists)  { $inRuleStatus  = "(pre-existing)" } else { $inRuleStatus  = "(created now)" }
if ($outExists) { $outRuleStatus = "(pre-existing)" } else { $outRuleStatus = "(created now)" }

Write-Host "==================== FINAL SUMMARY ===================="
Write-Host ("PowerShell version : " + $psVersionString)
Write-Host ("OS Name            : " + $osCaption)
Write-Host ("OS Version         : " + $osVersion)
Write-Host ("Architecture       : " + $osArchitecture)
Write-Host ""
Write-Host ("SMB inbound rule   : " + $ruleInName  + "  " + $inRuleStatus)
Write-Host ("SMB outbound rule  : " + $ruleOutName + "  " + $outRuleStatus)
Write-Host ""
Write-Host "Echo Request rule targets processed (4 total):"
foreach ($rep in $echoReport) {
    $lineMsg  = "  - " + $rep.Name
    $lineMsg += " | Instances: " + $rep.TotalInstances.ToString()
    $lineMsg += " | Enabled: "   + $rep.EnabledCount.ToString()
    $lineMsg += " | Disabled: "  + $rep.DisabledCount.ToString()
    Write-Host $lineMsg
}
Write-Host ""
Write-Host ("Echo rule names where action was taken : " + $echoEnabledNow.ToString())
Write-Host ("Echo rule names already fully enabled : " + $echoAlreadyOK.ToString())
Write-Host ("Echo rule names missing on system     : " + $echoMissing.ToString())
Write-Host ""
if ($regWorked) {
    if ($regHadSamr) {
        Write-Host "Registry NullSessionPipes: 'samr' was already present (no change)."
    } else {
        if ($regAddedSamr) {
            Write-Host "Registry NullSessionPipes: 'samr' has been ADDED."
        } else {
            Write-Host "Registry NullSessionPipes: attempted to add 'samr' but write failed."
        }
    }
} else {
    Write-Host "Registry NullSessionPipes: could not be modified."
}
Write-Host ""
Write-Host "WARNING: SMB (TCP 445) now allowed in/out, ping echo allowed (ICMPv4/v6 in+out),"
Write-Host "WARNING: and NullSessionPipes may now include 'samr'."
Write-Host "WARNING: This box is intentionally weakened for isolated lab exploitation only."
Write-Host "======================================================="
Write-Host ""

#########################################################
# 8. Offer reboot
#########################################################

$rebootAns = Read-Host "Reboot now to apply everything cleanly? (Y/N)"
if ($rebootAns -match '^[Yy]') {
    Write-Host "INFO: Rebooting..."
    shutdown /r /t 0
    exit 0
}

Write-Host "INFO: Reboot skipped. Some changes fully apply after restart."
Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
exit 0
