<#
File: step1-firewall-ms17.ps1
Purpose: Create inbound firewall rule for SMB (TCP 445) for lab use

Warning:
    This script is intended for controlled, isolated lab environments only.
    It is provided strictly for educational and defensive testing use.
    The author is not responsible for misuse or for any action performed
    on systems or networks you do not own or have explicit permission to test.

Run:
    Open PowerShell as Administrator
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    .\step1-firewall-ms17.ps1
#>

# Name and description for the firewall rule
$ruleDisplayName = "MS17 (Eternal Blue)"
$ruleInternalName = "MS17_EternalBlue_In"
$ruleDescription  = "Allow inbound SMB (TCP 445) for MS17-010 style lab testing. Use only in a controlled environment. Author is not responsible for misuse."

Write-Host "=== MS17-010 Lab Firewall Setup: Inbound TCP 445 ==="

# Check if the rule already exists by display name
$existingRule = Get-NetFirewallRule -DisplayName $ruleDisplayName -ErrorAction SilentlyContinue

if ($existingRule) {
    Write-Host "Rule '$ruleDisplayName' already exists. No new rule created."
} else {
    # Create inbound allow rule for TCP 445 on all profiles
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

Write-Host "Done."