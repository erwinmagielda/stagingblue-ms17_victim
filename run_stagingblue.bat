@echo off
echo [*] Launching MS17-010 Lab Prep Tool (ExecutionPolicy: Bypass)...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0stagingblue.ps1"
pause
