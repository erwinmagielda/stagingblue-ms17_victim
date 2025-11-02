@echo off
echo [*] Launching MS17-010 Lab Prep Tool (ExecutionPolicy: Bypass)...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0script.ps1"
pause
