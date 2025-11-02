@echo off
REM deploy_only_copy.bat
REM Copies the two script files from source -> destination and overwrites existing ones.

SET "SRC=C:\Users\Erwin\Desktop\code\exploit-ms17-automation"
SET "DST=C:\Users\Erwin\Desktop\shared_folder\test"

echo [*] Copying files from "%SRC%" to "%DST%"...

REM Use ROBOCOPY to copy specific files and overwrite silently if present
robocopy "%SRC%" "%DST%" script.ps1 run_script.bat /R:2 /W:2 /NFL /NDL

IF %ERRORLEVEL% GEQ 8 (
  echo [!] robocopy reported a failure. Check paths and permissions.
  pause
  exit /b 1
) ELSE (
  echo [+] Copy finished (files replaced if they existed).
  pause
  exit /b 0
)