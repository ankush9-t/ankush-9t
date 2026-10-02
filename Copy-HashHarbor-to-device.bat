@echo off
setlocal
set "SCRIPT=%~dp0Copy-HashHarbor.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
if errorlevel 1 (
    echo.
    echo HashHarbor copy did not complete. Check the message above.
    pause
)
endlocal