@echo off
setlocal
cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File "%~dp0launch-website-audit.ps1"
if errorlevel 1 (
  echo.
  echo Audit-Start fehlgeschlagen.
  pause
  exit /b 1
)
endlocal
