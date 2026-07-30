@echo off
rem Secure Code Review Dashboard - Windows installer launcher.
rem Works from double-click or cmd.exe; bypasses PowerShell script policy.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
if errorlevel 1 (
  echo.
  echo Installation reported an error - see the messages above.
)
pause