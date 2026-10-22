@echo off
rem Double-click launcher for the suspex0 status watch window.
rem Opens a PowerShell process running watch.ps1 in its own console.
powershell.exe -NoExit -ExecutionPolicy Bypass -File "%~dp0watch.ps1"
