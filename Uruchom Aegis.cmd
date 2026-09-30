@echo off
setlocal
title Aegis SOC - lokalny backend
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\aegis.ps1" -Action start
set "aegis_result=%errorlevel%"
echo.
pause
exit /b %aegis_result%
