@echo off
REM Double-click this file to start CIMI and open it in your browser.
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is not installed. Download it from https://nodejs.org ^(version 18 or newer^), then run this file again.
  pause
  exit /b 1
)
node scripts\launch.js
pause
