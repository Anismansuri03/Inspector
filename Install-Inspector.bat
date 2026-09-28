@echo off
:: ==============================================================================
:: Inspector v2 - One-Click Launcher
:: Checks prerequisites and launches Inspector.ps1 with the right action.
:: Double-click this to install, activate, or generate reports.
:: ==============================================================================
setlocal EnableDelayedExpansion

echo.
echo ====================================================
echo        Inspector v2 - Sysmon Security Monitor
echo ====================================================
echo.

:: Check admin rights
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo [ERROR] This tool requires Administrator privileges.
    echo.
    echo   Please right-click this file and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

:: Check .NET SDK (needed for build)
dotnet --version >nul 2>&1
if %errorLevel% NEQ 0 (
    echo [ERROR] .NET SDK not found.
    echo.
    echo   Inspector requires .NET 8 SDK to build.
    echo   Download from: https://dotnet.microsoft.com/download/dotnet/8.0
    echo.
    pause
    exit /b 1
)

:: Check if PowerShell execution policy allows scripts
powershell -Command "Get-ExecutionPolicy -Scope CurrentUser" 2>nul | findstr /r "Restricted AllSigned" >nul
if %errorLevel% EQU 0 (
    echo [NOTE] Setting PowerShell execution policy to RemoteSigned (one-time setup)...
    powershell -Command "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force"
    if %errorLevel% NEQ 0 (
        echo.
        echo [ERROR] Could not set execution policy. Please run this command as Administrator:
        echo   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
        echo.
        pause
        exit /b 1
    )
)

:: Check if Sysmon is installed
echo Checking for Sysmon...
sc query "Sysmon*" >nul 2>&1
if %errorLevel% NEQ 0 (
    sc query "Sysmon64" >nul 2>&1
)
if %errorLevel% NEQ 0 (
    echo.
    echo [WARNING] Sysmon is not installed.
    echo.
    echo Sysmon is required for Inspector to work. It provides kernel-level
    echo process monitoring for process creation and termination events.
    echo.
    echo Options:
    echo   1. Download Sysmon from:
    echo      https://learn.microsoft.com/sysinternals/downloads/sysmon
    echo.
    echo   2. Install with default config (run as Administrator):
    echo      Sysmon64.exe -accepteula -i
    echo.
    echo Press any key after installing Sysmon, then run this installer again.
    echo.
    pause
    exit /b 1
)

echo [OK] Sysmon detected.
echo.
echo Starting Inspector installer...
echo.

:: Launch the main PowerShell script with -Install
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "Inspector.ps1" -Install

if %errorLevel% NEQ 0 (
    echo.
    echo [ERROR] Installation encountered an issue.
    pause
    exit /b 1
)

echo.
echo ====================================================
echo   Installation complete!
echo ====================================================
echo.
echo Next steps:
echo   1. Run:  Inspector.ps1 -Activate
echo   2. When the popup happens again, run:  Inspector.ps1 -Report
echo.
pause
