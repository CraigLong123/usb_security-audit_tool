@echo off
:: ============================================================
::  Windows Security Audit Tool - Build Launcher
::  Double-click this file to build SecurityAudit.exe
:: ============================================================
 
title Security Audit Tool - Build
 
echo.
echo ============================================================
echo   Windows Security Audit Tool - Build Launcher
echo ============================================================
echo.
 
:: Check we're running from the right place
if not exist "audit.py" (
    echo   ERROR: audit.py not found.
    echo   Please run this script from the project root directory.
    echo.
    pause
    exit /b 1
)
 
if not exist "modules" (
    echo   ERROR: modules/ directory not found.
    echo   Please run this script from the project root directory.
    echo.
    pause
    exit /b 1
)
 
:: Check Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   ERROR: Python not found on PATH.
    echo   Please install Python 3.8+ and ensure it is on your PATH.
    echo   Download from: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)
 
echo   Python found:
python --version
echo.
 
:: Ask user if they want a clean build
set /p CLEAN="  Clean previous build? (y/n, default=n): "
if /i "%CLEAN%"=="y" (
    echo.
    echo   Running clean build...
    python build.py --clean
) else (
    echo.
    echo   Running build...
    python build.py
)
 
:: Check result
if %errorlevel% equ 0 (
    echo.
    echo ============================================================
    echo   SUCCESS - dist\SecurityAudit.exe is ready
    echo ============================================================
    echo.
    echo   Copy dist\SecurityAudit.exe to your USB drive.
    echo.
) else (
    echo.
    echo ============================================================
    echo   BUILD FAILED - See errors above
    echo ============================================================
    echo.
)
 
pause