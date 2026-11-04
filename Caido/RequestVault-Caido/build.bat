@echo off
setlocal enabledelayedexpansion

echo ================================================================
echo   RequestVault for Caido - Build and Package Script
echo   Author:  Kakaxh1
echo   Website: https://bhavymorvadiya.netlify.app/
echo ================================================================
echo.

node build.js
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Build failed.
    exit /b %ERRORLEVEL%
)

echo.
echo Build complete.
