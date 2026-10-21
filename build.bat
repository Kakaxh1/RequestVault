@echo off
setlocal enabledelayedexpansion

echo ================================================================
echo   RequestVault - HTTP Traffic Collection and Evidence Export
echo   GitHub:  https://github.com/Kakaxh1/RequestVault
echo   Author:  Kakaxh1
echo   Website: https://bhavymorvadiya.netlify.app/
echo ================================================================
echo.

if not exist "build\classes" mkdir "build\classes"
if not exist "build\libs" mkdir "build\libs"

set "CP=lib\montoya-api-2023.12.1.jar;lib\gson-2.10.1.jar"

echo [1/3] Compiling Java source files...
powershell -NoProfile -Command "Get-ChildItem -Recurse -Filter *.java src\main\java | ForEach-Object { '\"' + $_.FullName.Replace('\', '/') + '\"' } | Out-File -Encoding ASCII sources.txt"
javac -cp "%CP%" -d build\classes @sources.txt
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Compilation failed.
    if exist sources.txt del sources.txt
    exit /b %ERRORLEVEL%
)
if exist sources.txt del sources.txt

echo [2/3] Extracting runtime dependencies (Gson)...
cd build\classes
jar -xf "..\..\lib\gson-2.10.1.jar"
cd ..\..

echo [3/3] Packaging fat JAR (RequestVault.jar)...
jar -cfe build\libs\RequestVault.jar requestvault.RequestVaultExtension -C build\classes .

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ================================================================
    echo  [SUCCESS] Build Finished Successfully.
    echo  Artifact: build\libs\RequestVault.jar
    echo  Project:  https://github.com/Kakaxh1/RequestVault
    echo  Website:  https://bhavymorvadiya.netlify.app/
    echo ================================================================
    echo You can now load build\libs\RequestVault.jar directly into Burp Suite.
) else (
    echo.
    echo [ERROR] Packaging failed.
)
