@echo off
REM ============================================================
REM  SeewoKiller one-command release build
REM  Usage:  build_release.bat
REM  Requires: Visual Studio (LaunchDevCmd), CMake, Inno Setup,
REM            vcpkg with libssh+webview2 (set VCPKG_ROOT to override)
REM ============================================================
setlocal enabledelayedexpansion

cd /d "%~dp0"

if not exist VERSION (
    echo [ERR] VERSION file missing at repo root.
    exit /b 1
)
set /p APP_VERSION=<VERSION
echo [1/5] Version: %APP_VERSION%

REM -- keep setup.iss in sync with VERSION (single source of truth) --
findstr /C:"#define MyAppVersion \"%APP_VERSION%\"" setup.iss >nul
if errorlevel 1 (
    echo [ERR] setup.iss MyAppVersion does not match VERSION ^(%APP_VERSION%^).
    echo       Fix setup.iss first - never release with mismatched versions.
    exit /b 1
)

REM -- locate Visual Studio dev environment --
set "VSCMD=C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\LaunchDevCmd.bat"
if not exist "%VSCMD%" (
    echo [ERR] Visual Studio dev cmd not found: %VSCMD%
    exit /b 1
)
call "%VSCMD%" -arch=amd64 -no_logo >nul

REM -- configure + build --
if "%VCPKG_ROOT%"=="" set "VCPKG_ROOT=C:/dev/vcpkg/installed/x64-windows"
echo [2/5] Configure ^(VCPKG_ROOT=%VCPKG_ROOT%^) ...
cmake -B build -DVCPKG_ROOT=%VCPKG_ROOT% || exit /b 1
echo [3/5] Build Release ...
cmake --build build --config Release || exit /b 1

echo [4/5] Unit tests (ctest) ...
ctest --test-dir build -C Release --output-on-failure || exit /b 1

echo [5/5] Installer (Inno Setup) ...
set "ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" (
    echo [ERR] Inno Setup 6 not found at the default location.
    exit /b 1
)
"%ISCC%" setup.iss || exit /b 1

echo.
echo ============================================================
echo  Release %APP_VERSION% OK:  installer\SeewoKiller-v4-Setup.exe
echo ============================================================
endlocal
