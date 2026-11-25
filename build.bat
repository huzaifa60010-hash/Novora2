@echo off
setlocal EnableExtensions
title NOVORA Store - Production Builder

cd /d "%~dp0"

echo ===================================================
echo   NOVORA E-Commerce Store - Windows Production Build
echo ===================================================
echo.

echo [1/2] Checking Node.js...
where node >nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js is not installed.
    echo Please install Node.js LTS from https://nodejs.org/
    pause
    exit /b 1
)

set "NEED_INSTALL=0"
if not exist "node_modules" set "NEED_INSTALL=1"
if not exist "node_modules\.bin\vite.cmd" set "NEED_INSTALL=1"

if "%NEED_INSTALL%"=="1" (
    echo Installing dependencies...
    set "NODE_ENV="
    call npm install --include=dev
    if errorlevel 1 (
        echo ERROR: npm install failed.
        pause
        exit /b 1
    )
)

echo.
echo [2/2] Running production build with Vite...
set "NODE_ENV="
call npm run build

if errorlevel 1 (
    echo.
    echo ===================================================
    echo   BUILD FAILED! Please inspect errors above.
    echo ===================================================
    pause
    exit /b 1
) else (
    echo.
    echo ===================================================
    echo   BUILD SUCCEEDED! Production files generated in /dist
    echo ===================================================
    echo.
    echo Double-click OPEN-NOVORA.bat to launch the store locally.
    echo.
)

pause
