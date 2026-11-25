@echo off
setlocal EnableExtensions
title NOVORA E-Commerce Store - One-Click Launcher

cd /d "%~dp0"

echo ===================================================
echo   NOVORA E-Commerce Store - Windows Launcher
echo ===================================================
echo.

echo [1/4] Checking Node.js environment...
where node >nul 2>&1
if errorlevel 1 (
    echo.
    echo ERROR: Node.js is not installed or not found in PATH.
    echo Please install Node.js LTS from https://nodejs.org/ and restart this file.
    echo.
    pause
    exit /b 1
)

echo [2/4] Verifying dependencies...
set "NEED_INSTALL=0"
if not exist "node_modules" set "NEED_INSTALL=1"
if not exist "node_modules\.bin\vite.cmd" set "NEED_INSTALL=1"
if not exist "node_modules\.bin\tsx.cmd" set "NEED_INSTALL=1"

if "%NEED_INSTALL%"=="1" (
    echo Installing dependencies ^(this may take 1-2 minutes on first run^)...
    set "NODE_ENV="
    call npm install --include=dev
    if errorlevel 1 (
        echo.
        echo ERROR: npm install failed.
        pause
        exit /b 1
    )
) else (
    echo Dependencies found.
)

echo.
echo [3/4] Building production bundle (Vite)...
set "NODE_ENV="
call npm run build
if errorlevel 1 (
    echo.
    echo ERROR: npm run build failed.
    pause
    exit /b 1
)

if not exist "dist\index.html" (
    echo.
    echo ERROR: dist\index.html was not generated.
    pause
    exit /b 1
)

echo.
echo [4/4] Starting full-stack server...
set "NOVORA_PORT=3000"
for /f "usebackq delims=" %%P in (`node -e "const n=require('net');const t=p=>new Promise(r=>{const s=n.createServer();s.once('error',()=>r(0));s.once('listening',()=>s.close(()=>r(1)));s.listen(p,'0.0.0.0');});(async()=>{for(let p=3000;p!==3011;p++){if(await t(p)){console.log(p);process.exit(0);}}console.log(3000);})();"`) do set "NOVORA_PORT=%%P"

if not "%NOVORA_PORT%"=="3000" (
    echo Port 3000 is currently busy. Launching NOVORA on http://localhost:%NOVORA_PORT% instead.
)

set "PORT=%NOVORA_PORT%"
set "NODE_ENV=production"

echo Opening http://localhost:%NOVORA_PORT% once server responds...
start "" /b node -e "const h=require('http'),cp=require('child_process'),p=process.env.PORT?process.env.PORT:'3000',u='http://localhost:'+p;let i=0;const iv=setInterval(()=>{i++;if(i===90){clearInterval(iv);return;}const r=h.get('http://127.0.0.1:'+p+'/api/products',s=>{s.resume();clearInterval(iv);cp.execFile('cmd.exe',['/c','start','',u]);});r.on('error',()=>{});r.setTimeout(1000,()=>r.destroy());},400);"

call npm run start

if errorlevel 1 (
    echo.
    echo Server stopped with an error.
    pause
)
