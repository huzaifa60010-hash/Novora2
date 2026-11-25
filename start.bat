@echo off
setlocal EnableExtensions
title NOVORA Store - Windows Local Runner

cd /d "%~dp0"

echo ===================================================
echo   NOVORA E-Commerce Store - Windows Runner
echo ===================================================
echo.

echo [1/3] Checking Node.js environment...
where node >nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js is not installed or not in PATH.
    echo Please install Node.js LTS ^(v18 or higher^) from https://nodejs.org/
    echo.
    pause
    exit /b 1
)

echo [2/3] Checking project dependencies...
set "NEED_INSTALL=0"
if not exist "node_modules" set "NEED_INSTALL=1"
if not exist "node_modules\.bin\vite.cmd" set "NEED_INSTALL=1"
if not exist "node_modules\.bin\tsx.cmd" set "NEED_INSTALL=1"

if "%NEED_INSTALL%"=="1" (
    echo Installing npm dependencies...
    set "NODE_ENV="
    call npm install --include=dev
    if errorlevel 1 (
        echo ERROR: Dependency installation failed.
        pause
        exit /b 1
    )
) else (
    echo Dependencies are already installed.
)

echo.
echo [3/3] Starting NOVORA Full-Stack Server...
set "NOVORA_PORT=3000"
for /f "usebackq delims=" %%P in (`node -e "const n=require('net');const t=p=>new Promise(r=>{const s=n.createServer();s.once('error',()=>r(0));s.once('listening',()=>s.close(()=>r(1)));s.listen(p,'0.0.0.0');});(async()=>{for(let p=3000;p!==3011;p++){if(await t(p)){console.log(p);process.exit(0);}}console.log(3000);})();"`) do set "NOVORA_PORT=%%P"

set "PORT=%NOVORA_PORT%"
set "NODE_ENV="

echo Local URL: http://localhost:%NOVORA_PORT%
echo Browser will open automatically once server is ready...
start "" /b node -e "const h=require('http'),cp=require('child_process'),p=process.env.PORT?process.env.PORT:'3000',u='http://localhost:'+p;let i=0;const iv=setInterval(()=>{i++;if(i===90){clearInterval(iv);return;}const r=h.get('http://127.0.0.1:'+p+'/api/products',s=>{s.resume();clearInterval(iv);cp.execFile('cmd.exe',['/c','start','',u]);});r.on('error',()=>{});r.setTimeout(1000,()=>r.destroy());},400);"

call npm run dev

if errorlevel 1 (
    echo.
    echo Process exited with an error code.
    pause
)
