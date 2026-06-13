@echo off
SETLOCAL EnableDelayedExpansion
title AgentWall Dashboard Launcher

echo.
echo  ============================================
echo     AgentWall - One-Click Dashboard Launcher
echo  ============================================
echo.

:: Get script directory
set "ROOT=%~dp0"
cd /d "%ROOT%"

:: ─── Check Prerequisites ──────────────────────────────────────────────
echo [1/5] Checking prerequisites...

python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not installed or not in PATH.
    pause
    exit /b 1
)

where node >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Node.js is not installed or not in PATH.
    pause
    exit /b 1
)

echo       Python ... OK
echo       Node.js ... OK

:: ─── Virtual Environment ──────────────────────────────────────────────
echo [2/5] Setting up Python environment...

if not exist "venv" (
    echo       Creating virtual environment...
    python -m venv venv
)
call venv\Scripts\activate
pip install -q -r requirements.txt

:: ─── Dashboard Dependencies ───────────────────────────────────────────
echo [3/5] Installing dashboard dependencies...

cd dashboard
if not exist "node_modules" (
    echo       Running npm install...
    npm install --silent
)
cd ..

:: ─── Load .env ────────────────────────────────────────────────────────
if exist ".env" (
    for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
        set "LINE=%%A"
        if not "!LINE:~0,1!"=="#" (
            if not "%%A"=="" (
                set "%%A=%%B"
            )
        )
    )
)

:: ─── Kill any stale processes on ports 8000 and 3000 ──────────────────
echo [4/5] Clearing ports...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING" 2^>nul') do (
    taskkill /PID %%a /F >nul 2>&1
)
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":3000" ^| findstr "LISTENING" 2^>nul') do (
    taskkill /PID %%a /F >nul 2>&1
)

:: ─── Start Services ──────────────────────────────────────────────────
echo [5/5] Starting services...

:: Start Backend (FastAPI on port 8000)
start "AgentWall-Backend" cmd /c "cd /d "%ROOT%" && call venv\Scripts\activate && python -m uvicorn agentwall.main:app --host 0.0.0.0 --port 8000 --ws websockets"

:: Wait for backend to be ready
echo       Waiting for backend...
timeout /t 3 /nobreak >nul

:: Start Dashboard (Vite dev server on port 3000)
start "AgentWall-Dashboard" cmd /c "cd /d "%ROOT%\dashboard" && npm run dev"

:: Wait for dashboard to be ready
echo       Waiting for dashboard...
timeout /t 3 /nobreak >nul

:: Open browser
echo.
echo  ============================================
echo    AgentWall is running!
echo  ============================================
echo.
echo    Dashboard:  http://localhost:3000
echo    Backend:    http://localhost:8000
echo    Password:   (set in .env AGENTWALL_ADMIN_PASSWORD)
echo.
echo    To stop: close this window and the two
echo    terminal windows that opened.
echo  ============================================
echo.

start http://localhost:3000

echo Press any key to STOP all AgentWall services...
pause >nul

:: Cleanup - kill the backend and dashboard
taskkill /FI "WINDOWTITLE eq AgentWall-Backend*" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq AgentWall-Dashboard*" /F >nul 2>&1

echo.
echo AgentWall stopped.
