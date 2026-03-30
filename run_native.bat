@echo off
SETLOCAL EnableDelayedExpansion

echo ################################################
echo #      AgentWall Native Startup Script          #
echo ################################################
echo.

:: Check for Python
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not installed or not in PATH.
    pause
    exit /b
)

:: Check for Virtual Env or Install Deps
if not exist "venv" (
    echo [INFO] Creating virtual environment...
    python -m venv venv
)

echo [1/3] Installing/Updating dependencies...
call venv\Scripts\activate
pip install -q -r requirements.txt

:: Check for .env
if not exist ".env" (
    echo [INFO] Creating .env from .env.example...
    copy .env.example .env
)

echo [2/3] Starting AgentWall Proxy (Native Mode)...
echo [INFO] API will be available at http://localhost:8000
echo.

set AGENTWALL_ENV=development
set AGENTWALL_FAIL_MODE=closed
set REDIS_URL=

python -m uvicorn agentwall.main:app --host 0.0.0.0 --port 8000 --reload --ws websockets

echo.
pause
