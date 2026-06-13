@echo off
echo Stopping AgentWall services...

:: Kill backend (uvicorn on port 8000)
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING" 2^>nul') do (
    echo   Stopping backend (PID: %%a)
    taskkill /PID %%a /F >nul 2>&1
)

:: Kill dashboard (vite on port 3000)
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":3000" ^| findstr "LISTENING" 2^>nul') do (
    echo   Stopping dashboard (PID: %%a)
    taskkill /PID %%a /F >nul 2>&1
)

:: Kill any spawned windows
taskkill /FI "WINDOWTITLE eq AgentWall-Backend*" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq AgentWall-Dashboard*" /F >nul 2>&1

echo.
echo All AgentWall services stopped.
timeout /t 2 >nul
