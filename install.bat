@echo off
echo [AgentWall] Starting Installation...
python -m venv venv
call .\venv\Scripts\activate
echo [AgentWall] Installing core dependencies...
pip install -r requirements.txt
pip install websockets wsproto psutil
echo [AgentWall] Preparing Dashboard...
cd dashboard
npm install
npm run build
cd ..
echo [AgentWall] Installation Complete. Run .\run_agentwall.bat to start.
pause
