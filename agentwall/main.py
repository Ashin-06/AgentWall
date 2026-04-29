print("[Audit] [BOOT] AgentWall Loading...")
import asyncio
import json
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

from agentwall.proxy import AgentWallProxy
from agentwall.audit.schema import init_db
from agentwall.audit.logger import AuditLogger
from agentwall.shadow import ShadowMode
from agentwall.auth import require_auth, create_jwt, AUTH_ENABLED
from agentwall.metrics import MetricsRegistry
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from collections import defaultdict
import time


# Global rate limiters
login_attempts = defaultdict(list)
intercept_rate = defaultdict(list)


# ─── Request/Response Schemas ────────────────────────────────────────────────
class LoginRequest(BaseModel):
    password: str

class InterceptRequest(BaseModel):
    session_id: str
    agent_id: str
    call_id: str
    tool_name: str
    arguments: Dict[str, Any]
    source_fmt: Optional[str] = "unknown"

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB
    init_db()
    
    # Start background worker for audit queue
    from agentwall.audit.write_queue import DBWriteQueue
    queue = DBWriteQueue.get()
    
    def broadcast_alert(msg):
        for ws in list(active_connections):
            try: asyncio.create_task(ws.send_text(msg))
            except: pass
            
    queue.start(broadcast_cb=broadcast_alert)
    
    # Initialize Security Proxy
    proxy = AgentWallProxy()
    app.state.proxy = ShadowMode(proxy)
    
    # Start System Watcher
    from agentwall.audit.system_watcher import start_system_watcher
    watcher = start_system_watcher(asyncio.get_event_loop())
    
    # Seed metrics
    from agentwall.audit.schema import get_global_stats
    stats = get_global_stats()
    m = MetricsRegistry.get()
    for v, c in stats["verdicts"].items(): m.inc("agentwall_calls_total", {"verdict": v, "agent": "historical", "tool": "historical"}, c)
    for t, c in stats["mitre"].items(): m.inc("agentwall_mitre_hits_total", {"technique": t}, c)
    for t, c in stats["tools"].items(): m.inc("agentwall_tool_calls_total", {"tool": t}, c)
    print(f"[Metrics] [SEEDING] Successfully recovered historical events.")

    yield

    # Graceful shutdown
    await queue.flush()
    queue.stop()
    watcher.stop()
    print("AgentWall shut down cleanly")

app = FastAPI(title="AgentWall", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static Dashboard Mount
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
dashboard_dist = os.path.join(root_dir, "dashboard", "dist")
final_static_path = dashboard_dist if os.path.exists(dashboard_dist) else os.path.join(os.path.dirname(__file__), "static")
print(f"[Dashboard] Serving from: {final_static_path}")

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

if not os.path.exists(final_static_path):
    os.makedirs(final_static_path, exist_ok=True)
    with open(os.path.join(final_static_path, "index.html"), "w") as f:
        f.write("<html><body><h1>AgentWall Dashboard</h1></body></html>")

app.mount("/assets", StaticFiles(directory=os.path.join(final_static_path, "assets") if os.path.exists(os.path.join(final_static_path, "assets")) else final_static_path), name="assets")

@app.get("/")
async def root():
    return FileResponse(os.path.join(final_static_path, "index.html"))

active_connections = set()

@app.websocket("/ws/intercept")
async def websocket_endpoint(websocket: WebSocket, token: str):
    from agentwall.auth import verify_jwt
    payload = verify_jwt(token)
    if payload:
        await websocket.accept()
        active_connections.add(websocket)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            active_connections.remove(websocket)
    else:
        print(f"[WS] Auth Failed: Invalid token")
        try: await websocket.close(code=4003)
        except: pass

@app.post("/auth/login")
async def login(req: LoginRequest):
    admin_pw = os.getenv("AGENTWALL_ADMIN_PASSWORD", "admin")
    if req.password == admin_pw:
        return {"token": create_jwt({"sub": "admin", "role": "admin"}), "expires_in": 3600}
    raise HTTPException(status_code=401, detail="Invalid password")

@app.post("/intercept")
async def intercept(request: Request, body: InterceptRequest):
    proxy = app.state.proxy.raw_proxy
    res = await proxy.intercept(
        body.session_id, body.agent_id, body.call_id,
        body.tool_name, body.arguments, body.source_fmt
    )
    return res

@app.get("/api/sessions")
async def list_sessions(limit: int = 1000, auth=Depends(require_auth)):
    from agentwall.audit.schema import get_sessions
    return get_sessions(limit=limit)

@app.get("/api/sessions/{session_id}")
async def get_session_events(session_id: str, auth=Depends(require_auth)):
    from agentwall.audit.schema import get_session_events
    return get_session_events(session_id)

@app.get("/api/violations")
async def list_violations(limit: int = 1000, auth=Depends(require_auth)):
    from agentwall.audit.schema import get_violations
    return get_violations(limit=limit)

@app.get("/api/risk-scores")
async def get_risk_scores(auth=Depends(require_auth)):
    from agentwall.audit.schema import get_risk_scores
    return get_risk_scores()

@app.get("/api/campaigns")
async def get_campaigns(auth=Depends(require_auth)):
    from agentwall.audit.schema import get_campaigns
    return get_campaigns()

@app.get("/api/mitre-heatmap")
async def get_mitre_heatmap(auth=Depends(require_auth)):
    from agentwall.audit.schema import get_mitre_stats
    return get_mitre_stats()

@app.get("/api/attack-graph")
async def get_attack_graph(auth=Depends(require_auth)):
    # Fallback to empty graph if no data
    return {"nodes": [], "edges": []}

@app.get("/metrics")
async def metrics():
    return PlainTextResponse(MetricsRegistry.get().export())

# Universal AI Gateway (OpenAI, Claude, Gemini compatible)
@app.post("/v1/chat/completions")
@app.post("/v1/messages")
@app.post("/v1/proxy/{target_host:path}")
async def universal_gateway(request: Request, target_host: str = "api.openai.com"):
    body = await request.json()
    agent_id = request.headers.get("X-AgentWall-Agent", "browser_intercept")
    session_id = request.headers.get("X-AgentWall-Session", f"SESS_{int(time.time())}")
    
    # Identify protocol
    protocol = "openai"
    if "/messages" in str(request.url): protocol = "anthropic"
    if "google" in target_host: protocol = "google"

    from agentwall.audit.write_queue import DBWriteQueue
    await DBWriteQueue.get().write((
        session_id, agent_id, f"gen_{int(time.time())}", f"{protocol}_call",
        body, "PERMIT", f"Intercepted via {protocol.upper()} Gateway", 
        {"target": target_host}, "T1059", "gateway", 0, False, protocol
    ))

    api_key = os.getenv("AGENTWALL_UPSTREAM_KEY")
    if not api_key:
        return JSONResponse(status_code=200, content={"message": "AgentWall: Dev Mode Active. No upstream key set."})

    import httpx
    async with httpx.AsyncClient() as client:
        # Determine upstream URL
        if protocol == "openai":
            url = os.getenv("AGENTWALL_UPSTREAM_URL", "https://api.openai.com/v1/chat/completions")
        elif protocol == "anthropic":
            url = "https://api.anthropic.com/v1/messages"
        else:
            url = f"https://{target_host}"

        resp = await client.post(url, json=body, headers={"Authorization": f"Bearer {api_key}"}, timeout=60.0)
        return JSONResponse(status_code=resp.status_code, content=resp.json() if "json" in resp.headers.get("content-type", "") else resp.text)

# Transparent Proxy Handler (DISABLED to restore VS Code connectivity)
# @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
# async def catchall_proxy(request: Request, path: str):
#     if any(path.startswith(x) for x in ["api", "auth", "ws", "assets", "metrics", "health", "v1"]):
#         raise HTTPException(status_code=404)
#     import httpx
#     method = request.method
#     url = str(request.url)
#     headers = dict(request.headers)
#     body = await request.body()
#     from agentwall.audit.system_watcher import get_likely_agent
#     agent_id = get_likely_agent()
#     session_id = f"PROXY_{int(time.time())}"
#     from agentwall.audit.write_queue import DBWriteQueue
#     await DBWriteQueue.get().write((
#         session_id, agent_id, f"px_{int(time.time())}", "proxy_request",
#         {"url": url, "method": method}, "AUDIT", 
#         f"Transparent Intercept: {method} request to {url}", 
#         {"headers": headers}, "T1090", "proxy", 0, False, "http"
#     ))
#     async with httpx.AsyncClient() as client:
#         try:
#             headers.pop("host", None)
#             resp = await client.request(method, url, content=body, headers=headers, follow_redirects=True, timeout=30.0)
#             return JSONResponse(status_code=resp.status_code, content=resp.json() if "json" in resp.headers.get("content-type", "") else resp.text)
#         except Exception as e:
#             return JSONResponse(status_code=502, content={"error": str(e)})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
