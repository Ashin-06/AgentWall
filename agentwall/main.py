print("[Audit] [BOOT] AgentWall Loading...")

# Load .env BEFORE any other imports so all modules see the env vars
import os
import hmac
import secrets

from dotenv import load_dotenv
_env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
if os.path.exists(_env_path):
    load_dotenv(_env_path, override=False)
    print(f"[Config] Loaded .env from {_env_path}")

import asyncio
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

from agentwall.proxy import AgentWallProxy
from agentwall.audit.schema import init_db
from agentwall.audit.logger import AuditLogger
from agentwall.shadow import ShadowMode
from agentwall.auth import require_auth, create_jwt, AUTH_ENABLED, JWT_TTL
from agentwall.metrics import MetricsRegistry
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from collections import defaultdict
import time


# Global rate limiters
login_attempts = defaultdict(list)
LOGIN_MAX_FAILURES = int(os.getenv("AGENTWALL_LOGIN_MAX_FAILURES", "5"))  # per IP per minute


# --- Request/Response Schemas ------------------------------------------------
class LoginRequest(BaseModel):
    password: str

class InterceptRequest(BaseModel):
    session_id: str
    agent_id: str
    call_id: str
    tool_name: str
    arguments: Dict[str, Any]
    source_fmt: Optional[str] = "unknown"
    context: Optional[str] = None

class OutputRequest(BaseModel):
    output: str
    session_id: Optional[str] = None
    agent_id: Optional[str] = None
    tool_name: Optional[str] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    from agentwall.auth import validate_production_config
    validate_production_config()
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
    # The dashboard is served from this origin; other origins must be listed explicitly.
    allow_origins=[o.strip() for o in os.getenv("AGENTWALL_CORS_ORIGINS", "").split(",") if o.strip()],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static Dashboard Mount
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
dashboard_dist = os.path.join(root_dir, "dashboard", "dist")
final_static_path = dashboard_dist if os.path.exists(dashboard_dist) else os.path.join(os.path.dirname(__file__), "static")
print(f"[Dashboard] Serving from: {final_static_path}")

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse


_assets = os.path.join(final_static_path, "assets")
if os.path.isdir(_assets):
    app.mount("/assets", StaticFiles(directory=_assets), name="assets")

@app.get("/")
async def root():
    index = os.path.join(final_static_path, "index.html")
    if not os.path.exists(index):
        return HTMLResponse("<html><body><h1>AgentWall</h1><p>Dashboard build not found.</p></body></html>")
    return FileResponse(index)

@app.get("/health")
async def health():
    return {"status": "ok"}

active_connections = set()

@app.websocket("/ws/intercept")
async def websocket_endpoint(websocket: WebSocket):
    """Clients send {"type": "auth", "token": "<jwt or api key>"} first; tokens stay out of URLs and logs."""
    import agentwall.auth as auth_config
    await websocket.accept()
    if auth_config.AUTH_ENABLED:
        try:
            msg = json.loads(await asyncio.wait_for(websocket.receive_text(), timeout=5))
            if msg.get("type") != "auth":
                raise ValueError("first message must be auth")
            auth_config.require_auth_token(str(msg.get("token", "")))  # raises on a bad token
        except Exception:
            await websocket.close(code=4003)
            return
    active_connections.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        active_connections.discard(websocket)

ADMIN_PASSWORD = os.getenv("AGENTWALL_ADMIN_PASSWORD") or secrets.token_urlsafe(12)
if not os.getenv("AGENTWALL_ADMIN_PASSWORD"):
    # Dev only: production refuses to start without AGENTWALL_ADMIN_PASSWORD (auth.validate_production_config).
    print(f"[Security] AGENTWALL_ADMIN_PASSWORD is not set. Dashboard password for this run: {ADMIN_PASSWORD}")  # vibeaudit: ignore[SEC010] one-time generated dev password, never a configured secret


@app.post("/auth/login")
async def login(req: LoginRequest, request: Request):
    # ponytail: in-process per-IP limit; use a shared store if running several replicas
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    for other in [k for k, v in login_attempts.items() if not v or now - v[-1] >= 60]:
        del login_attempts[other]  # ponytail: O(ips) per login; fine for an admin-only endpoint
    recent = [t for t in login_attempts.get(ip, []) if now - t < 60]
    if len(recent) >= LOGIN_MAX_FAILURES:
        raise HTTPException(status_code=429, detail="Too many failed logins; try again later")
    if hmac.compare_digest(req.password.encode(), ADMIN_PASSWORD.encode()):
        return {"token": create_jwt({"sub": "admin", "role": "admin"}), "expires_in": JWT_TTL}
    login_attempts[ip] = recent + [now]
    raise HTTPException(status_code=401, detail="Invalid password")

@app.post("/intercept")
@app.post("/intercept/langchain")
async def intercept(request: Request, body: Dict[str, Any], auth=Depends(require_auth)):
    from agentwall.interceptor import normalise_raw
    from pydantic import ValidationError
    try:
        normalised = normalise_raw(body)
        call = InterceptRequest(**normalised)  # vibeaudit: ignore[BE009] pydantic validation model, nothing is written from it directly
    except (KeyError, TypeError, ValueError, ValidationError):
        raise HTTPException(status_code=422, detail="Invalid tool-call payload")
    # Route through ShadowMode wrapper which handles the evaluation
    res = await app.state.proxy.observe(call.model_dump())
    return res

@app.post("/intercept/output")
async def sanitise_output(body: OutputRequest, auth=Depends(require_auth)):
    return await app.state.proxy.proxy.sanitise_output(body.model_dump())

@app.get("/api/sessions")
async def list_sessions(limit: int = Query(1000, ge=1, le=1000), auth=Depends(require_auth)):
    from agentwall.audit.schema import get_sessions
    return get_sessions(limit=limit)

@app.get("/api/sessions/{session_id}")
async def get_session_events(session_id: str, auth=Depends(require_auth)):
    from agentwall.audit.schema import get_session_events
    return get_session_events(session_id)

@app.get("/api/violations")
async def list_violations(limit: int = Query(1000, ge=1, le=1000), auth=Depends(require_auth)):
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
    return app.state.proxy.proxy.causal.export_graph()

@app.get("/api/security-status")
async def security_status(auth=Depends(require_auth)):
    return {
        "authentication_enabled": AUTH_ENABLED,
        "enforcement_mode": "observe" if app.state.proxy.enabled else "enforce",
        "policy_profile": app.state.proxy.proxy._variant,
        "gateway_policy_enforced": True,
    }

@app.get("/metrics")
async def metrics(auth=Depends(require_auth)):
    return PlainTextResponse(MetricsRegistry.get().export())

@app.get("/api/performance")
async def performance(auth=Depends(require_auth)):
    from agentwall.audit.write_queue import DBWriteQueue
    return MetricsRegistry.get().performance(DBWriteQueue.get().queue_size())

UPSTREAM_HOSTS = {
    "api.openai.com": "openai",
    "api.anthropic.com": "anthropic",
    "generativelanguage.googleapis.com": "google",
}

# Universal AI Gateway (OpenAI, Claude, Gemini compatible)
@app.post("/v1/chat/completions")
@app.post("/v1/messages")
@app.post("/v1/proxy/{target_host:path}")
async def universal_gateway(request: Request, target_host: str = "api.openai.com", auth=Depends(require_auth)):
    from agentwall import gateway
    body = await request.json()
    agent_id = request.headers.get("X-AgentWall-Agent", "browser_intercept")
    session_id = request.headers.get("X-AgentWall-Session", f"SESS_{int(time.time())}")

    # Identify protocol. The upstream key is attached to the forwarded request, so the
    # /v1/proxy target host must be a known provider, never caller-chosen (SSRF / key leak).
    host = target_host.split("/", 1)[0].lower()
    if host not in UPSTREAM_HOSTS:
        raise HTTPException(status_code=400, detail="Unsupported upstream host")
    protocol = UPSTREAM_HOSTS[host]
    if request.url.path == "/v1/messages": protocol = "anthropic"
    if body.get("stream") or ":streamGenerateContent" in target_host:
        raise HTTPException(status_code=400, detail="Streaming is not supported: responses could not be checked before the agent acts on them")

    # Request: tool calls in the conversation, then the message text as one synthetic call.
    observe = app.state.proxy.observe
    calls = gateway.request_tool_calls(protocol, body)
    texts = gateway.request_text(protocol, body)
    if texts:
        calls.append(("llm_request", {"messages": texts}))
    blocked = await gateway.check_calls(observe, session_id, agent_id, calls, f"gw_req_{int(time.time())}_")
    if blocked:
        return _gateway_block(blocked)

    api_key = os.getenv("AGENTWALL_UPSTREAM_KEY")
    if not api_key:
        return JSONResponse(status_code=200, content={"message": "AgentWall: Dev Mode Active. No upstream key set."})

    if protocol == "openai":
        url = os.getenv("AGENTWALL_UPSTREAM_URL", "https://api.openai.com/v1/chat/completions")
        headers = {"Authorization": f"Bearer {api_key}"}
    elif protocol == "anthropic":
        url = "https://api.anthropic.com/v1/messages"
        headers = {"x-api-key": api_key,
                   "anthropic-version": request.headers.get("anthropic-version", "2023-06-01")}
    else:
        url = f"https://{target_host}"
        headers = {"x-goog-api-key": api_key}

    status, data = await _forward(url, body, headers)
    if status >= 400 or not isinstance(data, dict):
        return JSONResponse(status_code=status, content=data)

    # Response: tool calls the model wants executed, then sanitise the text it returns.
    blocked = await gateway.check_calls(observe, session_id, agent_id,
                                        gateway.response_tool_calls(protocol, data), f"gw_resp_{int(time.time())}_")
    if blocked:
        return _gateway_block(blocked)
    gateway.sanitise_response(protocol, data, app.state.proxy.proxy.sanitiser.clean)
    return JSONResponse(status_code=status, content=data)


async def _forward(url: str, body: dict, headers: dict):
    import httpx
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, json=body, headers=headers, timeout=60.0)
    is_json = "json" in resp.headers.get("content-type", "")
    return resp.status_code, resp.json() if is_json else resp.text


def _gateway_block(event: dict):
    return JSONResponse(status_code=403, content={"error": {
        "type": "agentwall_blocked", "message": event["reason"], "tool": event["tool_name"],
        "event_id": event["event_id"], "mitre_id": event.get("mitre_id")}})

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
    uvicorn.run(app, host=os.getenv("AGENTWALL_HOST", "127.0.0.1"), port=8000)
