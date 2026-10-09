import { useState, useEffect, useRef, useCallback } from "react";
import SessionList from "./components/SessionList";
import RiskScore from "./components/RiskScore";
import SessionReplay from "./components/SessionReplay";
import PolicyViolations from "./components/PolicyViolations";
import AttackGraph from "./components/AttackGraph";
import MitreHeatmap from "./components/MitreHeatmap";
import CampaignTimeline from "./components/CampaignTimeline";
import MetricsDashboard from "./components/MetricsDashboard";
import { createWSClient } from "./ws";
import Login from "./components/Login";
import { fetchJSON, agentName, filterSessions } from "./api.mjs";
import "./dashboard.css";

const API = "";
const WS  = (window.location.protocol === "https:" ? "wss://" : "ws://") + window.location.host + "/ws/intercept";

export default function App() {
  const [token, setToken]       = useState(localStorage.getItem("agentwall_token"));
  const [tab, setTab]           = useState("overview");
  const [sessions, setSessions] = useState([]);
  const [violations, setViolations] = useState([]);
  const [riskScores, setRiskScores] = useState([]);
  const [campaigns, setCampaigns]   = useState([]);
  const [mitreData, setMitreData]   = useState([]);
  const [graphData, setGraphData]   = useState({});
  const [activeSession, setActive]  = useState(null);
  const [replayEvents, setReplay]   = useState([]);
  const [alerts, setAlerts]         = useState([]);
  const [wsStatus, setWSStatus]     = useState("connecting");
  const refreshController = useRef(null);
  const replayController = useRef(null);
  const [query, setQuery] = useState("");
  const [paused, setPaused] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [error, setError] = useState("");
  const [replayLoading, setReplayLoading] = useState(false);
  const [replayError, setReplayError] = useState("");
  const [securityStatus, setSecurityStatus] = useState(null);

  const [filterAgent, setFilterAgent] = useState(null);

  // ── Auth Handling ────────────────────────────────────────────────────────
  const handleLogin = async (password) => {
    const res = await fetch(`${API}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password })
    });
    if (!res.ok) throw new Error("Unauthorized");
    const { token } = await res.json();
    setToken(token);
    localStorage.setItem("agentwall_token", token);
  };

  const handleLogout = useCallback(() => {
    refreshController.current?.abort();
    replayController.current?.abort();
    setSessions([]); setViolations([]); setRiskScores([]);
    setCampaigns([]); setMitreData([]); setGraphData({});
    setReplay([]); setActive(null); setAlerts([]); setLastUpdated(null);
    setError(""); setReplayError(""); setQuery(""); setFilterAgent(null);
    setRefreshing(false); setReplayLoading(false); setPaused(false);
    setSecurityStatus(null);
    setTab("overview");
    setToken(null);
    localStorage.removeItem("agentwall_token");
  }, []);

  // ── WebSocket for real-time alerts ──────────────────────────────────────
  useEffect(() => {
    if (!token) return;
    setWSStatus("connecting");
    const ws = createWSClient(WS, {
      token,
      onOpen:    ()    => { setWSStatus("connected"); ws.send({type:"subscribe"}); },
      onClose:   ()    => setWSStatus("disconnected"),
      onMessage: (msg) => {
        if (msg.type === "alert" && msg.event) {
          setAlerts(prev => [msg.event, ...prev].slice(0, 100));
        }
      },
    });

    return () => ws.close();
  }, [token]);

  // ── REST polling ────────────────────────────────────────────────────────
  const refresh = useCallback(async () => {
    if (!token) return;
    refreshController.current?.abort();
    const controller = new AbortController();
    refreshController.current = controller;
    setRefreshing(true);
    const paths = ["sessions?limit=1000", "violations?limit=1000", "risk-scores", "campaigns", "mitre-heatmap", "security-status"];
    if (tab === "graph") paths.push("attack-graph");
    try {
      const results = await Promise.all(paths.map(path => fetchJSON(`${API}/api/${path}`, token, controller.signal)));
      if (controller.signal.aborted) return;
      if (!results.slice(0, 5).every(Array.isArray)) throw new Error("Unexpected server data. Please retry.");
      const [s, v, r, c, m, status, g] = results;
      setSessions(s); setViolations(v); setRiskScores(r);
      setCampaigns(c); setMitreData(m);
      setSecurityStatus(status);
      if (g) setGraphData(g);
      setLastUpdated(new Date()); setError("");
    } catch (err) {
      if (controller.signal.aborted) return;
      if (err.status === 401) handleLogout();
      else setError(`${err.message} Showing the last successfully loaded data.`);
    } finally {
      if (!controller.signal.aborted) setRefreshing(false);
    }
  }, [token, tab, handleLogout]);

  useEffect(() => {
    refresh();
    return () => refreshController.current?.abort();
  }, [refresh]);

  useEffect(() => {
    if (paused) return;
    const iv = setInterval(refresh, 10000);
    return () => clearInterval(iv);
  }, [refresh, paused]);

  useEffect(() => () => replayController.current?.abort(), []);

  const openSession = async (sid) => {
    replayController.current?.abort();
    const controller = new AbortController();
    replayController.current = controller;
    setActive(sid); setReplay([]); setReplayError(""); setReplayLoading(true); setTab("replay");
    try {
      const events = await fetchJSON(`${API}/api/sessions/${encodeURIComponent(sid)}`, token, controller.signal);
      if (controller.signal.aborted) return;
      if (!Array.isArray(events)) throw new Error("Unexpected session data.");
      setReplay(events);
    } catch (err) {
      if (controller.signal.aborted) return;
      if (err.status === 401) handleLogout();
      else setReplayError(err.message);
    } finally {
      if (!controller.signal.aborted) setReplayLoading(false);
    }
  };

  if (!token) {
    return <Login onLogin={handleLogin} />;
  }

  const sessions_safe = Array.isArray(sessions) ? sessions : [];
  const violations_safe = Array.isArray(violations) ? violations : [];
  const campaigns_safe = Array.isArray(campaigns) ? campaigns : [];

  const uniqueAgents = Array.from(new Set(sessions_safe.map(s => agentName(s))));
  const filteredSessions = filterSessions(sessions_safe, filterAgent, query);
  const filteredViolations = filterAgent ? violations_safe.filter(v => agentName(v) === filterAgent) : violations_safe;

  const totalBlocks = violations_safe.filter(v=>v.verdict==="BLOCK").length;
  const totalAudits = violations_safe.filter(v=>v.verdict==="AUDIT").length;
  const activeCampaigns = campaigns_safe.filter(c=>c.is_active).length;

  return (
    <div style={s.app}>
      <header style={s.header}>
        <div style={s.logoArea}>
          <img src="/assets/logo.png" style={s.logoImg} alt="AgentWall" />
          <div>
            <div style={s.brand}>AgentWall</div>
            <div style={s.tagline}>Intelligent AI Security</div>
          </div>
          <div style={{...s.wsIndicator, background: wsStatus==="connected" ? "#5dcaa5" : "#f09999"}}>
            {wsStatus}
          </div>
        </div>
        <div className="dashboard-stats" style={s.headerStats}>
          <Stat label="Live Sessions" value={sessions_safe.length}  color="#60a5fa" />
          <Stat label="Total Blocked" value={totalBlocks}      color="#f09999" pulse={totalBlocks > 0} />
          <Stat label="Risk Level"    value={!lastUpdated || error ? "UNKNOWN" : activeCampaigns > 0 ? "HIGH" : "SAFE"} color={activeCampaigns > 0 ? "#fb923c" : "#5dcaa5"} pulse={activeCampaigns > 0} />
          <Stat label="Campaigns"     value={activeCampaigns}  color="#c084fc" />
        </div>
        <nav className="dashboard-nav" aria-label="Dashboard sections" style={s.nav}>
          {["overview","replay","graph","mitre","campaigns","metrics"].map(t => (
            <button key={t} aria-current={tab === t ? "page" : undefined} onClick={()=>setTab(t)}
              style={{...s.navBtn, ...(tab===t ? s.navActive : {}),
                      ...(t==="metrics" ? {borderColor:"#5dcaa5", color: tab==="metrics"?"#5dcaa5":"#5dcaa550"} : {})}}>
              {t === "metrics" ? "Metrics" : t.charAt(0).toUpperCase()+t.slice(1)}
            </button>
          ))}
        </nav>
      </header>

      <div className="dashboard-toolbar">
        <input aria-label="Search sessions" placeholder="Search sessions by agent or session ID" value={query} onChange={e => { setQuery(e.target.value); setTab("overview"); }} />
        <button onClick={refresh} disabled={refreshing}>{refreshing ? "Refreshing…" : "Refresh now"}</button>
        <button aria-pressed={paused} onClick={() => setPaused(p => !p)}>{paused ? "Resume auto-refresh" : "Pause auto-refresh"}</button>
        <span role="status">{lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString()}` : "Waiting for data"}{paused ? " · Overview polling paused; live alerts continue" : " · Overview refreshes every 10 seconds"}</span>
        <button onClick={handleLogout}>Sign out</button>
      </div>
      {error && <div className="dashboard-error" role="alert">{error}</div>}
      {securityStatus && <div className="dashboard-toolbar" role="status">
        <span>Tool-call policy: <strong>{error ? "Status unavailable" : securityStatus.enforcement_mode === "enforce" ? "Enforcement enabled" : "Observe only — calls are not blocked"}</strong></span>
        <span>Authentication: {securityStatus.authentication_enabled ? "Enabled" : "Disabled"}</span>
        <span>Profile: {securityStatus.policy_profile}</span>
        {!securityStatus.gateway_policy_enforced && <span>LLM gateway: monitoring only</span>}
      </div>}
      {/* Real-time alert strip */}
      {alerts.length > 0 && (
        <div style={s.alertStrip}>
          <span style={{color: "#f09999", marginRight: "8px"}}>⚡ LIVE:</span>
          <span style={s.alertText}>
            {alerts[0].verdict} — {alerts[0].tool_name} — {alerts[0].reason?.slice(0,80)}
            {alerts[0].mitre_id && <span style={s.mitreBadge}>{alerts[0].mitre_id}</span>}
          </span>
          <span style={s.alertCount}>+{alerts.length-1} more</span>
        </div>
      )}

      {/* Tab content */}
      <div className="dashboard-content" style={s.content}>
        {tab === "overview" && (
          <div className="overview-grid" style={s.overviewGrid}>
            <div style={s.agentSidebar}>
               <h3 style={s.sidebarTitle}>Agent Intelligence</h3>
               <button onClick={() => setFilterAgent(null)} style={{...s.agentItem, ...(filterAgent === null ? s.agentActive : {})}}>
                  All Agents <span style={s.agentCount}>{sessions_safe.length}</span>
               </button>
               {uniqueAgents.map(a => (
                 <button key={a} onClick={() => setFilterAgent(a)} style={{...s.agentItem, ...(filterAgent === a ? s.agentActive : {})}}>
                    {a} <span style={s.agentCount}>{sessions_safe.filter(s => agentName(s) === a).length}</span>
                 </button>
               ))}
            </div>
            <div><RiskScore scores={riskScores} /></div>
            <div><PolicyViolations violations={filteredViolations} /></div>
            <div><SessionList sessions={filteredSessions} onSelect={openSession} activeSession={activeSession} /></div>
          </div>
        )}
        {tab === "replay" && (
          replayLoading ? <p role="status">Loading session events…</p> : replayError ? <div role="alert">{replayError} <button onClick={() => openSession(activeSession)}>Retry</button></div> : <SessionReplay key={activeSession} events={replayEvents} sessionId={activeSession} apiBase={API} />
        )}
        {tab === "graph" && (
          <AttackGraph data={graphData} />
        )}
        {tab === "mitre" && (
          <MitreHeatmap data={mitreData} />
        )}
        {tab === "campaigns" && (
          <CampaignTimeline campaigns={campaigns_safe} />
        )}
        {tab === "metrics" && (
          <MetricsDashboard token={token} onUnauthorized={handleLogout} />
        )}
      </div>
    </div>
  );
}

function Stat({ label, value, color, pulse }) {
  return (
    <div style={{...s.stat, ...(pulse ? s.pulse : {})}}>
      <span style={{...s.statValue, color}}>{value}</span>
      <span style={s.statLabel}>{label}</span>
    </div>
  );
}

const s = {
  app: { background: "#0a0c14", minHeight: "100vh", color: "#e2e0d6",
         fontFamily: "'JetBrains Mono', monospace", fontSize: "15px" },
  header: { display: "flex", alignItems: "center", justifyContent: "space-between",
             padding: "15px 30px", borderBottom: "1px solid #1a1d27",
             background: "#0e1018", gap: "20px", flexWrap: "wrap" },
  logoArea:  { display: "flex", alignItems: "center", gap: "12px" },
  logoImg:   { width: "32px", height: "32px", borderRadius: "6px" },
  brand:     { fontSize: "18px", fontWeight: "900", color: "#e2e0d6", letterSpacing: "-0.5px" },
  version: { color: "#3d4052", fontSize: "12px" },
  wsIndicator: { padding: "4px 12px", borderRadius: "12px", fontSize: "11px",
                  color: "#0a0c14", fontWeight: "900" },
  headerStats: { display: "flex", gap: "48px", marginLeft: "auto", marginRight: "48px" },
  stat:      { display: "flex", flexDirection: "column", alignItems: "center", minWidth: "100px" },
  statValue: { fontSize: "28px", fontWeight: "900", letterSpacing: "-1px" },
  statLabel: { fontSize: "11px", color: "#4b5563", textTransform: "uppercase", fontWeight: "900", marginTop: "4px" },
  pulse:     { animation: "pulse 1.5s infinite" },
  nav: { display: "flex", gap: "10px", background: "#0a0c14", padding: "6px", borderRadius: "10px", border: "1px solid #1a1d27" },
  navBtn: { background: "none", border: "none", color: "#4b5563",
             padding: "8px 24px", borderRadius: "8px", cursor: "pointer",
             fontSize: "14px", fontFamily: "inherit", fontWeight: "800", transition: "all 0.2s" },
  navActive: { background: "#1a1d27", color: "#e2e0d6", boxShadow: "0 4px 15px rgba(0,0,0,0.5)" },
  alertStrip: { background: "#0e1018", borderBottom: "1px solid #1a1d27",
                 padding: "10px 30px", display: "flex", alignItems: "center", gap: "15px", height: "44px" },
  alertText:  { flex: 1, color: "#f0c875", overflow: "hidden", textOverflow: "ellipsis",
                 whiteSpace: "nowrap", fontSize: "13px", fontWeight: "600" },
  alertCount: { color: "#3d4052", fontSize: "11px", fontWeight: "900" },
  mitreBadge: { marginLeft: "10px", padding: "2px 8px", background: "#2d1a4a",
                 border: "1px solid #7c3aed", color: "#c084fc", borderRadius: "4px",
                 fontSize: "10px", fontWeight: "900" },
  content: { padding: "30px", overflow: "auto", height: "calc(100vh - 120px)", background: "radial-gradient(circle at 50% 0%, #11141d 0%, #0a0c14 100%)" },
  overviewGrid: { display: "grid", gridTemplateColumns: "220px 1fr 1.2fr 0.8fr", gap: "30px", height: "100%" },
  agentSidebar: { background: "#0e1018", border: "1px solid #1a1d27", borderRadius: "12px", padding: "20px", display: "flex", flexDirection: "column", gap: "10px" },
  sidebarTitle: { fontSize: "14px", fontWeight: "900", color: "#5dcaa5", textTransform: "uppercase", marginBottom: "15px", letterSpacing: "1px" },
  agentItem: { background: "none", border: "1px solid #1a1d27", color: "#9ca3af", padding: "12px 16px", borderRadius: "8px", cursor: "pointer", 
                textAlign: "left", fontSize: "13px", fontWeight: "700", display: "flex", justifyContent: "space-between", alignItems: "center", transition: "all 0.2s" },
  agentActive: { background: "#1a1d27", borderColor: "#5dcaa5", color: "#e2e0d6", boxShadow: "0 0 15px #5dcaa522" },
  agentCount: { background: "#0a0c14", padding: "2px 8px", borderRadius: "6px", fontSize: "10px", color: "#4b5563" },
};
