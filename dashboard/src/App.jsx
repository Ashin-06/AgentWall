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
  const wsRef = useRef(null);

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

  const handleLogout = () => {
    setToken(null);
    localStorage.removeItem("agentwall_token");
  };

  // ── WebSocket for real-time alerts ──────────────────────────────────────
  useEffect(() => {
    if (!token) return;
    const ws = createWSClient(WS, {
      token,
      onOpen:    ()    => { setWSStatus("connected"); ws.send({type:"subscribe"}); },
      onClose:   ()    => setWSStatus("disconnected"),
      onMessage: (msg) => {
        if (msg.type === "alert") {
          setAlerts(prev => [msg.event, ...prev].slice(0, 100));
        }
      },
    });
    wsRef.current = ws;
    return () => ws.close();
  }, [token]);

  // ── REST polling ────────────────────────────────────────────────────────
  const refresh = useCallback(async () => {
    if (!token) return;
    const headers = { "Authorization": `Bearer ${token}` };
    
    // Split fetches: Core metrics (fast) vs Graph data (heavy)
    const coreFetches = [
      fetch(`${API}/api/sessions?limit=1000`, {headers}).then(r=>r.ok?r.json():[]).catch(()=>[]),
      fetch(`${API}/api/violations?limit=1000`, {headers}).then(r=>r.ok?r.json():[]).catch(()=>[]),
      fetch(`${API}/api/risk-scores`, {headers}).then(r=>r.ok?r.json():[]).catch(()=>[]),
      fetch(`${API}/api/campaigns`, {headers}).then(r=>r.ok?r.json():[]).catch(()=>[]),
      fetch(`${API}/api/mitre-heatmap`, {headers}).then(r=>r.ok?r.json():[]).catch(()=>[]),
    ];

    if (tab === "graph") {
      coreFetches.push(fetch(`${API}/api/attack-graph`, {headers}).then(r=>r.ok?r.json():{}).catch(()=>({})));
    }

    const results = await Promise.all(coreFetches);
    const [s, v, r, c, m, g] = results;
    
    if (results.some(x => x?.detail === "Invalid or expired token")) {
      handleLogout();
      return;
    }

    setSessions(s); setViolations(v); setRiskScores(r);
    setCampaigns(c); setMitreData(m); 
    if (g) setGraphData(g);
  }, [token, tab]);

  useEffect(() => { 
    refresh(); 
    const iv = setInterval(refresh, 10000); 
    return ()=>clearInterval(iv); 
  }, [refresh]);

  const openSession = async (sid) => {
    setActive(sid);
    const headers = { "Authorization": `Bearer ${token}` };
    const events = await fetch(`${API}/api/sessions/${sid}`, {headers}).then(r=>r.json()).catch(()=>[]);
    setReplay(events);
    setTab("replay");
  };

  if (!token) {
    return <Login onLogin={handleLogin} />;
  }

  const sessions_safe = Array.isArray(sessions) ? sessions : [];
  const violations_safe = Array.isArray(violations) ? violations : [];
  const campaigns_safe = Array.isArray(campaigns) ? campaigns : [];

  const uniqueAgents = Array.from(new Set(sessions_safe.map(s => (s.agent_id || "unknown").trim())));
  const filteredSessions = filterAgent ? sessions_safe.filter(s => (s.agent_id || "unknown").trim() === filterAgent) : sessions_safe;
  const filteredViolations = filterAgent ? violations_safe.filter(v => (v.agent_id || "unknown").trim() === filterAgent) : violations_safe;

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
        <div style={s.headerStats}>
          <Stat label="Live Sessions" value={sessions_safe.length}  color="#60a5fa" />
          <Stat label="Total Blocked" value={totalBlocks}      color="#f09999" pulse={totalBlocks > 0} />
          <Stat label="Risk Level"    value={activeCampaigns > 0 ? "HIGH" : "SAFE"} color={activeCampaigns > 0 ? "#fb923c" : "#5dcaa5"} pulse={activeCampaigns > 0} />
          <Stat label="Campaigns"     value={activeCampaigns}  color="#c084fc" />
        </div>
        <nav style={s.nav}>
          {["overview","replay","graph","mitre","campaigns","metrics"].map(t => (
            <button key={t} onClick={()=>setTab(t)}
              style={{...s.navBtn, ...(tab===t ? s.navActive : {}),
                      ...(t==="metrics" ? {borderColor:"#5dcaa5", color: tab==="metrics"?"#5dcaa5":"#5dcaa550"} : {})}}>
              {t === "metrics" ? "Metrics" : t.charAt(0).toUpperCase()+t.slice(1)}
            </button>
          ))}
        </nav>
      </header>

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
      <div style={s.content}>
        {tab === "overview" && (
          <div style={s.overviewGrid}>
            <div style={s.agentSidebar}>
               <h3 style={s.sidebarTitle}>Agent Intelligence</h3>
               <button onClick={() => setFilterAgent(null)} style={{...s.agentItem, ...(filterAgent === null ? s.agentActive : {})}}>
                  All Agents <span style={s.agentCount}>{sessions_safe.length}</span>
               </button>
               {uniqueAgents.map(a => (
                 <button key={a} onClick={() => setFilterAgent(a)} style={{...s.agentItem, ...(filterAgent === a ? s.agentActive : {})}}>
                    {a} <span style={s.agentCount}>{sessions_safe.filter(s => s.agent_id === a).length}</span>
                 </button>
               ))}
            </div>
            <div><RiskScore scores={riskScores} /></div>
            <div><PolicyViolations violations={filteredViolations} /></div>
            <div><SessionList sessions={filteredSessions} onSelect={openSession} activeSession={activeSession} /></div>
          </div>
        )}
        {tab === "replay" && (
          <SessionReplay events={replayEvents} sessionId={activeSession} apiBase={API} />
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
          <MetricsDashboard />
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
