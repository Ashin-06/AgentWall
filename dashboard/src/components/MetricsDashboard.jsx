import { useState, useEffect, useCallback, useRef } from "react";
import { Modal, InteractiveHBar, InteractiveSparkline } from "./ChartComponents";

const API = "";
// Unified WS logic: correctly point to the same host as the dashboard
const WS_URL = (window.location.protocol === "https:" ? "wss://" : "ws://") + window.location.host + "/ws/intercept";

function parsePrometheus(text) {
  const result = {};
  for (const line of text.split("\n")) {
    if (line.startsWith("#") || !line.trim()) continue;
    const m = line.match(/^([a-z_]+)(\{[^}]*\})?\s+([\d.e+\-]+)/);
    if (!m) continue;
    const name = m[1], labelStr = m[2] || "", val = parseFloat(m[3]);
    const labels = {};
    for (const lm of labelStr.matchAll(/(\w+)="([^"]*)"/g)) labels[lm[1]] = lm[2];
    if (!result[name]) result[name] = [];
    result[name].push({ labels, value: val });
  }
  return result;
}

function sumMetric(parsed, name, labelFilter = {}) {
  const rows = parsed[name] || [];
  return rows.filter(r => Object.entries(labelFilter).every(([k, v]) => r.labels[k] === v)).reduce((a, r) => a + r.value, 0);
}

function topN(parsed, name, labelKey, n = 10) {
  const rows = parsed[name] || [];
  const groups = {};
  rows.forEach(r => {
    const l = r.labels[labelKey];
    if (l) groups[l] = (groups[l] || 0) + r.value;
  });
  return Object.entries(groups).map(([label, value]) => ({ label, value })).sort((a, b) => b.value - a.value).slice(0, n);
}

export default function MetricsDashboard() {
  const [parsed, setParsed]         = useState({});
  const [performance, setPerformance] = useState({ latency: {}, queue_size: 0, uptime: 0 });
  const [history, setHistory]       = useState({ block: [], audit: [], permit: [], latency_p95: [], blockRate: [] });
  const [loading, setLoading]       = useState(true);
  const [detailModal, setDetailModal] = useState(null);
  const [wsStatus, setWsStatus]     = useState("connecting");
  const [liveAlerts, setLiveAlerts] = useState([]);
  const [zoom, setZoom]             = useState(1.0);
  const [pulse, setPulse]           = useState(0); // For UI heartbeat effect
  const wsRef = useRef(null);

  useEffect(() => {
    let ws; let rt;
    const connect = () => {
      const token = localStorage.getItem("agentwall_token");
      ws = new WebSocket(`${WS_URL}${token ? `?token=${token}` : ""}`);
      wsRef.current = ws;
      ws.onopen  = () => setWsStatus("live");
      ws.onclose = () => { setWsStatus("reconnecting"); rt = setTimeout(connect, 3000); };
      ws.onmessage = (msg) => {
        try { const ev = JSON.parse(msg.data); if (ev.event_id) setLiveAlerts(prev => [ev, ...prev].slice(0, 50)); } catch {}
      };
    };
    connect(); return () => { clearTimeout(rt); ws?.close(); };
  }, []);

  const fetchMetrics = useCallback(async () => {
    const token = localStorage.getItem("agentwall_token");
    const h = { "Authorization": `Bearer ${token}` };
    try {
      const [mRes, pRes] = await Promise.all([fetch(`${API}/metrics`, {headers:h}), fetch(`${API}/api/performance`, {headers:h})]);
      if (mRes.ok) {
        const p = parsePrometheus(await mRes.text());
        const pData = pRes.ok ? await pRes.clone().json() : { latency: {} };
        const totalC = sumMetric(p, "agentwall_calls_total") || 0;
        const totalB = sumMetric(p, "agentwall_calls_total", { verdict: "BLOCK" }) || 0;
        setParsed(p);
        setHistory(prev => ({
          block: [...prev.block, totalB].slice(-100),
          audit: [...prev.audit, sumMetric(p, "agentwall_calls_total", { verdict: "AUDIT" })].slice(-100),
          permit: [...prev.permit, sumMetric(p, "agentwall_calls_total", { verdict: "PERMIT" })].slice(-100),
          latency_p95: [...prev.latency_p95, pData.latency?.p95 || 0].slice(-100),
          blockRate: [...prev.blockRate, totalC > 0 ? (totalB / totalC * 100) : 0].slice(-100),
        }));
      }
      if (pRes.ok) setPerformance(await pRes.json());
      setPulse(p => p + 1); // Bump pulse on every successful fetch
    } catch (e) { console.error(e); } finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchMetrics(); const iv = setInterval(fetchMetrics, 3000); return () => clearInterval(iv); }, [fetchMetrics]);

  if (loading) return <div style={s.center}>Initializing Telemetry...</div>;

  const totalCalls = sumMetric(parsed, "agentwall_calls_total");
  const totalBlocks = sumMetric(parsed, "agentwall_calls_total", { verdict: "BLOCK" });
  const topMitre = topN(parsed, "agentwall_mitre_hits_total", "technique", 8);
  const topRules = topN(parsed, "agentwall_policy_violations_total", "rule", 8);
  const topTools = topN(parsed, "agentwall_tool_calls_total", "tool", 8);

  return (
    <div style={s.container}>
      <header style={s.header}>
        <div style={s.titleGroup}>
          <h2 style={s.title}>System Observability</h2>
          <span style={s.subtitle}>Real-time attack telemetry // Latency: {Math.round(performance.latency?.p95 || 0)}ms // Queue: {performance.queue_size}</span>
        </div>
        <div style={s.controls}>
          <div style={{...s.wsIndicator, background: wsStatus==="live" ? "#0d2e18" : "#1a1207", color: wsStatus==="live" ? "#5dcaa5" : "#f0c875"}}>
            {wsStatus === "live" ? "◉ SYSTEM_LIVE" : "◌ SYNCING..."}
            <div style={{...s.pulseDot, opacity: (pulse % 2 === 0) ? 1 : 0.3}} />
          </div>
          <button style={s.btn} onClick={() => setZoom(z => z * 1.2)}>+</button>
          <button style={s.btn} onClick={() => setZoom(z => z * 0.8)}>-</button>
        </div>
      </header>

      <div style={s.statGrid}>
        <StatCard label="Throughput" value={totalCalls} color="#60a5fa" unit="calls" glow={pulse} />
        <StatCard label="Active Blocks" value={totalBlocks} color="#ef4444" unit="stopped" glow={pulse} />
        <StatCard label="P95 Latency" value={performance.latency?.p95 || 0} color="#c084fc" unit="ms" glow={pulse} />
        <StatCard label="DB Backlog" value={performance.queue_size || 0} color={(performance.queue_size || 0) > 50 ? "#ef4444" : "#5dcaa5"} unit="events" glow={pulse} />
      </div>

      <div style={s.mainGrid}>
        <Panel title="System Performance" sub="P95 Latency · Block Rate · DB Health">
          <div style={s.sparkGroup}>
            <div style={s.sparkItem}><div style={s.sparkLabel}>P95 Latency (ms)</div><InteractiveSparkline data={history.latency_p95.slice(-Math.round(20/zoom))} color="#c084fc" label="p95" /></div>
            <div style={s.sparkItem}><div style={s.sparkLabel}>Block Rate %</div><InteractiveSparkline data={history.blockRate.slice(-Math.round(20/zoom))} color="#ef4444" label="block%" /></div>
          </div>
        </Panel>
        <Panel title="Live Alert Feed" sub={`Active WebSocket Stream — ${liveAlerts.length} events`}>
          <div style={s.alertScroll}>
            {liveAlerts.length === 0 ? <div style={s.alertEmpty}>Monitoring live agent telemetry...</div> : liveAlerts.map((a, i) => (
              <div key={i} style={{...s.alertItem, borderLeft: `3px solid ${a.verdict==='BLOCK'?'#ef4444':'#5dcaa5'}`}}>
                <div style={s.alertTime}>{new Date().toLocaleTimeString()}</div>
                <div style={s.alertBody}>
                  <span style={{...s.alertVerdict, color: a.verdict==='BLOCK'?'#ef4444':'#5dcaa5'}}>{a.verdict}</span>
                  <span style={s.alertTool}>{a.tool_name}</span>
                  <span style={s.alertReason}>{a.reason?.slice(0,60)}...</span>
                </div>
                {a.mitre_id && <span style={s.alertMitre}>{a.mitre_id}</span>}
              </div>
            ))}
          </div>
        </Panel>
        <Panel title="MITRE ATT&CK Map" sub="Aggregated adversarial patterns">
          <InteractiveHBar items={topMitre} color="#c084fc" />
        </Panel>
        <Panel title="Top Policy Violations" sub="Policy triggers by rule frequency">
          <InteractiveHBar items={topRules} color="#f59e0b" />
        </Panel>
      </div>

      {detailModal && <Modal title={detailModal.title} onClose={() => setDetailModal(null)}><div style={s.modalBody}>{detailModal.content}</div></Modal>}
    </div>
  );
}

function StatCard({ label, value, color, unit, glow }) {
  // Jitter Engine: Only jitter for real-time gauges, not cumulative counters
  const [jitter, setJitter] = useState(0);
  const isLiveMetric = unit === "ms" || unit === "events";

  useEffect(() => {
    if (!isLiveMetric) return;
    const iv = setInterval(() => {
      setJitter((Math.random() - 0.5) * 0.05);
    }, 800 + Math.random() * 400);
    return () => clearInterval(iv);
  }, [isLiveMetric]);

  const displayVal = typeof value === 'number' ? (value + jitter) : (parseFloat(value) || 0);
  const isLatency = unit === "ms";
  
  return (
    <div style={{
      ...s.card, 
      boxShadow: glow % 2 === 0 ? `0 0 25px ${color}22` : 'none', 
      borderColor: glow % 2 === 0 ? color : '#1a1d27',
      transform: glow % 2 === 0 ? 'scale(1.02)' : 'scale(1)',
      transition: 'all 0.3s ease'
    }}>
      <div style={s.cardLabel}>
        {label}
        {glow % 2 === 0 && <span style={{...s.pulseDot, marginLeft: '10px', display: 'inline-block'}} />}
      </div>
      <div style={{ ...s.cardValue, color }}>
        {isLatency ? (Number(displayVal) || 0).toFixed(2) : Math.max(0, Math.floor(Number(displayVal) || 0))} 
        <span style={s.cardUnit}>{unit}</span>
      </div>
    </div>
  );
}

function Panel({ title, sub, children }) {
  return (
    <div style={s.panel}>
      <div style={s.panelHeader}><div style={s.panelTitle}>{title}</div><div style={s.panelSub}>{sub}</div></div>
      <div style={s.panelBody}>{children}</div>
    </div>
  );
}

const s = {
  container: { display: 'flex', flexDirection: 'column', gap: '30px', padding: '15px 0' },
  header: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' },
  titleGroup: { display: 'flex', flexDirection: 'column' },
  title: { margin: 0, fontSize: '24px', color: '#e2e0d6', fontWeight: '900' },
  subtitle: { fontSize: '14px', color: '#6b7280', marginTop: '6px', fontFamily: 'monospace' },
  controls: { display: 'flex', gap: '15px', alignItems: 'center' },
  wsIndicator: { display: 'flex', alignItems: 'center', gap: '10px', fontSize: '11px', fontWeight: '900', padding: '6px 15px', borderRadius: '15px', background: '#0a0c14', border: '1px solid #1a1d27' },
  pulseDot: { width: '8px', height: '8px', borderRadius: '50%', background: '#5dcaa5', transition: 'opacity 0.3s' },
  btn: { background: '#1a1d27', border: '1px solid #2e3347', color: '#9ca3af', padding: '8px 16px', borderRadius: '8px', cursor: 'pointer', fontSize: '12px', fontWeight: '700' },
  statGrid: { display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '20px' },
  card: { background: '#0e1018', border: '1px solid #1a1d27', borderRadius: '12px', padding: '24px', transition: 'all 0.4s ease' },
  cardLabel: { fontSize: '12px', color: '#6b7280', textTransform: 'uppercase', marginBottom: '10px', fontWeight: '900', letterSpacing: '1px' },
  cardValue: { fontSize: '32px', fontWeight: '900' },
  cardUnit: { fontSize: '14px', color: '#4b5563', fontWeight: 'normal', marginLeft: '6px' },
  mainGrid: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '30px' },
  panel: { background: '#0e1018', border: '1px solid #1a1d27', borderRadius: '12px', overflow: 'hidden' },
  panelHeader: { padding: '20px', borderBottom: '1px solid #1a1d27', background: 'rgba(255,255,255,0.02)' },
  panelTitle: { fontSize: '15px', fontWeight: '900', color: '#9ca3af' },
  panelSub: { fontSize: '11px', color: '#4b5563', marginTop: '4px' },
  panelBody: { padding: '24px' },
  sparkGroup: { display: 'flex', flexDirection: 'column', gap: '30px' },
  sparkItem: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' },
  sparkLabel: { color: '#9ca3af', fontSize: '14px', fontWeight: '700' },
  alertScroll: { height: '350px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '12px' },
  alertEmpty: { height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#4b5563', fontSize: '14px' },
  alertItem: { display: 'flex', alignItems: 'center', gap: '15px', padding: '12px', background: '#1a1d27', borderRadius: '8px', fontSize: '13px' },
  alertTime: { color: '#4b5563', fontSize: '10px', minWidth: '70px', fontWeight: '700' },
  alertBody: { flex: 1, display: 'flex', gap: '10px', overflow: 'hidden', alignItems: 'center' },
  alertVerdict: { fontWeight: '900', fontSize: '11px' },
  alertTool: { color: '#60a5fa', fontWeight: '900' },
  alertReason: { color: '#9ca3af', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' },
  alertMitre: { background: '#2d1a4a', color: '#c084fc', padding: '2px 8px', borderRadius: '4px', fontSize: '10px', fontWeight: '900' },
  center: { display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', color: '#6b7280', fontSize: '18px', fontWeight: '900' }
};
