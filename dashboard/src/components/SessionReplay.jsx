import { useState, useEffect } from "react";

const VERDICT_COLOR = { 
  BLOCK: "#f09999", 
  AUDIT: "#f0c875", 
  PERMIT: "#5dcaa5", 
  SANITISE: "#60a5fa",
  PAUSE_HITL: "#c084fc",
  SANDBOX: "#fb923c"
};

/**
 * Forensic Session Export
 * Note: The chain_hash fields are generated server-side using HMAC-SHA256
 * and can be verified using the secret key at /api/audit/verify.
 */
function exportForensicJSON(sessionId, events) {
  const bundle = {
    session_id: sessionId,
    exported_at: new Date().toISOString(),
    verification_info: "Log integrity can be verified via server-side HMAC validation (chain_hash).",
    summary: {
        total_events: events.length,
        blocks: events.filter(e => e.verdict === "BLOCK").length,
        mitre_techniques: [...new Set(events.map(e => e.mitre_id).filter(Boolean))],
    },
    events,
  };
  const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `agentwall-forensics-${sessionId?.slice(0, 8)}-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

export default function SessionReplay({ events, sessionId }) {
  const [selectedIdx, setSelectedIdx] = useState(0);
  const events_safe = Array.isArray(events) ? events : [];
  const selectedEvent = (events_safe.length > 0) ? events_safe[selectedIdx] : null;

  // Keyboard navigation (Issue 5)
  useEffect(() => {
    const handler = (e) => {
      if (!events_safe.length) return;
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setSelectedIdx(i => Math.min(i + 1, events_safe.length - 1));
      }
      if (e.key === "ArrowUp") {
        e.preventDefault();
        setSelectedIdx(i => Math.max(i - 1, 0));
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [events_safe]);

  // Auto-scroll to selected event in timeline
  useEffect(() => {
    if (selectedEvent) {
      const el = document.getElementById(`ev-${selectedIdx}`);
      if (el) el.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }, [selectedIdx, selectedEvent]);

  if (!sessionId) return (
    <div style={s.empty}>
      <div style={{ fontSize: 32 }}>📁</div>
      <p style={{ color: "#4b5563", marginTop: 10 }}>Select a session from the list to begin forensic playback.</p>
    </div>
  );

  if (events_safe.length === 0) return (
    <div style={s.empty}>
      <div style={{ fontSize: 32 }}>⏳</div>
      <p style={{ color: "#4b5563", marginTop: 10 }}>No events recorded for this session yet.</p>
    </div>
  );

  const blockCount   = events_safe.filter(e => e.verdict === "BLOCK").length;
  const auditCount   = events_safe.filter(e => e.verdict === "AUDIT").length;
  const mitreIds     = [...new Set(events_safe.map(e => e.mitre_id).filter(Boolean))];
  const riskScore    = Math.min(100, Math.round((blockCount * 5 + auditCount) / (events_safe.length || 1) * 100));

  return (
    <div style={s.container}>
      <header style={s.header}>
        <div style={s.sessionInfo}>
          <h3 style={s.title}>Forensic Playback</h3>
          <span style={s.sid}>Session: {sessionId}</span>
        </div>
        <div style={s.headerRight}>
          <div style={s.pills}>
            <span style={s.pill}>{events_safe.length} events</span>
            <span style={{ ...s.pill, color: "#f09999" }}>{blockCount} blocked</span>
            <span style={{ ...s.pill, color: "#c084fc" }}>Risk {riskScore}%</span>
          </div>
          <button style={s.exportBtn} onClick={() => exportForensicJSON(sessionId, events_safe)} title="Download raw session data with HMAC chains">
            ⬇ Export Forensics
          </button>
        </div>
      </header>

      {/* Risk Timeline Minimap (Issue 4) */}
      <div style={s.minimap}>
        {events_safe.map((ev, i) => (
          <div
            key={i}
            title={`${ev.tool_name} → ${ev.verdict}`}
            onClick={() => setSelectedIdx(i)}
            style={{
              ...s.minimapBar,
              background: VERDICT_COLOR[ev.verdict] || "#2e3347",
              opacity: selectedIdx === i ? 1 : 0.4,
              transform: selectedIdx === i ? "scaleY(1.6)" : "scaleY(1)",
              border: selectedIdx === i ? "1px solid #fff" : "none"
            }}
          />
        ))}
      </div>

      <div style={s.hint}>↑ ↓ arrow keys to step · Click minimap to jump</div>

      <div style={s.main}>
        {/* Timeline list */}
        <div style={s.timeline}>
          {events_safe.map((event, idx) => (
            <div
              key={idx}
              id={`ev-${idx}`}
              style={{
                ...s.eventCard,
                backgroundColor: selectedIdx === idx ? "#1a1d27" : "#0e1018",
                borderColor: selectedIdx === idx
                  ? (VERDICT_COLOR[event.verdict] || "#2e3347")
                  : "#1a1d27",
              }}
              onClick={() => setSelectedIdx(idx)}
            >
              <div style={s.eventTime}>{event.ts ? new Date(event.ts * 1000).toLocaleTimeString() : "00:00:00"}</div>
              <div style={s.eventCore}>
                <div style={s.eventTool}>{event.tool_name}</div>
                <div style={{ ...s.eventVerdict, color: VERDICT_COLOR[event.verdict] || "#9ca3af" }}>
                  {event.verdict}
                </div>
              </div>
              {event.mitre_id && <span style={s.miniMitre}>{event.mitre_id}</span>}
              <div style={s.eventReason}>{(event.reason || "").slice(0, 60)}...</div>
            </div>
          ))}
        </div>

        {/* Detail inspector */}
        <div style={s.detail}>
          {selectedEvent ? (
            <div style={s.inspector}>
              <div style={s.insHeader}>
                <h4 style={{ margin: 0, color: "#e2e0d6" }}>Event Detail</h4>
                <div style={s.insBadges}>
                  {selectedEvent.mitre_id && <span style={s.mitreBadge}>{selectedEvent.mitre_id}</span>}
                  <span style={{ ...s.pill, color: VERDICT_COLOR[selectedEvent.verdict] }}>{selectedEvent.verdict}</span>
                </div>
              </div>

              <Section label="Input Arguments">
                <Code>
                   {JSON.stringify(selectedEvent.arguments || {}, null, 2)}
                </Code>
              </Section>

              <Section label="Security Reasoning">
                <p style={s.rationale}>{selectedEvent.reason}</p>
                <div style={s.detailsGrid}>
                    <InfoTile label="Technique" value={selectedEvent.mitre_id || "N/A"} />
                    <InfoTile label="Latency"   value={`${typeof selectedEvent.latency_ms === "number" ? selectedEvent.latency_ms.toFixed(1) : "?"}ms`} />
                </div>
              </Section>

              {selectedEvent.details?.injection && (
                <Section label="Semantic Guard Analytics">
                   <div style={s.detailsGrid}>
                      <ScoreTile label="Injection Confidence" value={selectedEvent.details.injection.score} threshold={0.7} />
                      <InfoTile  label="LLM Rationale" value={selectedEvent.details.injection.reasoning} />
                   </div>
                </Section>
              )}

              <Section label="Forensic Chain Hash">
                 <div style={{fontSize: 9, color: "#4b5563", fontFamily: "monospace", wordBreak: "break-all", background: "#070910", padding: 8, borderRadius: 4}}>
                    {selectedEvent.chain_hash || "NULL (Chain verification pending)"}
                 </div>
              </Section>
            </div>
          ) : (
            <div style={s.selectHint}>Select an event to inspect forensic details</div>
          )}
        </div>
      </div>
    </div>
  );
}

function Section({ label, children }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ fontSize: 10, color: "#4b5563", textTransform: "uppercase", letterSpacing: "0.5px" }}>{label}</div>
      {children}
    </div>
  );
}

function Code({ children }) {
  return <pre style={{ background: "#0e1018", padding: 16, borderRadius: 8, border: "1px solid #1a1d27", color: "#5dcaa5", fontSize: 11, overflowX: "auto" }}>{children}</pre>;
}

function ScoreTile({ label, value, threshold }) {
  const v = value ?? 0;
  const isDanger = v >= threshold;
  return (
    <div style={{ background: "#0e1018", padding: 12, borderRadius: 8, border: `1px solid ${isDanger ? "#f09999" : "#1a1d27"}` }}>
      <div style={{ fontSize: 9, color: "#4b5563", marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 18, fontWeight: "bold", color: isDanger ? "#f09999" : "#5dcaa5" }}>{typeof v === "number" ? v.toFixed(3) : "0.000"}</div>
    </div>
  );
}

function InfoTile({ label, value }) {
  return (
    <div style={{ background: "#0e1018", padding: 12, borderRadius: 8, border: "1px solid #1a1d27" }}>
      <div style={{ fontSize: 9, color: "#4b5563", marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 11, color: "#9ca3af" }}>{value}</div>
    </div>
  );
}

const s = {
  container:   { height: "100%", display: "flex", flexDirection: "column" },
  header:      { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px", borderBottom: "1px solid #1a1d27", background: "#0e1018" },
  sessionInfo: { display: "flex", flexDirection: "column", gap: 2 },
  title:       { margin: 0, fontSize: 16, color: "#e2e0d6" },
  sid:         { fontSize: 10, color: "#4b5563", fontFamily: "monospace" },
  headerRight: { display: "flex", gap: 16, alignItems: "center" },
  pills:       { display: "flex", gap: 8 },
  pill:        { fontSize: 10, color: "#9ca3af", background: "#1a1d27", padding: "4px 10px", borderRadius: 12, fontWeight: 600 },
  exportBtn:   { background: "#5dcaa5", border: "none", color: "#05070a", padding: "6px 14px", borderRadius: 6, cursor: "pointer", fontSize: 11, fontWeight: "bold" },
  minimap:     { display: "flex", height: 16, padding: "0 16px", gap: 2, alignItems: "center", background: "#070910", borderBottom: "1px solid #1a1d27" },
  minimapBar:  { flex: 1, height: 8, borderRadius: 1, transition: "all 0.15s", cursor: "pointer" },
  hint:        { fontSize: 9, color: "#3d4052", padding: "4px 16px", borderBottom: "1px solid #1a1d27" },
  main:        { display: "flex", flex: 1, overflow: "hidden" },
  timeline:    { width: 340, borderRight: "1px solid #1a1d27", overflowY: "auto", padding: "12px", display: "flex", flexDirection: "column", gap: 8 },
  eventCard:   { padding: "12px", borderRadius: 10, border: "1px solid transparent", cursor: "pointer", transition: "all 0.15s" },
  eventTime:   { fontSize: 9, color: "#4b5563", marginBottom: 4 },
  eventCore:   { display: "flex", justifyContent: "space-between", marginBottom: 4 },
  eventTool:   { fontSize: 13, color: "#60a5fa", fontWeight: "bold" },
  eventVerdict:{ fontSize: 10, fontWeight: "bold" },
  miniMitre:   { fontSize: 9, background: "#1a0d2e", color: "#a78bfa", padding: "2px 6px", borderRadius: 4, display: "inline-block", marginBottom: 4 },
  eventReason: { fontSize: 10, color: "#6b7280", lineHeight: "1.4" },
  detail:      { flex: 1, background: "#0a0c14", padding: "24px", overflowY: "auto" },
  inspector:   { display: "flex", flexDirection: "column", gap: 24 },
  insHeader:   { display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid #1a1d27", paddingBottom: 16 },
  insBadges:   { display: "flex", gap: 8 },
  mitreBadge:  { padding: "2px 8px", background: "#2d1a4a", color: "#c084fc", borderRadius: 4, fontSize: 10, fontWeight: "bold" },
  rationale:   { color: "#9ca3af", fontSize: 13, lineHeight: "1.6", margin: 0 },
  detailsGrid: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 },
  selectHint:  { height: "100%", display: "flex", alignItems: "center", justifyContent: "center", color: "#3d4052" },
  empty:       { height: "100%", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" },
};
