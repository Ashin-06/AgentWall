export default function RiskScore({ scores }) {
  const top = scores.slice(0, 8);
  return (
    <div style={s.card}>
      <h3 style={s.title}>Agent Risk Scores</h3>
      {top.length === 0 && <p style={s.empty}>No agents yet.</p>}
      {top.map(a => {
        const color = a.risk_score > 66 ? "#f09999" :
                      a.risk_score > 33 ? "#f0c875" : "#5dcaa5";
        const label = a.risk_score > 66 ? "HIGH" :
                      a.risk_score > 33 ? "MED"  : "LOW";
        return (
          <div key={a.agent_id} style={s.row}>
            <div style={s.agentInfo}>
              <span style={s.agent}>{a.agent_id}</span>
              <span style={s.calls}>{a.total_calls} calls</span>
            </div>
            <div style={s.barWrap}>
              <div style={{ ...s.fill, width: `${a.risk_score}%`, background: color }} />
            </div>
            <span style={{ ...s.badge, color, borderColor: color + "44", background: color + "11" }}>
              {label}
            </span>
            <span style={{ ...s.score, color }}>{a.risk_score}</span>
          </div>
        );
      })}
    </div>
  );
}

const s = {
  card:      { marginBottom: "30px" },
  title:     { color: "#9ca3af", fontSize: "12px", textTransform: "uppercase",
                letterSpacing: "1.5px", marginBottom: "20px", fontWeight: "900" },
  empty:     { color: "#4b5563", fontStyle: "italic" },
  row:       { display: "flex", alignItems: "center", gap: "15px", marginBottom: "16px", 
                transition: "transform 0.2s", cursor: "pointer" },
  agentInfo: { display: "flex", flexDirection: "column", width: "140px" },
  agent:     { color: "#e2e0d6", fontWeight: "700", overflow: "hidden",
                textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: "14px" },
  calls:     { color: "#4b5563", fontSize: "11px", fontWeight: "600" },
  barWrap:   { flex: 1, height: "10px", background: "#1a1d27", borderRadius: "5px", overflow: "hidden" },
  fill:      { height: "100%", borderRadius: "5px", transition: "width 0.8s cubic-bezier(0.175, 0.885, 0.32, 1.275)" },
  badge:     { padding: "2px 8px", borderRadius: "4px", fontSize: "10px",
                fontWeight: "900", border: "1px solid", flexShrink: 0 },
  score:     { width: "40px", textAlign: "right", fontWeight: "900", fontSize: "16px" },
};
