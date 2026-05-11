import { useState } from "react";
import { formatDistanceToNow } from "date-fns";

export default function PolicyViolations({ violations }) {
  const [expanded, setExpanded] = useState(null);
  const violations_safe = Array.isArray(violations) ? violations : [];
  const recent = violations_safe.slice(0, 100);

  return (
    <div style={s.container}>
      <h3 style={s.title}>
        Violations
        <span style={s.count}>{violations_safe.length}</span>
      </h3>
      <div style={s.scroll}>
        {recent.length === 0 && <p style={s.empty}>No violations. 🎉</p>}
        {recent.map(v => (
          <div key={v.event_id} style={{...s.row, background: expanded === v.event_id ? "#1a1d27" : "transparent"}} 
               onClick={() => setExpanded(expanded === v.event_id ? null : v.event_id)}>
            <span style={{
              ...s.badge,
              color:      v.verdict === "BLOCK" ? "#f09999" : "#f0c875",
              borderColor:v.verdict === "BLOCK" ? "#f0999933" : "#f0c87533",
              background: v.verdict === "BLOCK" ? "#200a0a"  : "#201a0a",
            }}>
              {v.verdict}
            </span>
            <div style={s.info}>
              <div style={s.toolRow}>
                <span style={s.tool}>{v.tool_name}</span>
                {v.mitre_id && (
                  <span style={s.mitre}>{v.mitre_id}</span>
                )}
              </div>
              <span style={s.reason} title={v.reason}>{v.reason?.slice(0, 65)}</span>
              
              {expanded === v.event_id && (
                <div style={s.detailBox}>
                   <pre style={s.json}>{JSON.stringify(v.arguments || {}, null, 2)}</pre>
                   {v.details && typeof v.details === "object" && v.details.injection && (
                     <div style={s.injBox}>
                       <span style={s.injTitle}>Semantic Guard Analysis:</span>
                       <p style={s.injText}>{v.details.injection.reasoning || "No reasoning provided."}</p>
                     </div>
                   )}
                </div>
              )}

              <span style={s.ts}>
                {v.ts ? formatDistanceToNow(new Date(v.ts * 1000), { addSuffix: true }) : "Unknown time"}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

const s = {
  container: { height: "100%", display: "flex", flexDirection: "column" },
  scroll:    { flex: 1, overflowY: "auto", paddingRight: "10px" },
  title:   { color: "#9ca3af", fontSize: "12px", textTransform: "uppercase",
              letterSpacing: "1.5px", marginBottom: "15px",
              display: "flex", alignItems: "center", gap: "10px", fontWeight: "900" },
  count:   { background: "#1a1d27", padding: "2px 8px", borderRadius: "10px",
              fontSize: "11px", color: "#6b7280", fontWeight: "900" },
  empty:   { color: "#4b5563", fontStyle: "italic" },
  row:     { display: "flex", gap: "15px", marginBottom: "12px",
              padding: "12px", borderRadius: "8px", borderBottom: "1px solid #1a1d27",
              transition: "background 0.2s, transform 0.2s", cursor: "pointer" },
  badge:   { padding: "4px 10px", borderRadius: "6px", fontSize: "11px",
              fontWeight: "900", border: "1px solid", flexShrink: 0,
              alignSelf: "flex-start", letterSpacing: "0.5px" },
  info:    { display: "flex", flexDirection: "column", gap: "6px", flex: 1, minWidth: 0 },
  toolRow: { display: "flex", alignItems: "center", gap: "10px" },
  tool:    { color: "#e2e0d6", fontWeight: "700", fontSize: "15px" },
  mitre:   { fontSize: "11px", color: "#c084fc", background: "#2d1a4a",
              border: "1px solid #7c3aed66", padding: "1px 8px", borderRadius: "4px", fontWeight: "900" },
  reason:  { color: "#94a3b8", fontSize: "13px", lineHeight: "1.4" },
  detailBox: { background: "#0a0c14", padding: "15px", borderRadius: "8px", margin: "10px 0", border: "1px solid #1a1d27" },
  json:    { fontSize: "12px", color: "#5dcaa5", whiteSpace: "pre-wrap", margin: 0, overflow: "hidden" },
  injBox:  { marginTop: "15px", borderTop: "1px solid #1a1d27", paddingTop: "10px" },
  injTitle: { fontSize: "11px", color: "#f09999", fontWeight: "900", textTransform: "uppercase" },
  injText: { color: "#9ca3af", fontSize: "12px", fontStyle: "italic", marginTop: "5px" },
  ts:      { color: "#4b5563", fontSize: "11px", fontWeight: "600" },
};
