import { formatDistanceToNow } from "date-fns";

export default function SessionList({ sessions, onSelect, activeSession }) {
  const sessions_safe = Array.isArray(sessions) ? sessions : [];
  return (
    <div style={s.container}>
      <h3 style={s.title}>Sessions <span style={s.count}>{sessions_safe.length}</span></h3>
      <div style={s.scroll}>
        {sessions_safe.length === 0 && <p style={s.empty}>No sessions yet.</p>}
        {sessions_safe.map(sess => {
          const riskColor = sess.blocks > 2  ? "#f09999" :
                            sess.audits > 5  ? "#f0c875" : "#5dcaa5";
          return (
            <div key={sess.session_id}
              onClick={() => onSelect(sess.session_id)}
              style={{
                ...s.row,
                background: activeSession === sess.session_id ? "#121520" : "transparent",
                borderLeft: `2px solid ${riskColor}`,
              }}>
              <div style={s.top}>
                <span style={s.agent}>{sess.agent_id}</span>
                <span style={s.time}>
                  {sess.last_seen ? formatDistanceToNow(new Date(sess.last_seen * 1000), { addSuffix: true }) : "Unknown time"}
                </span>
              </div>
              <div style={s.bottom}>
                <Chip label={`${sess.total_calls} calls`}   color="#6b7280" />
                {sess.blocks    > 0 && <Chip label={`${sess.blocks} blocked`}   color="#f09999" />}
                {sess.audits    > 0 && <Chip label={`${sess.audits} flagged`}   color="#f0c875" />}
                {sess.sanitised > 0 && <Chip label={`${sess.sanitised} cleaned`} color="#60a5fa" />}
                {sess.avg_latency_ms > 0 && (
                  <Chip label={`${Math.round(sess.avg_latency_ms)}ms avg`} color="#4b5563" />
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function Chip({ label, color }) {
  return (
    <span style={{
      padding: "2px 8px", borderRadius: "4px", fontSize: "11px", fontWeight: "900",
      color, border: `1px solid ${color}44`, background: `${color}15`,
    }}>
      {label}
    </span>
  );
}

const s = {
  container: { height: "100%", display: "flex", flexDirection: "column" },
  scroll:    { flex: 1, overflowY: "auto", paddingRight: "10px" },
  title:  { color: "#9ca3af", fontSize: "12px", textTransform: "uppercase",
             letterSpacing: "1.5px", marginBottom: "15px",
             display: "flex", alignItems: "center", gap: "10px", fontWeight: "900" },
  count:  { background: "#1a1d27", padding: "2px 8px", borderRadius: "10px",
             fontSize: "11px", color: "#6b7280", fontWeight: "900" },
  empty:  { color: "#4b5563", fontStyle: "italic" },
  row:    { padding: "12px 15px", marginBottom: "10px", borderRadius: "8px",
             cursor: "pointer", borderLeft: "3px solid transparent", 
             transition: "all 0.2s cubic-bezier(0.4, 0, 0.2, 1)" },
  top:    { display: "flex", justifyContent: "space-between", marginBottom: "8px" },
  agent:  { color: "#e2e0d6", fontWeight: "700", fontSize: "14px" },
  time:   { color: "#6b7280", fontSize: "11px", fontWeight: "600" },
  bottom: { display: "flex", gap: "6px", flexWrap: "wrap" },
};
