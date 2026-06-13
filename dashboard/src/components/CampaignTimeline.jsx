import { useState } from "react";
import { Modal } from "./ChartComponents";

export default function CampaignTimeline({ campaigns }) {
  const [selected, setSelected] = useState(null);

  if (!campaigns || campaigns.length === 0) {
    return (
      <div style={s.empty}>
        <div style={{ fontSize: 32 }}>🛰️</div>
        <p style={{ color: "#4b5563", marginTop: 10 }}>No multi-stage attack campaigns detected.</p>
      </div>
    );
  }

  return (
    <div style={s.container}>
      <header style={s.header}>
        <h3 style={s.title}>Threat Campaigns</h3>
        <span style={s.badge}>{campaigns.length} campaigns detected</span>
      </header>

      <div style={s.list}>
        {campaigns.map((c, idx) => {
          const score = typeof c.score === "number" ? c.score : (c.hit_count || 0) / 10;
          const techniques = c.techniques || [];
          const mainTechnique = c.main_technique || (techniques.length > 0 ? techniques[0] : "Mixed");

          return (
            <div key={c.id || idx} style={s.card} onClick={() => setSelected(c)}>
              <div style={s.cardHeader}>
                <div style={s.cardTitleGroup}>
                  <div style={s.cardId}>{c.id || `CAMP-${idx}`}</div>
                  <div style={s.cardName}>
                    {c.is_active ? "🟢 Active" : "⚪ Archived"}
                    {c.agent_id ? ` — ${c.agent_id}` : ""}
                  </div>
                </div>
                <div style={{
                  ...s.riskBadge,
                  backgroundColor: score > 0.8 ? '#f0999920' : '#f0c87520',
                  color: score > 0.8 ? '#f09999' : '#f0c875'
                }}>
                  {c.hit_count || 0} hits
                </div>
              </div>

              {/* Technique pills */}
              {techniques.length > 0 && (
                <div style={s.techRow}>
                  {techniques.slice(0, 5).map((t, i) => (
                    <span key={i} style={s.techPill}>{t}</span>
                  ))}
                  {techniques.length > 5 && <span style={s.techMore}>+{techniques.length - 5}</span>}
                </div>
              )}

              {/* Timeline dots for attempts if they exist */}
              {Array.isArray(c.attempts) && c.attempts.length > 0 && (
                <div style={s.timeline}>
                  {c.attempts.map((att, i) => (
                    <div key={i} style={s.stage}>
                      <div style={{ ...s.dot, backgroundColor: att.verdict === "BLOCK" ? "#f09999" : "#f0c875" }} />
                      {i < c.attempts.length - 1 && <div style={s.connector} />}
                      <div style={s.stageInfo}>
                        <div style={s.stageTool}>{att.tool_name || "tool"}</div>
                        <div style={s.stageTime}>{att.ts ? new Date(att.ts * 1000).toLocaleTimeString() : ""}</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              <div style={s.cardFooter}>
                <span style={s.technique}>{mainTechnique}</span>
                <span style={s.events}>
                  {c.start_ts ? new Date(c.start_ts * 1000).toLocaleDateString() : ""}
                  {c.end_ts && c.start_ts !== c.end_ts ? ` → ${new Date(c.end_ts * 1000).toLocaleDateString()}` : ""}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {selected && (
        <Modal title={`Campaign: ${selected.id || "Details"}`} onClose={() => setSelected(null)}>
          <div style={s.modalBody}>
            <div style={s.modalOverview}>
              <div style={s.modStat}>
                <label style={s.modLabel}>Status</label>
                <span>{selected.is_active ? "🟢 Live Correlation" : "⚪ Archived Chain"}</span>
              </div>
              <div style={s.modStat}>
                <label style={s.modLabel}>Agent</label>
                <span style={{ color: '#60a5fa' }}>{selected.agent_id || "unknown"}</span>
              </div>
              <div style={s.modStat}>
                <label style={s.modLabel}>Session</label>
                <span style={{ color: '#9ca3af', fontSize: 12 }}>{selected.session_id || "—"}</span>
              </div>
              <div style={s.modStat}>
                <label style={s.modLabel}>Hit Count</label>
                <span style={{ color: '#f09999', fontWeight: 900 }}>{selected.hit_count || 0}</span>
              </div>
            </div>

            {(selected.techniques || []).length > 0 && (
              <div style={s.detailSection}>
                <label style={s.historyLabel}>MITRE Techniques</label>
                <div style={s.techRow}>
                  {selected.techniques.map((t, i) => (
                    <span key={i} style={s.techPillLarge}>{t}</span>
                  ))}
                </div>
              </div>
            )}

            {Array.isArray(selected.attempts) && selected.attempts.length > 0 && (
              <div style={s.detailSection}>
                <label style={s.historyLabel}>Full Event Chain</label>
                {selected.attempts.map((at, i) => (
                  <div key={i} style={s.historyRow}>
                    <span style={s.rowIdx}>{i + 1}</span>
                    <span style={{ ...s.rowVerdict, color: at?.verdict === "BLOCK" ? "#f09999" : "#f0c875" }}>
                      {at?.verdict || "UNKNOWN"}
                    </span>
                    <span style={s.rowTool}>{at?.tool_name || "tool"}</span>
                    <span style={s.rowReason}>{at?.text || at?.reason || "—"}</span>
                  </div>
                ))}
              </div>
            )}

            <div style={s.detailSection}>
              <label style={s.historyLabel}>Time Range</label>
              <div style={{ color: '#9ca3af', fontSize: 13 }}>
                {selected.start_ts ? new Date(selected.start_ts * 1000).toLocaleString() : "—"}
                {" → "}
                {selected.end_ts ? new Date(selected.end_ts * 1000).toLocaleString() : "—"}
              </div>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

const s = {
  container: { padding: "15px 0" },
  header: { display: "flex", alignItems: "center", gap: "15px", marginBottom: "30px" },
  title: { margin: 0, fontSize: "22px", color: "#e2e0d6", fontWeight: '900' },
  badge: { padding: "5px 15px", background: "#c084fc20", color: "#c084fc", borderRadius: "15px", fontSize: "12px", fontWeight: "900", border: '1px solid #c084fc33' },
  list: { display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(400px, 1fr))", gap: "25px" },
  card: {
    background: "#0e1018", border: "1px solid #1a1d27", borderRadius: "15px",
    padding: "25px", cursor: "pointer", transition: "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
    position: 'relative'
  },
  cardHeader: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "15px" },
  cardTitleGroup: { display: "flex", flexDirection: "column", gap: "4px" },
  cardId: { fontSize: "14px", fontWeight: "900", color: "#9ca3af", fontFamily: "'JetBrains Mono', monospace", letterSpacing: '1px' },
  cardName: { fontSize: "12px", color: "#6b7280", fontWeight: '700' },
  riskBadge: { padding: "6px 12px", borderRadius: "8px", fontSize: "13px", fontWeight: "900" },
  techRow: { display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "15px" },
  techPill: {
    padding: "3px 10px", background: "#2d1a4a", color: "#c084fc", borderRadius: "6px",
    fontSize: "10px", fontWeight: "900", border: "1px solid #7c3aed44"
  },
  techPillLarge: {
    padding: "6px 14px", background: "#2d1a4a", color: "#c084fc", borderRadius: "8px",
    fontSize: "12px", fontWeight: "900", border: "1px solid #7c3aed44"
  },
  techMore: { padding: "3px 8px", color: "#4b5563", fontSize: "10px", fontWeight: "900" },
  timeline: { display: "flex", gap: "15px", overflowX: "auto", padding: "15px 0", marginBottom: "15px" },
  stage: { display: "flex", flexDirection: "column", alignItems: "center", minWidth: "80px", position: "relative" },
  dot: {
    width: "14px", height: "14px", borderRadius: "50%", zIndex: 2, marginBottom: "10px",
    border: '3px solid #0a0c14', boxShadow: '0 0 15px rgba(255,255,255,0.1)'
  },
  connector: { position: "absolute", top: "7px", left: "45px", width: "50px", height: "2px", background: "#1a1d27", zIndex: 1 },
  stageInfo: { textAlign: "center" },
  stageTool: { fontSize: "11px", color: "#e2e0d6", fontWeight: "900", whiteSpace: "nowrap" },
  stageTime: { fontSize: "10px", color: "#4b5563", fontWeight: '700' },
  cardFooter: { display: "flex", justifyContent: "space-between", borderTop: "1px solid #1a1d27", paddingTop: "15px" },
  technique: { fontSize: "13px", color: "#c084fc", fontWeight: "900" },
  events: { fontSize: "12px", color: "#6b7280", fontWeight: '700' },
  empty: { display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "300px", fontWeight: '900', color: '#4b5563' },
  modalBody: { display: "flex", flexDirection: "column", gap: "25px", paddingRight: "15px", overflowY: "auto", flex: 1 },
  modalOverview: {
    display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px",
    background: "#1a1d27", padding: "25px", borderRadius: "12px", flexShrink: 0, border: '1px solid #333'
  },
  modStat: { display: "flex", flexDirection: "column", gap: "6px" },
  modLabel: { fontSize: "10px", color: "#4b5563", textTransform: "uppercase", fontWeight: "900", letterSpacing: "1px" },
  detailSection: { display: "flex", flexDirection: "column", gap: "12px" },
  historyLabel: { fontSize: "12px", color: "#6b7280", textTransform: "uppercase", marginBottom: "4px", fontWeight: '900', letterSpacing: '1px' },
  historyRow: {
    display: "flex", gap: "15px", alignItems: "center", padding: "12px",
    background: "#0a0c14", borderRadius: "8px", fontSize: "14px", border: '1px solid #1a1d27'
  },
  rowIdx: { color: "#3d4052", width: "20px", fontWeight: '900' },
  rowVerdict: { fontWeight: "900", width: "70px" },
  rowTool: { color: "#60a5fa", width: "100px", fontWeight: '900' },
  rowReason: { color: "#9ca3af", flex: 1, fontSize: "13px", lineHeight: '1.4' },
};
