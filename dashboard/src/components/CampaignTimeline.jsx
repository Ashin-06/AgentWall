import { useState } from "react";
import { Modal } from "./ChartComponents";

export default function CampaignTimeline({ campaigns }) {
  const [selected, setSelected] = useState(null);

  if (!campaigns || campaigns.length === 0) {
    return (
      <div style={s.empty}>
        <div style={{ fontSize: 32 }}>🛰️</div>
        <p style={{ color: "#4b5563", marginTop: 10 }}>No multi-stage attack campaigns active.</p>
      </div>
    );
  }

  return (
    <div style={s.container}>
      <header style={s.header}>
        <h3 style={s.title}>Active Threat Campaigns</h3>
        <span style={s.badge}>{campaigns.length} campaigns detected</span>
      </header>

      <div style={s.list}>
        {campaigns.map(c => (
          <div key={c.id} style={s.card} onClick={() => setSelected(c)}>
            <div style={s.cardHeader}>
              <div style={s.cardTitleGroup}>
                <div style={s.cardId}>{c.id}</div>
                <div style={s.cardName}>{c.is_active ? "🟢 Active Stage" : "⚪ Completed"}</div>
              </div>
              <div style={{ ...s.riskBadge, backgroundColor: c.score > 0.8 ? '#f0999920' : '#f0c87520', color: c.score > 0.8 ? '#f09999' : '#f0c875' }}>
                Score: {c.score.toFixed(2)}
              </div>
            </div>

            <div style={s.timeline}>
              {(c.attempts || []).map((att, idx) => (
                <div key={idx} style={s.stage}>
                  <div style={{ ...s.dot, backgroundColor: att.verdict === "BLOCK" ? "#f09999" : "#f0c875" }} />
                  {idx < (c.attempts.length - 1) && <div style={s.connector} />}
                  <div style={s.stageInfo}>
                    <div style={s.stageTool}>{att.tool_name || "tool"}</div>
                    <div style={s.stageTime}>{new Date(att.ts * 1000).toLocaleTimeString()}</div>
                  </div>
                </div>
              ))}
            </div>

            <div style={s.cardFooter}>
              <span style={s.technique}>{c.main_technique || "Mixed Campaign"}</span>
              <span style={s.events}>{c.attempts?.length || 0} events</span>
            </div>
          </div>
        ))}
      </div>

      {selected && (
        <Modal title={`Campaign Details: ${selected.id}`} onClose={() => setSelected(null)}>
          {(() => {
            try {
              return (
                <div style={s.modalBody}>
                  <div style={s.modalOverview}>
                    <div style={s.modStat}>
                      <label>Status</label>
                      <span>{selected.is_active ? "Live Correlation" : "Archived Chain"}</span>
                    </div>
                    <div style={s.modStat}>
                      <label>Primary Vector</label>
                      <span style={{ color: '#c084fc' }}>{selected.main_technique || "Generic Probe"}</span>
                    </div>
                  </div>
                  
                  <div style={s.eventHistory}>
                    <label style={s.historyLabel}>Full Event Chain</label>
                    {(selected.attempts || []).map((at, i) => (
                      <div key={i} style={s.historyRow}>
                        <span style={s.rowIdx}>{i+1}</span>
                        <span style={{ ...s.rowVerdict, color: at?.verdict === "BLOCK" ? "#f09999" : "#f0c875" }}>{at?.verdict || "UNKNOWN"}</span>
                        <span style={s.rowTool}>{at?.tool_name || "tool"}</span>
                        <span style={s.rowReason}>{at?.text || "No details available"}</span>
                      </div>
                    ))}
                  </div>
                </div>
              );
            } catch (err) {
              return <div style={{padding: 20, color: '#f09999'}}>Error loading campaign forensics: {err.message}</div>
            }
          })()}
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
  cardHeader: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" },
  cardTitleGroup: { display: "flex", flexDirection: "column", gap: "4px" },
  cardId: { fontSize: "14px", fontWeight: "900", color: "#9ca3af", fontFamily: "'JetBrains Mono', monospace", letterSpacing: '1px' },
  cardName: { fontSize: "12px", color: "#6b7280", fontWeight: '900' },
  riskBadge: { padding: "6px 12px", borderRadius: "8px", fontSize: "13px", fontWeight: "900" },
  timeline: { display: "flex", gap: "15px", overflowX: "auto", padding: "15px 0", marginBottom: "20px" },
  stage: { display: "flex", flexDirection: "column", alignItems: "center", minWidth: "80px", position: "relative" },
  dot: { width: "14px", height: "14px", borderRadius: "50%", zIndex: 2, marginBottom: "10px", border: '3px solid #0a0c14', boxShadow: '0 0 15px rgba(255,255,255,0.1)' },
  connector: { position: "absolute", top: "7px", left: "45px", width: "50px", height: "2px", background: "#1a1d27", zIndex: 1 },
  stageInfo: { textAlign: "center" },
  stageTool: { fontSize: "11px", color: "#e2e0d6", fontWeight: "900", whiteSpace: "nowrap" },
  stageTime: { fontSize: "10px", color: "#4b5563", fontWeight: '700' },
  cardFooter: { display: "flex", justifyContent: "space-between", borderTop: "1px solid #1a1d27", paddingTop: "20px" },
  technique: { fontSize: "13px", color: "#c084fc", fontWeight: "900" },
  events: { fontSize: "13px", color: "#6b7280", fontWeight: '900' },
  empty: { display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "300px", fontWeight: '900', color: '#4b5563' },
  modalBody: { display: "flex", flexDirection: "column", gap: "25px", paddingRight: "15px", overflowY: "auto", flex: 1 },
  modalOverview: { display: "flex", gap: "40px", background: "#1a1d27", padding: "25px", borderRadius: "12px", flexShrink: 0, border: '1px solid #333' },
  modStat: { display: "flex", flexDirection: "column", gap: "6px" },
  eventHistory: { display: "flex", flexDirection: "column", gap: "12px" },
  historyLabel: { fontSize: "12px", color: "#6b7280", textTransform: "uppercase", marginBottom: "8px", fontWeight: '900', letterSpacing: '1px' },
  historyRow: { 
    display: "flex", gap: "15px", alignItems: "center", padding: "12px", 
    background: "#0a0c14", borderRadius: "8px", fontSize: "14px", border: '1px solid #1a1d27'
  },
  rowIdx: { color: "#3d4052", width: "20px", fontWeight: '900' },
  rowVerdict: { fontWeight: "900", width: "70px" },
  rowTool: { color: "#60a5fa", width: "100px", fontWeight: '900' },
  rowReason: { color: "#9ca3af", flex: 1, fontSize: "13px", lineHeight: '1.4' }
};
