import { useState } from "react";
import { Modal } from "./ChartComponents";

const MITRE_INFO = {
  T1003: { name: "Credential Dumping", desc: "Adversaries may attempt to dump credentials to obtain account login and password information. In AgentWall, this is detected when an agent searches memory or files for secrets/keys." },
  T1041: { name: "Exfiltration Over C2 Channel", desc: "Adversaries may steal data by transferring it over an existing command and control channel. Often seen when an agent sends retrieved data to an external HTTP endpoint." },
  T1048: { name: "Exfiltration Over Alt Protocol", desc: "Adversaries may use an alternate protocol to transfer data. Matches AgentWall's detection of DNS-based data exfiltration." },
  T1059: { name: "Command and Scripting Interpreter", desc: "Adversaries may abuse command and script interpreters to execute commands. Matches AgentWall's detection of 'bash' or 'python_repl' abuse." },
  "T1059.006": { name: "Python Scripting", desc: "Abuse of Python for script execution. Often used in RAG poisoning or data manipulation attacks." },
  "T1059.007": { name: "LLM Scripting / Injection", desc: "Abuse of LLM-specific scripting or prompt injection to achieve code execution." },
  T1078: { name: "Valid Accounts / Privilege", desc: "Adversaries may obtain and abuse credentials of existing accounts. In AI contexts, this relates to identity theft of the agent's system identity." },
  T1083: { name: "File/Directory Discovery", desc: "Adversaries may enumerate files and directories. Matches AgentWall's detection of path traversal and sensitive file access." },
  T1190: { name: "Exploit Public-Facing App", desc: "Adversaries may attempt to exploit a weakness in an Internet-facing computer or program. Matches SQL injection and SSRF detections." },
  T1552: { name: "Unsecured Credentials", desc: "Adversaries may search for credentials in files or on-screen. Matches searches for passwords or API keys in memory." },
  "T1552.005": { name: "Cloud Metadata Access", desc: "Adversaries may attempt to access cloud metadata services to steal IAM credentials. Matches SSRF attempts to 169.254.169.254." },
  T1565: { name: "Data Manipulation", desc: "Adversaries may insert, delete, or manipulate data. Matches unauthorized file modifications or RAG poisoning." },
  T1567: { name: "Exfiltration Over Web Service", desc: "Adversaries may use an existing web service to exfiltrate data. Matches data transfers to common tunnel/exfil domains." },
};

export default function MitreHeatmap({ data }) {
  const [detail, setDetail] = useState(null);
  
  if (!data || data.length === 0) {
    return (
      <div style={s.empty}>
        <div style={{ fontSize: 32 }}>🟣</div>
        <p style={{ color: "#4b5563", marginTop: 10 }}>No MITRE techniques detected in recent activity.</p>
      </div>
    );
  }

  const maxHits = Math.max(...data.map(d => d.count), 1);

  return (
    <div style={s.container}>
      <div style={s.grid}>
        {data.map(item => {
          const info = MITRE_INFO[item.mitre_id] || { name: "Unknown Technique", desc: "No description available." };
          const intensity = Math.min(item.count / 10, 1);
          
          return (
            <div 
              key={item.mitre_id} 
              style={{
                ...s.tile,
                backgroundColor: `rgba(192, 132, 252, ${0.1 + intensity * 0.8})`,
                borderColor: `rgba(192, 132, 252, ${0.3 + intensity * 0.4})`,
                boxShadow: intensity > 0.5 ? '0 0 15px rgba(192, 132, 252, 0.2)' : 'none'
              }}
              onClick={() => setDetail({ ...item, ...info })}
            >
              <div style={s.tileId}>{item.mitre_id}</div>
              <div style={s.tileName}>{info.name}</div>
              <div style={s.tileCount}>{item.count} hits</div>
              <div style={{...s.indicator, width: `${(item.count / maxHits) * 100}%`}} />
            </div>
          );
        })}
      </div>

      {detail && (
        <Modal title={`${detail.mitre_id}: ${detail.name}`} onClose={() => setDetail(null)}>
          <div style={s.detailBody}>
            <p style={s.desc}>{detail.desc}</p>
            <div style={s.stats}>
              <div style={s.statItem}>
                <span style={s.statLabel}>Frequency</span>
                <span style={s.statVal}>{detail.count} detections</span>
              </div>
              <div style={s.statItem}>
                <span style={s.statLabel}>Severity</span>
                <span style={{...s.statVal, color: detail.count > 5 ? '#f09999' : '#f0c875'}}>
                  {detail.count > 5 ? 'High Criticality' : 'Medium Priority'}
                </span>
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
  grid: { 
    display: "grid", 
    gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))", 
    gap: "15px" 
  },
  tile: {
    padding: "20px", borderRadius: "12px", border: "1px solid transparent",
    cursor: "pointer", transition: "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
    position: "relative", overflow: "hidden", display: "flex", flexDirection: "column", gap: "8px"
  },
  tileId: { fontSize: "12px", fontWeight: "900", color: "#c084fc", textTransform: "uppercase", letterSpacing: "1px" },
  tileName: { fontSize: "14px", color: "#e2e0d6", fontWeight: "700", lineHeight: "1.4", marginBottom: "6px" },
  tileCount: { fontSize: "13px", color: "#9ca3af", fontWeight: "600" },
  indicator: { position: "absolute", bottom: 0, left: 0, height: "4px", background: "#c084fc", opacity: 0.8 },
  empty: { display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "300px", fontWeight: '900', color: '#4b5563' },
  detailBody: { display: "flex", flexDirection: "column", gap: "20px" },
  desc: { color: "#d1d5db", fontSize: "15px", lineHeight: "1.7" },
  stats: { display: "flex", gap: "30px", background: "#1a1d27", padding: "20px", borderRadius: "10px", border: '1px solid #333' },
  statItem: { display: "flex", flexDirection: "column", gap: "6px" },
  statLabel: { fontSize: "11px", color: "#6b7280", textTransform: "uppercase", fontWeight: '900' },
  statVal: { fontSize: "15px", fontWeight: "900", color: "#e2e0d6" }
};
