import { useRef, useEffect, useState, useMemo, useCallback } from "react";
import { formatDistanceToNow } from "date-fns";

const CATEGORY_MAP = {
  READ:  { x: -350, color: "#60a5fa", label: "READ", short: "R" },
  WRITE: { x: -210, color: "#34d399", label: "WRITE", short: "W" },
  EXEC:  { x: -70,  color: "#f87171", label: "EXEC", short: "E" },
  NET:   { x: 70,   color: "#a78bfa", label: "NET", short: "N" },
  MEM:   { x: 210,  color: "#38bdf8", label: "MEM", short: "M" },
  DB:    { x: 350,  color: "#fbbf24", label: "DB", short: "D" },
};

const VERDICT_COLORS = {
  BLOCK:  "#ef4444",
  AUDIT:  "#f59e0b",
  PERMIT: "#10b981",
  ALLOW:  "#10b981",
  PASS:   "#10b981",
};

const s = {
  container: { display: 'flex', flexDirection: 'column', height: '100%', background: '#05060a', borderRadius: '12px', border: '1px solid #1a1d27', overflow: 'hidden', position: 'relative', color: '#e2e0d6', fontFamily: "'JetBrains Mono', monospace" },
  topBar: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '15px 30px', borderBottom: '1px solid #1a1d27', background: '#0e1018', zIndex: 100 },
  main: { display: 'flex', flex: 1, overflow: 'hidden', position: 'relative' },
  graphPane: { flex: 1, position: 'relative', overflow: 'hidden', cursor: 'crosshair' },
  timelinePane: { width: '420px', borderLeft: '1px solid #1a1d27', background: '#0a0c14', display: 'flex', flexDirection: 'column' },
  controller: { position: 'absolute', bottom: '40px', left: '50%', transform: 'translateX(-50%)', background: 'rgba(14, 16, 24, 0.95)', border: '1px solid #3b82f6', borderRadius: '40px', padding: '12px 30px', display: 'flex', alignItems: 'center', gap: '20px', zIndex: 200, boxShadow: '0 0 40px rgba(59, 130, 246, 0.4)', backdropFilter: 'blur(10px)' },
  slider: { width: '300px', cursor: 'pointer' },
  detailStrip: { height: '180px', background: '#0e1018', borderTop: '3px solid #3b82f6', display: 'flex', padding: '20px 40px', gap: '50px', alignItems: 'center', zIndex: 100 },
  detailKey: { fontSize: '11px', color: '#4b5563', textTransform: 'uppercase', marginBottom: '8px', fontWeight: '900', letterSpacing: '1px' },
  detailVal: { fontSize: '15px', fontWeight: '900', color: '#fff' },
  timelineScroll: { flex: 1, overflowY: 'auto', padding: '20px' },
  btn: { background: '#1a1d27', border: '1px solid #333', color: '#fff', padding: '8px 16px', borderRadius: '8px', cursor: 'pointer', fontSize: '12px', fontWeight: 'bold', transition: 'all 0.2s' },
  legend: { position: 'absolute', bottom: '20px', left: '20px', background: 'rgba(0,0,0,0.6)', padding: '10px', borderRadius: '8px', border: '1px solid #1a1d27', pointerEvents: 'auto', zIndex: 50 },
};

function project(x, y, z, rotX, rotY, W, H, fov, zoom, pX, pY) {
  const cosY = Math.cos(rotY), sinY = Math.sin(rotY);
  const rx = x * cosY - z * sinY;
  const rz = x * sinY + z * cosY;
  const cosX = Math.cos(rotX), sinX = Math.sin(rotX);
  const ry = y * cosX - rz * sinX;
  const fz = y * sinX + rz * cosX;
  const div = fov + fz + 400;
  const scale = (fov / (div <= 0 ? 1 : div)) * zoom;
  return { sx: W / 2 + (rx + pX) * scale, sy: H / 2 + (ry + pY) * scale, scale: Math.max(0.1, scale), fz };
}

export default function AttackGraph({ data }) {
  const [activeSession, setActive] = useState(null);
  const [hoveredNode, setHovered] = useState(null);
  const [viewMode, setViewMode] = useState("split");
  const [showAll, setShowAll] = useState(false);
  const [rotX, setRotX] = useState(0.5);
  const [rotY, setRotY] = useState(0.8);
  const [panX, setPanX] = useState(0);
  const [panY, setPanY] = useState(0);
  const [zoom, setZoom] = useState(1);
  const [replaySpeed, setReplaySpeed] = useState(1);
  const [autoRotate, setAutoRotate] = useState(false);
  const [cinematicMode, setCinematicMode] = useState(false);
  const [replayIdx, setReplayIdx] = useState(-1);
  const [isPlaying, setIsPlaying] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [lastMouse, setLastMouse] = useState({ x: 0, y: 0 });

  const canvasRef = useRef(null);
  const frameRef = useRef(null);

  const sessions = useMemo(() => Object.keys(data || {}), [data]);
  useEffect(() => { if (sessions.length > 0 && !activeSession) setActive(sessions[0]); }, [sessions, activeSession]);

  const processedData = useMemo(() => {
    if (!data || sessions.length === 0) return [];
    return sessions.map((sid, sIdx) => {
      const g = data[sid] || {};
      const zOffset = showAll ? (sIdx - sessions.length/2) * 100 : 0;
      const nodes = (g.nodes || []).map((n, i) => {
        const cat = CATEGORY_MAP[n.category] || { x: 0, color: '#6b7280' };
        const score = n.details?.injection?.score || n.details?.anomaly?.anomaly_score || n.risk || 0;
        // Semantic Spiral: Creates 3D depth even if risk is 0
        const angle = i * 0.5;
        const radius = 50 + score * 50;
        const xPos = cat.x + Math.cos(angle) * radius;
        const zPos = (i - (g.nodes?.length || 0) / 2) * 80 + zOffset + Math.sin(angle) * radius;
        return { ...n, sid, semanticX: xPos, semanticY: -score * 300 - 20, semanticZ: zPos, risk: score, stepIdx: i };
      });
      return { sid, nodes, edges: g.edges || [] };
    });
  }, [data, sessions, showAll]);

  const activeGraph = useMemo(() => processedData.find(g => g.sid === activeSession), [processedData, activeSession]);
  const currentReplayNode = useMemo(() => (replayIdx === -1 || !activeGraph) ? null : activeGraph.nodes[replayIdx], [activeGraph, replayIdx]);

  useEffect(() => {
    if (activeGraph?.nodes?.length > 0) setHovered(activeGraph.nodes[0]);
  }, [activeGraph]);

  useEffect(() => {
    if (currentReplayNode) setHovered(currentReplayNode);
  }, [currentReplayNode]);

  const resetForensics = useCallback(() => {
    setReplayIdx(-1); setIsPlaying(false); setCinematicMode(false); setPanX(0); setPanY(0); setZoom(1);
    if (activeGraph?.nodes?.length > 0) setHovered(activeGraph.nodes[0]);
  }, [activeGraph]);

  useEffect(() => {
    if (isPlaying && activeGraph) {
      const t = setInterval(() => {
        setReplayIdx(prev => {
          if (prev >= activeGraph.nodes.length - 1) { setIsPlaying(false); return prev; }
          return prev + 1;
        });
      }, 3000 / (replaySpeed || 1));
      return () => clearInterval(t);
    }
  }, [isPlaying, activeGraph, replaySpeed]);

  const render = useCallback(() => {
    const canvas = canvasRef.current; if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr; canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
    const W = rect.width, H = rect.height, fov = 1000;
    ctx.clearRect(0, 0, W, H);

    const sFact = (replaySpeed || 1);
    if (autoRotate) setRotY(y => y + (0.005 * sFact));
    if (cinematicMode && currentReplayNode) {
      setPanX(prev => prev + (-currentReplayNode.semanticX - prev) * 0.03 * sFact);
      setPanY(prev => prev + (-currentReplayNode.semanticY - prev) * 0.03 * sFact);
    }

    Object.values(CATEGORY_MAP).forEach(cat => {
      const p1 = project(cat.x, 0, -600, rotX, rotY, W, H, fov, zoom, panX, panY);
      const p2 = project(cat.x, 0, 600, rotX, rotY, W, H, fov, zoom, panX, panY);
      ctx.strokeStyle = "rgba(59, 130, 246, 0.1)"; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(p1.sx, p1.sy); ctx.lineTo(p2.sx, p2.sy); ctx.stroke();
    });

    const drawGraph = (g, isBg) => {
      if (!g) return;
      const maxIdx = (replayIdx === -1 || isBg) ? 999 : replayIdx;
      g.edges.forEach(e => {
        const from = g.nodes.find(n => n.id === e.source), to = g.nodes.find(n => n.id === e.target);
        if (!from || !to || from.stepIdx > maxIdx || to.stepIdx > maxIdx) return;
        const p1 = project(from.semanticX, from.semanticY, from.semanticZ, rotX, rotY, W, H, fov, zoom, panX, panY);
        const p2 = project(to.semanticX, to.semanticY, to.semanticZ, rotX, rotY, W, H, fov, zoom, panX, panY);
        ctx.beginPath(); ctx.moveTo(p1.sx, p1.sy); ctx.lineTo(p2.sx, p2.sy);
        ctx.strokeStyle = isBg ? "rgba(255,255,255,0.05)" : "rgba(59, 130, 246, 0.4)"; ctx.lineWidth = 2; ctx.stroke();
      });
      g.nodes.forEach(n => {
        if (n.stepIdx > maxIdx) return;
        const p = project(n.semanticX, n.semanticY, n.semanticZ, rotX, rotY, W, H, fov, zoom, panX, panY);
        const cat = CATEGORY_MAP[n.category] || {color: "#6b7280"};
        let rawV = getHeuristicVerdict(n); const vColor = VERDICT_COLORS[rawV] || "#6b7280";
        const isHover = hoveredNode?.id === n.id, radius = (n.risk * 35 + 22) * p.scale;
        ctx.beginPath(); ctx.arc(p.sx, p.sy, radius + 10, 0, Math.PI*2); ctx.strokeStyle = isBg ? "transparent" : vColor + "66"; ctx.lineWidth = 4; ctx.stroke();
        ctx.beginPath(); ctx.arc(p.sx, p.sy, radius, 0, Math.PI*2); ctx.fillStyle = isBg ? "rgba(75, 85, 99, 0.2)" : cat.color; ctx.fill();
        if (!isBg && (n.risk > 0.5 || isHover)) {
          ctx.fillStyle = "#fff"; ctx.font = "900 11px 'JetBrains Mono'"; ctx.textAlign = "left";
          ctx.fillText(n.tool || n.tool_name || n.label?.split('(')[0] || "Unknown", p.sx + radius + 15, p.sy);
          ctx.fillStyle = vColor; ctx.font = "bold 10px 'JetBrains Mono'"; ctx.fillText(rawV, p.sx + radius + 15, p.sy + 14);
        }
      });
    };
    if (showAll) processedData.forEach(g => drawGraph(g, g.sid !== activeSession)); else drawGraph(activeGraph, false);
  }, [processedData, activeGraph, rotX, rotY, panX, panY, zoom, showAll, hoveredNode, replayIdx, autoRotate, replaySpeed, currentReplayNode, cinematicMode]);

  useEffect(() => {
    const loop = () => { render(); frameRef.current = requestAnimationFrame(loop); };
    loop(); return () => cancelAnimationFrame(frameRef.current);
  }, [render]);

  const handleMouseMove = (e) => {
    if (!canvasRef.current) return;
    const rect = canvasRef.current.getBoundingClientRect(); const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    if (dragging) {
      if (e.buttons === 2 || e.shiftKey) { setPanX(p => p + (e.clientX - lastMouse.x) * 2 / zoom); setPanY(p => p + (e.clientY - lastMouse.y) * 2 / zoom); }
      else { setRotY(y => y + (e.clientX - lastMouse.x) * 0.002); setRotX(x => x + (e.clientY - lastMouse.y) * 0.002); }
      setLastMouse({ x: e.clientX, y: e.clientY });
    }
    let found = null;
    processedData.forEach(g => {
      if (!showAll && g.sid !== activeSession) return;
      g.nodes.forEach(n => {
        const p = project(n.semanticX, n.semanticY, n.semanticZ, rotX, rotY, rect.width, rect.height, 1000, zoom, panX, panY);
        if (Math.sqrt((mx-p.sx)**2 + (my-p.sy)**2) < 40) found = n;
      });
    });
    if (found) setHovered(found);
  };

  const getHeuristicReason = (n) => {
    if (n.reason) return n.reason;
    const tool = n.tool || n.tool_name || "system_call";
    if (n.risk > 0.8) return `CRITICAL_ALERT: High-risk ${n.category} activity detected via ${tool}. Heuristic analysis suggests potential unauthorized ${n.category === 'EXEC' ? 'execution' : 'access'} attempt. Blocking for safety.`;
    if (n.risk > 0.4) return `SUSPICIOUS_OBSERVATION: Elevated ${n.category} signals from ${tool}. Analyzing behavior for command injection or sandbox escape patterns. Monitoring closely.`;
    return `ROUTINE_MONITORING: ${n.category} interaction via ${tool} verified against safe baseline. No immediate threat detected.`;
  };

  const getHeuristicVerdict = (n) => {
    let v = (n.verdict || n.label?.split('(')[1]?.split(')')[0] || "").toUpperCase();
    if (!v) { if (n.risk > 0.8) v = "BLOCK"; else if (n.risk > 0.3) v = "AUDIT"; else v = "PERMIT"; }
    return v;
  };

  return (
    <div style={s.container}>
      <div style={s.topBar}>
        <div style={{display:'flex', gap:20, alignItems:'center'}}><div style={{fontSize:16, fontWeight:900, color:'#3b82f6', letterSpacing:2}}>AGENTWALL_FORENSICS_PRO</div><div style={{display:'flex', background:'#0a0c14', borderRadius:10, padding:3, border:'1px solid #1a1d27'}}>{["3d","split","2d"].map(v => <button key={v} onClick={()=>setViewMode(v)} style={{...s.btn, border:'none', background:viewMode===v?'#3b82f6':'transparent', color:viewMode===v?'#fff':'#4b5563', padding:'6px 18px', fontSize:13}}>{v.toUpperCase()}</button>)}</div></div>
        <div style={{display:'flex', gap:40, alignItems:'center', background:'#0a0c14', padding:'8px 24px', borderRadius:12, border:'1px solid #1a1d27'}}><div style={{display:'flex', alignItems:'center', gap:15}}><span style={{fontSize:11, color:'#4b5563', fontWeight:'900'}}>SPEED</span><input type="range" min="0.1" max="10" step="0.1" value={replaySpeed} onChange={e=>setReplaySpeed(parseFloat(e.target.value))} style={{width:100}} /><span style={{fontSize:12, color:'#fff', minWidth:40, fontWeight:'900'}}>{replaySpeed.toFixed(1)}x</span></div><div style={{display:'flex', alignItems:'center', gap:15}}><span style={{fontSize:11, color:'#4b5563', fontWeight:'900'}}>ZOOM</span><input type="range" min="0.1" max="20" step="0.1" value={zoom} onChange={e=>setZoom(parseFloat(e.target.value))} style={{width:100}} /><span style={{fontSize:12, color:'#fff', minWidth:40, fontWeight:'900'}}>{zoom.toFixed(1)}x</span></div></div>
        <div style={{display:'flex', gap:20, alignItems:'center'}}><select style={{...s.btn, padding:'8px 15px', fontSize:13}} value={activeSession||""} onChange={e=>setActive(e.target.value)}>{sessions.map(sid => <option key={sid} value={sid}>SESSION_{sid.slice(0,8)}</option>)}</select><label style={{fontSize:11, color:'#4b5563', display:'flex', alignItems:'center', gap:8, fontWeight:'900', cursor:'pointer'}}><input type="checkbox" checked={showAll} onChange={e=>setShowAll(e.target.checked)} /> GLOBAL_MODE</label></div>
      </div>

      <div style={s.main}>
        {viewMode !== "2d" && (
          <div id="graph-pane" style={s.graphPane} onMouseDown={e=>{setDragging(true);setLastMouse({x:e.clientX,y:e.clientY})}} onMouseMove={handleMouseMove} onMouseUp={()=>setDragging(false)} onContextMenu={e=>e.preventDefault()}>
            <canvas ref={canvasRef} style={{width:'100%', height:'100%'}} />
            {currentReplayNode && (
              <div style={{position: 'absolute', top: '30px', right: '30px', background: 'rgba(14, 16, 24, 0.95)', border: '2px solid #ef4444', borderRadius: '15px', padding: '25px 35px', zIndex: 150, width: '480px', boxShadow: '0 0 50px rgba(239, 68, 68, 0.4)', backdropFilter: 'blur(20px)'}}>
                <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:18}}><div style={{fontSize:13, color:'#ef4444', fontWeight:'900', letterSpacing:2}}>STAGE_{currentReplayNode.stepIdx + 1} // ACTIVE_TRACK</div><div style={{fontSize:20, fontWeight:900, color:'#fff'}}>{Math.round(currentReplayNode.risk * 100)}% THREAT</div></div>
                <div style={{fontSize:26, fontWeight:900, color:'#fff', marginBottom:12}}>{currentReplayNode.category} INTERCEPT</div>
                <div style={{fontSize:15, color:'#d1d5db', borderTop:'1px solid #1a1d27', paddingTop:15, marginTop:15, lineHeight:'1.7'}}><div style={{color:'#3b82f6', fontSize:12, marginBottom:6, fontWeight:'900'}}>GENERAL_CONTEXT</div>{currentReplayNode.label}<div style={{color:'#3b82f6', fontSize:12, marginBottom:6, marginTop:20, fontWeight:'900'}}>SPECIFIC_INTELLIGENCE</div>{currentReplayNode.tool || currentReplayNode.tool_name || "CORE_SYSTEM_ACCESS"} <span style={{color:VERDICT_COLORS[getHeuristicVerdict(currentReplayNode)] || "#fff"}}>({getHeuristicVerdict(currentReplayNode)})</span></div>
              </div>
            )}
            <div style={{...s.legend, width:'260px'}}><div style={{fontSize:11, color:'#4b5563', marginBottom:15, display:'flex', justifyContent:'space-between', alignItems:'center', fontWeight:'900'}}>NAV_CONTROLS <div style={{display:'flex', gap:10}}><div style={{textAlign:'center'}}><button onClick={()=>setCinematicMode(!cinematicMode)} style={{...s.btn, fontSize:10, padding:'6px 12px', background:cinematicMode?'#ef4444':'#1a1d27', border:cinematicMode?'1px solid #ef4444':'1px solid #333'}}>CINEMATIC</button><div style={{fontSize:7, color:'#4b5563', marginTop:4}}>AUTO-FOLLOW</div></div><div style={{textAlign:'center'}}><button onClick={()=>setAutoRotate(!autoRotate)} style={{...s.btn, fontSize:10, padding:'6px 12px', background:autoRotate?'#3b82f6':'#1a1d27', border:autoRotate?'1px solid #3b82f6':'1px solid #333'}}>ORBIT</button><div style={{fontSize:7, color:'#4b5563', marginTop:4}}>360° ROTATE</div></div></div></div><div style={{marginBottom:15}}><div style={{fontSize:9, color:'#4b5563', marginBottom:6, fontWeight:'900'}}>ROTATION_Y</div><input type="range" min="0" max="6.28" step="0.05" value={rotY} onChange={e=>setRotY(parseFloat(e.target.value))} style={{width:'100%', cursor:'pointer'}} /></div><div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:12}}>{Object.values(CATEGORY_MAP).map(c => <div key={c.label} style={{display:'flex', alignItems:'center', gap:10, fontSize:10, fontWeight:'700'}}><div style={{width:10,height:10,background:c.color, borderRadius:2}} /> {c.label}</div>)}</div></div>
            {replayIdx !== -1 && (
              <div style={s.controller}>
                <button style={{...s.btn, background:'none', border:'none', fontSize:18}} onClick={()=>setReplayIdx(p => Math.max(0, p-1))}>⏮</button>
                <button style={{...s.btn, background:'none', border:'none', fontSize:32}} onClick={()=>setIsPlaying(!isPlaying)}>{isPlaying ? "⏸" : "▶"}</button>
                <button style={{...s.btn, background:'none', border:'none', fontSize:18}} onClick={()=>setReplayIdx(p => Math.min((activeGraph?.nodes?.length||1)-1, p+1))}>⏭</button>
                <input type="range" style={s.slider} min="0" max={(activeGraph?.nodes?.length||1)-1} value={replayIdx} onChange={e=>setReplayIdx(parseInt(e.target.value))} />
                <div style={{fontSize:14, minWidth:60, fontWeight:900}}>{replayIdx + 1} / {activeGraph?.nodes?.length}</div>
                <button style={{...s.btn, background:'rgba(239, 68, 68, 0.2)', color:'#ef4444', border:'1px solid #ef4444', padding:'8px 20px', borderRadius:20}} onClick={resetForensics}>EXIT_FORENSICS</button>
              </div>
            )}
            {replayIdx === -1 && <button style={{position:'absolute', bottom:50, right:50, ...s.btn, padding:'18px 40px', background:'#3b82f6', color:'#fff', borderRadius:40, fontSize:16, fontWeight:'900', boxShadow:'0 15px 40px rgba(59, 130, 246, 0.4)', letterSpacing:1}} onClick={()=>{setReplayIdx(0); setIsPlaying(true)}}>START_FORENSIC_ANALYSIS</button>}
          </div>
        )}
        {viewMode !== "3d" && (
          <div style={viewMode==="2d" ? {...s.timelinePane, width:'100%'} : s.timelinePane}>
            <div style={{padding:'25px', borderBottom:'1px solid #1a1d27', display:'flex', justifyContent:'space-between', alignItems:'center', background:'#0e1018'}}><div style={{fontSize:14, fontWeight:900, color:'#3b82f6', letterSpacing:1}}>VERTICAL_KILL_CHAIN</div><div style={{fontSize:11, color:'#4b5563', fontWeight:'900'}}>{activeGraph?.nodes?.length || 0} EVENTS</div></div>
            <div style={s.timelineScroll}><div style={{position:'relative', borderLeft:'3px solid #1a1d27', marginLeft:'20px', paddingLeft:'40px'}}>
                {activeGraph?.nodes?.map((n, i) => {
                  const cat = CATEGORY_MAP[n.category] || {color:'#333', short:'?'};
                  const hV = getHeuristicVerdict(n); const vColor = VERDICT_COLORS[hV] || "#1e293b"; const isActive = hoveredNode?.id === n.id;
                  return (
                    <div key={n.id} onMouseEnter={()=>setHovered(n)} onClick={()=>setReplayIdx(i)} style={{position:'relative', marginBottom:'35px', cursor:'pointer', background: isActive ? 'rgba(59, 130, 246, 0.15)' : 'transparent', padding:'20px', borderRadius:'15px', transition:'all 0.3s', border: isActive ? '1px solid #3b82f6' : '1px solid transparent', boxShadow: isActive ? '0 0 20px rgba(59, 130, 246, 0.1)' : 'none'}}>
                      <div style={{position:'absolute', left:'-48px', top:'25px', width:'15px', height:'15px', borderRadius:'50%', background: vColor, border:'3px solid #0a0c14', boxShadow: `0 0 20px ${vColor}`}} />
                      <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8}}><div style={{fontSize:14, fontWeight:900, color:cat.color}}>{n.category}</div><div style={{fontSize:11, padding:'3px 10px', borderRadius:5, background:vColor, color:'#fff', fontWeight:'900'}}>{hV}</div></div>
                      <div style={{fontSize:16, fontWeight:'900', color:'#fff'}}>{n.tool || n.tool_name || "Unknown Tool"}</div>
                      <div style={{fontSize:12, color:'#6b7280', marginTop:10, lineHeight:'1.5'}}>{n.label}</div>
                    </div>
                  );
                })}
              </div></div>
          </div>
        )}
      </div>

      {hoveredNode && (
        <div style={s.detailStrip}>
          <div style={{width:'22%'}}><div style={s.detailKey}>Observed Behavior</div><div style={s.detailVal}>{hoveredNode.tool || hoveredNode.tool_name || hoveredNode.label?.split('(')[0] || "SYSTEM_CALL"}</div><div style={{fontSize:11, color:'#4b5563', marginTop:8, fontWeight:'700'}}>{hoveredNode.id.slice(0,24)}... // {hoveredNode.category}</div></div>
          <div style={{width:'32%'}}><div style={s.detailKey}>Security Signals (HT | POL | ANM | INJ | CMP)</div>
            <div style={{display:'flex', gap:12, height:70, marginTop:12}}>
              {[hoveredNode.details?.honeytoken?.triggered ? 1 : 0, hoveredNode.details?.policy?.action === 'BLOCK' ? 1 : 0, Math.max(hoveredNode.details?.anomaly?.anomaly_score || 0, hoveredNode.details?.rag?.score || 0), hoveredNode.details?.injection?.score || 0, hoveredNode.risk || 0].map((v, i) => {
                const color = v > 0.7 ? '#ef4444' : v > 0.3 ? '#f59e0b' : '#3b82f6';
                return (<div key={i} style={{flex:1, background:'#1a1d27', position:'relative', borderRadius:6, overflow:'hidden', border:'1px solid #333'}}>
                  <div style={{position:'absolute', bottom:0, width:'100%', height:`${Math.max(v*100, 10)}%`, background: color, boxShadow: `0 0 25px ${color}`, transition:'all 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275)'}} />
                </div>)
              })}
            </div>
          </div>
          <div style={{flex:1}}><div style={s.detailKey}>HEURISTIC_STRATEGIC_REASONING</div><div style={{...s.detailVal, fontWeight:400, color:'#d1d5db', fontSize:14, lineHeight:'1.7'}}>{getHeuristicReason(hoveredNode)}</div></div>
          <div style={{width:160, textAlign:'right', background:'rgba(59, 130, 246, 0.05)', padding:'20px', borderRadius:15, border:'1px solid #1a1d27'}}>
            <div style={s.detailKey}>Final Verdict</div>
            <div style={{...s.detailVal, color: VERDICT_COLORS[getHeuristicVerdict(hoveredNode)], fontSize:28, textShadow:`0 0 25px ${VERDICT_COLORS[getHeuristicVerdict(hoveredNode)]}77`}}>{getHeuristicVerdict(hoveredNode)}</div>
          </div>
        </div>
      )}
    </div>
  );
}
