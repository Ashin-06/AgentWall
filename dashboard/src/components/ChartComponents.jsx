import { useState } from "react";

/**
 * Modal Overlay for Drill-down
 */
export function Modal({ title, onClose, children }) {
  return (
    <div style={s.modalOverlay} onClick={onClose}>
      <div style={s.modalContent} onClick={e => e.stopPropagation()}>
        <div style={s.modalHeader}>
          <h3 style={s.modalTitle}>{title}</h3>
          <button style={s.closeBtn} onClick={onClose}>&times;</button>
        </div>
        <div style={s.modalBody}>{children}</div>
      </div>
    </div>
  );
}

/**
 * Interactive Horizontal Bar Chart with Popup Drill-down
 */
export function InteractiveHBar({ items, color = "#f09999", onBarClick }) {
  if (!items.length) return <div style={s.noData}>No data available</div>;
  const max = Math.max(...items.map(i => i.value), 1);

  return (
    <div style={s.barContainer}>
      {items.map((item, idx) => (
        <div key={idx} style={s.barRow} onClick={() => onBarClick && onBarClick(item)}>
          <div style={s.barLabel} title={item.label}>{item.label}</div>
          <div style={s.barTrack}>
            <div 
              style={{ 
                ...s.barFill, 
                width: `${(item.value / max) * 100}%`, 
                backgroundColor: color,
                boxShadow: `0 0 10px ${color}33`
              }} 
            />
          </div>
          <div style={{ ...s.barValue, color }}>{Math.round(item.value)}</div>
        </div>
      ))}
    </div>
  );
}

/**
 * Enhanced Sparkline with Hover
 */
export function InteractiveSparkline({ data, color, height = 40, width = 200, label }) {
  const [hoverVal, setHoverVal] = useState(null);
  if (!data || data.length === 0) return <div style={{height, width, color: '#3d4052'}}>---</div>;
  if (data.length === 1) return <div style={{height, width, display: 'flex', alignItems: 'center', justifyContent: 'center'}}><div style={{width: 4, height: 4, borderRadius: '50%', background: color}} /></div>;
  
  const max = Math.max(...data, 0.001);
  const min = Math.min(...data);
  const range = max - min || 1;

  const points = data.map((v, i) => {
    const x = (i / (data.length - 1)) * width;
    const y = height - ((v - min) / range) * height;
    return `${x},${y}`;
  }).join(" ");

  return (
    <div style={{ position: 'relative' }} onMouseLeave={() => setHoverVal(null)}>
      <svg width={width} height={height} style={{ overflow: 'visible' }}>
        <polyline points={points} fill="none" stroke={color} strokeWidth="3" strokeLinejoin="round" strokeLinecap="round" />
        {data.map((v, i) => (
          <circle 
            key={i} 
            cx={(i / (data.length - 1)) * width} 
            cy={height - ((v - min) / range) * height} 
            r="4" 
            fill="transparent" 
            onMouseEnter={() => setHoverVal(v)}
            style={{ cursor: 'pointer' }}
          />
        ))}
      </svg>
      {hoverVal !== null && (
        <div style={{ ...s.sparkTooltip, left: width / 2, bottom: height + 5 }}>
          {label}: {hoverVal.toFixed(1)}
        </div>
      )}
    </div>
  );
}

const s = {
  modalOverlay: {
    position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
    backgroundColor: 'rgba(0,0,0,0.85)', backdropFilter: 'blur(4px)',
    display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 9999
  },
  modalContent: {
    backgroundColor: '#0e1018', border: '1px solid #2e3347', borderRadius: '12px',
    width: '90%', maxWidth: '800px', maxHeight: '90vh', padding: '24px', 
    boxShadow: '0 20px 50px rgba(0,0,0,0.5)',
    display: 'flex', flexDirection: 'column'
  },
  modalHeader: {
    display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexShrink: 0
  },
  modalTitle: { margin: 0, color: '#5dcaa5', fontSize: '18px' },
  closeBtn: {
    background: 'none', border: 'none', color: '#6b7280', fontSize: '24px', cursor: 'pointer'
  },
  modalBody: { color: '#e2e0d6', fontSize: '14px', lineHeight: '1.6', overflowY: 'auto', flex: 1 },
  noData: { color: '#4b5563', fontSize: '12px', padding: '10px' },
  barContainer: { display: 'flex', flexDirection: 'column', gap: '8px' },
  barRow: { 
    display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer',
    padding: '4px', borderRadius: '4px', transition: 'background 0.2s'
  },
  barLabel: { 
    width: '120px', color: '#9ca3af', fontSize: '11px', textAlign: 'right',
    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'
  },
  barTrack: { flex: 1, height: '8px', backgroundColor: '#1a1d27', borderRadius: '4px', overflow: 'hidden' },
  barFill: { height: '100%', borderRadius: '4px', transition: 'width 0.6s cubic-bezier(0.34, 1.56, 0.64, 1)' },
  barValue: { width: '40px', fontSize: '12px', fontWeight: 'bold', textAlign: 'left' },
  sparkTooltip: {
    position: 'absolute', backgroundColor: '#1a1d27', color: '#fff', padding: '2px 6px',
    borderRadius: '4px', fontSize: '10px', pointerEvents: 'none', transform: 'translateX(-50%)',
    border: '1px solid #2e3347'
  }
};
