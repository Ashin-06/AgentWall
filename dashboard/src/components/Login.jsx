import { useState } from "react";

export default function Login({ onLogin, error: externalError }) {
  const [password, setPassword] = useState("");
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState(externalError || "");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      await onLogin(password);
    } catch (err) {
      setError("Invalid security credential");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={s.container}>
      <div style={s.card}>
        <div style={s.logoArea}>
          <span style={s.icon}>🛡️</span>
          <h1 style={s.title}>AgentWall Login</h1>
          <p style={s.subtitle}>Enter administrative credential to access telemetry</p>
        </div>
        
        <form onSubmit={handleSubmit} style={s.form}>
          <div style={s.inputGroup}>
            <label style={s.label}>ADMIN_PASSWORD</label>
            <input 
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              style={s.input}
              autoFocus
            />
          </div>
          
          {error && <div style={s.error}>{error}</div>}
          
          <button type="submit" disabled={loading} style={s.button}>
            {loading ? "AUTHENTICATING..." : "AUTHORIZE ACCESS"}
          </button>
        </form>
        
        <div style={s.footer}>
          <div style={s.securityBadge}>
            <span style={s.dot} />
            ENCRYPTED CHANNEL
          </div>
        </div>
      </div>
    </div>
  );
}

const s = {
  container: {
    height: "100vh",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    background: "radial-gradient(circle at 50% 50%, #1a1d27 0%, #0a0c14 100%)",
    fontFamily: "'JetBrains Mono', monospace",
  },
  card: {
    background: "#0e1018",
    border: "1px solid #1a1d27",
    padding: "40px",
    borderRadius: "12px",
    width: "100%",
    maxWidth: "400px",
    boxShadow: "0 20px 50px rgba(0,0,0,0.5)",
  },
  logoArea: {
    textAlign: "center",
    marginBottom: "32px",
  },
  icon: {
    fontSize: "48px",
    display: "block",
    marginBottom: "16px",
  },
  title: {
    fontSize: "20px",
    fontWeight: "700",
    color: "#5dcaa5",
    margin: "0 0 8px 0",
    letterSpacing: "-0.5px",
  },
  subtitle: {
    fontSize: "11px",
    color: "#4b5563",
    margin: 0,
    textTransform: "uppercase",
    letterSpacing: "0.5px",
  },
  form: {
    display: "flex",
    flexDirection: "column",
    gap: "24px",
  },
  inputGroup: {
    display: "flex",
    flexDirection: "column",
    gap: "8px",
  },
  label: {
    fontSize: "10px",
    fontWeight: "700",
    color: "#3d4052",
    letterSpacing: "1px",
  },
  input: {
    background: "#0a0c14",
    border: "1px solid #1a1d27",
    padding: "12px 16px",
    borderRadius: "6px",
    color: "#e2e0d6",
    fontSize: "14px",
    fontFamily: "inherit",
    outline: "none",
    transition: "border-color 0.2s",
    "&:focus": {
      borderColor: "#5dcaa5",
    }
  },
  button: {
    background: "#5dcaa5",
    color: "#0a0c14",
    border: "none",
    padding: "14px",
    borderRadius: "6px",
    fontSize: "12px",
    fontWeight: "800",
    cursor: "pointer",
    transition: "transform 0.1s, filter 0.2s",
    "&:active": {
      transform: "scale(0.98)",
    },
    "&:hover": {
      filter: "brightness(1.1)",
    }
  },
  error: {
    fontSize: "11px",
    color: "#f09999",
    textAlign: "center",
    background: "rgba(240, 153, 153, 0.1)",
    padding: "8px",
    borderRadius: "4px",
    border: "1px solid rgba(240, 153, 153, 0.2)",
  },
  footer: {
    marginTop: "32px",
    display: "flex",
    justifyContent: "center",
  },
  securityBadge: {
    fontSize: "9px",
    color: "#3d4052",
    display: "flex",
    alignItems: "center",
    gap: "6px",
    letterSpacing: "1px",
  },
  dot: {
    width: "6px",
    height: "6px",
    borderRadius: "50%",
    background: "#5dcaa5",
    boxShadow: "0 0 5px #5dcaa5",
  }
};
