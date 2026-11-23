/**
 * WebSocket client with auto-reconnect.
 * Subscribes to AgentWall real-time alert stream.
 */
export function createWSClient(url, { onOpen, onClose, onMessage, token }) {
  let ws = null;
  let reconnectTimer = null;
  let closed = false;

  function connect() {
    if (!token) {
      console.warn("[WS] Aborting connection: No security token provided.");
      return;
    }
    // The token is sent as the first message so it never appears in URLs or access logs.
    ws = new WebSocket(url);
    ws.onopen    = () => {
      ws.send(JSON.stringify({ type: "auth", token }));
      if (!closed) onOpen?.();
    };
    ws.onclose   = () => {
      if (!closed) onClose?.();
      if (!closed) {
        reconnectTimer = setTimeout(connect, 3000);
      }
    };
    ws.onmessage = (e) => {
      if (closed) return;
      try { onMessage?.(JSON.parse(e.data)); }
      catch {}
    };
  }

  connect();

  return {
    send: (data) => ws?.readyState === WebSocket.OPEN && ws.send(JSON.stringify(data)),
    close: () => { closed = true; clearTimeout(reconnectTimer); ws?.close(); },
  };
}
