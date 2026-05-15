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
    const finalUrl = `${url}?token=${token}`;
    ws = new WebSocket(finalUrl);
    ws.onopen    = () => { onOpen?.(); };
    ws.onclose   = () => {
      onClose?.();
      if (!closed) {
        reconnectTimer = setTimeout(connect, 3000);
      }
    };
    ws.onmessage = (e) => {
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
