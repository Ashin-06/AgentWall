import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fetchJSON, filterSessions, agentName } from "../src/api.mjs";

// Load the browser module without changing the Vite configuration's module type.
const wsSource = await readFile(new URL("../src/ws.js", import.meta.url), "utf8");
const { createWSClient } = await import(`data:text/javascript;base64,${Buffer.from(wsSource).toString("base64")}`);

test("HTTP auth and server failures are not treated as empty data", async t => {
  for (const status of [401, 500]) {
    t.mock.method(globalThis, "fetch", async () => ({ ok: false, status }));
    await assert.rejects(fetchJSON("/api/sessions", "test"), error => error.status === status);
    t.mock.restoreAll();
  }
});

test("search combines agent selection and case-insensitive session matching", () => {
  const sessions = [{ agent_id: " Cursor ", session_id: "ABC-123" }, { agent_id: "Aider", session_id: "ABC-456" }];
  assert.deepEqual(filterSessions(sessions, "Cursor", " abc "), [sessions[0]]);
  assert.equal(filterSessions(sessions, null, "aider").length, 1);
  assert.equal(agentName({ agent_id: "  " }), "unknown");
});

test("closing a socket prevents reconnection and late callbacks", t => {
  let socket;
  class FakeSocket {
    static OPEN = 1;
    constructor(url) { this.url = url; socket = this; }
    close() { this.onclose(); }
  }
  t.mock.method(globalThis, "setTimeout", () => { throw new Error("Unexpected reconnect"); });
  const previous = globalThis.WebSocket;
  globalThis.WebSocket = FakeSocket;
  t.after(() => { globalThis.WebSocket = previous; });
  const messages = [];
  const client = createWSClient("ws://localhost/ws", { token: "a&b", onMessage: msg => messages.push(msg), onClose: () => { throw new Error("Late close callback"); } });
  assert.equal(socket.url, "ws://localhost/ws?token=a%26b");
  socket.onmessage({ data: '{"type":"alert","event":{"event_id":"1"}}' });
  assert.equal(messages[0].event.event_id, "1");
  client.close();
  socket.onmessage({ data: '{"type":"alert"}' });
  assert.equal(messages.length, 1);
});
