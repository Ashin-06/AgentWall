export async function fetchJSON(path, token, signal) {
  const response = await fetch(path, {
    headers: { Authorization: `Bearer ${token}` }, signal,
  });
  if (!response.ok) {
    const error = new Error(response.status === 401
      ? "Your session has expired. Please sign in again."
      : `Unable to load data (${response.status}). Please retry.`);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

export const agentName = row => row.agent_id?.trim() || "unknown";

export function filterSessions(sessions, agent, query) {
  const search = query.trim().toLowerCase();
  return sessions.filter(session => (!agent || agentName(session) === agent)
    && (!search || [session.session_id, agentName(session)].some(value =>
      String(value ?? "").toLowerCase().includes(search))));
}
