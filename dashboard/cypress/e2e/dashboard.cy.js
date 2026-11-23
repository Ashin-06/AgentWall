// cy.env (Cypress 16+) reads values from cypress.config.mjs `env` without exposing them to the page.
const signIn = (password) => {
  const type = pw => {
    cy.visit("/");
    cy.get("input[type=password]").type(pw, { log: false });
    cy.contains("button", "AUTHORIZE ACCESS").click();
  };
  if (password) type(password);
  else cy.env(["password"]).then(({ password: pw }) => type(pw));
};

describe("AgentWall dashboard", () => {
  const session = `e2e_${Date.now()}`;

  before(() => {
    // Real tool calls through the API: one the policy blocks, one it permits.
    cy.env(["apiKey"]).then(({ apiKey }) => {
      const call = (call_id, tool_name, args) => cy.request({
        method: "POST", url: "/intercept",
        headers: { "X-AgentWall-Key": apiKey },
        body: { session_id: session, agent_id: "e2e-agent", call_id, tool_name, arguments: args },
      }).its("body");
      call("c1", "bash", { command: "rm -rf /" }).its("verdict").should("eq", "BLOCK");
      call("c2", "read_file", { path: "/tmp/notes.md" }).its("verdict").should("not.eq", "BLOCK");
    });
  });

  it("rejects a wrong password", () => {
    signIn("definitely-not-the-password");
    cy.contains("Invalid security credential");
    cy.contains("button", "Sign out").should("not.exist");
  });

  it("shows the blocked call, filters, replays the session and signs out", () => {
    signIn();
    cy.contains("Enforcement enabled");
    cy.contains("e2e-agent");

    cy.get("input[aria-label='Search sessions']").type(session);
    cy.get("[role=button]").should("have.length", 1).and("contain", "e2e-agent").and("contain", "1 blocked").click();
    cy.contains("Loading session events").should("not.exist");
    cy.contains("bash");
    cy.contains("read_file");

    for (const tab of ["Graph", "Mitre", "Campaigns", "Metrics", "Overview"]) {
      cy.contains("nav button", tab).click().should("have.attr", "aria-current", "page");
      cy.get("[role=alert]").should("not.exist");
    }
    cy.contains("nav button", "Metrics").click();
    cy.contains("System Observability");

    cy.contains("button", "Sign out").click();
    cy.contains("AgentWall Login");
    cy.window().its("localStorage.agentwall_token").should("be.undefined");
  });

  it("returns to sign-in when the stored token is invalid", () => {
    cy.visit("/", { onBeforeLoad: win => win.localStorage.setItem("agentwall_token", "not-a-jwt") });
    cy.contains("AgentWall Login");
  });
});
