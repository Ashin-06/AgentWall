import { defineConfig } from "cypress";

// Runs against a real AgentWall server serving the built dashboard (see .github/workflows/verify.yml).
export default defineConfig({
  e2e: {
    baseUrl: process.env.AGENTWALL_URL || "http://127.0.0.1:8000",
    supportFile: false,
    video: false,
    env: {
      password: process.env.AGENTWALL_ADMIN_PASSWORD,
      apiKey: process.env.AGENTWALL_API_KEYS,
    },
  },
});
