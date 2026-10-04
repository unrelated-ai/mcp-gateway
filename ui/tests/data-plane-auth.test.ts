import assert from "node:assert/strict";
import test from "node:test";
import {
  authDraftFromSettings,
  authSettingsFromDraft,
  buildMcpClientConfig,
} from "../src/lib/data-plane-auth";

test("data-plane auth drafts preserve discriminated settings", () => {
  const oauth = { mode: "oauth" as const, requiredScopes: ["mcp:access", "tools:read"] };
  assert.deepEqual(authSettingsFromDraft(authDraftFromSettings(oauth)), oauth);
  assert.deepEqual(authSettingsFromDraft(authDraftFromSettings({ mode: "disabled" })), {
    mode: "disabled",
  });
  assert.deepEqual(
    authSettingsFromDraft(authDraftFromSettings({ mode: "apiKey", acceptXApiKey: true })),
    { mode: "apiKey", acceptXApiKey: true },
  );
});

test("OAuth MCP client config contains only the URL and no JWT header", () => {
  const json = JSON.parse(
    buildMcpClientConfig("gateway", "https://mcp.example/profile/mcp", null, {
      mode: "oauth",
      requiredScopes: ["mcp:access"],
    }),
  );
  assert.equal(json.mcpServers.gateway.url, "https://mcp.example/profile/mcp");
  assert.equal(json.mcpServers.gateway.headers, undefined);
});

test("API-key MCP client config uses only the preferred bearer header", () => {
  const json = JSON.parse(
    buildMcpClientConfig("gateway", "https://mcp.example/profile/mcp", null, {
      mode: "apiKey",
      acceptXApiKey: true,
    }),
  );
  assert.deepEqual(json.mcpServers.gateway.headers, {
    Authorization: "Bearer <api_key_secret>",
  });
});
