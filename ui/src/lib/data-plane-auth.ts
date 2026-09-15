import type { DataPlaneAuthSettings } from "@/src/lib/types";

export type AuthDraft = {
  mode: DataPlaneAuthSettings["mode"];
  acceptXApiKey: boolean;
  requiredScopes: string[];
};

export function authDraftFromSettings(auth: DataPlaneAuthSettings): AuthDraft {
  return {
    mode: auth.mode,
    acceptXApiKey: auth.mode === "apiKey" ? auth.acceptXApiKey : false,
    requiredScopes: auth.mode === "oauth" ? auth.requiredScopes : ["mcp:access"],
  };
}

export function authSettingsFromDraft(draft: AuthDraft): DataPlaneAuthSettings {
  if (draft.mode === "disabled") return { mode: "disabled" };
  if (draft.mode === "apiKey") {
    return { mode: "apiKey", acceptXApiKey: draft.acceptXApiKey };
  }
  return { mode: "oauth", requiredScopes: draft.requiredScopes };
}

export function buildMcpClientConfig(
  clientKey: string,
  mcpUrl: string,
  description: string | null,
  auth: DataPlaneAuthSettings | null,
): string {
  const entry: Record<string, unknown> = {
    type: "streamable-http",
    url: mcpUrl,
  };
  if (auth?.mode === "apiKey") {
    entry.headers = { Authorization: "Bearer <api_key_secret>" };
    entry.note = description || "Unrelated MCP Gateway profile (API key required on every request)";
  } else if (auth?.mode === "oauth") {
    entry.note = description || "Unrelated MCP Gateway profile (OAuth discovery enabled)";
  } else {
    entry.note = description || "Unrelated MCP Gateway profile (no auth)";
  }
  return JSON.stringify({ mcpServers: { [clientKey]: entry } }, null, 2);
}
