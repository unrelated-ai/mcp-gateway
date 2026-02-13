"use client";

import { useMemo } from "react";
import type { Profile } from "@/src/lib/types";
import { formatDataPlaneAuthMode } from "@/src/lib/display";
import { CopyButton, LockIcon, Toggle } from "@/components/ui";
import { InfoIconAlt } from "@/components/icons";

function getMcpJsonText(
  clientKey: string,
  mcpUrl: string,
  profile: Profile | null,
  authOverride: { mode: Profile["dataPlaneAuth"]["mode"]; acceptXApiKey: boolean } | null,
): string {
  const noteFromProfileDescription = profile?.description?.trim() || null;

  const entry: Record<string, unknown> = {
    type: "streamable-http",
    url: mcpUrl,
  };

  const effectiveAuth = authOverride ?? profile?.dataPlaneAuth ?? null;
  const mode = effectiveAuth?.mode ?? null;
  if (mode && mode !== "disabled") {
    if (mode.startsWith("apiKey")) {
      const headers: Record<string, string> = { Authorization: "Bearer <api_key_secret>" };
      if (effectiveAuth?.acceptXApiKey) {
        headers["x-api-key"] = "<api_key_secret>";
      }
      entry.headers = headers;
      entry.note = noteFromProfileDescription
        ? noteFromProfileDescription
        : mode === "apiKeyInitializeOnly"
          ? "Unrelated MCP Gateway profile (API key required only for initialize; compatibility mode, not recommended)"
          : "Unrelated MCP Gateway profile (API key required on every request)";
    } else if (mode.startsWith("jwt")) {
      entry.headers = { Authorization: "Bearer <jwt>" };
      entry.note = noteFromProfileDescription
        ? noteFromProfileDescription
        : "Unrelated MCP Gateway profile (JWT required on every request)";
    }
  } else {
    entry.note = noteFromProfileDescription
      ? noteFromProfileDescription
      : "Unrelated MCP Gateway profile (no auth)";
  }

  return JSON.stringify({ mcpServers: { [clientKey]: entry } }, null, 2);
}

function AuthBadge({ mode }: { mode: "api_key" | "jwt" | "none" }) {
  return (
    <span
      className={`px-2.5 py-1 rounded-full text-xs font-medium ${
        mode === "api_key"
          ? "bg-violet-500/10 text-violet-400 border border-violet-500/20"
          : mode === "jwt"
            ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
            : "bg-zinc-500/10 text-zinc-400 border border-zinc-500/20"
      }`}
    >
      {mode === "api_key" ? "API Key" : mode === "jwt" ? "JWT" : "No Auth"}
    </span>
  );
}

const InfoIcon = InfoIconAlt;

export function ConnectionInfoCard({
  profile,
  mcpUrl,
  clientKey,
  toggleEnabledPending,
  onToggleEnabled,
  onEditAuth,
  onOpenAuthHelp,
  showAuthSettings,
  authDraft,
}: {
  profile: Profile | null;
  mcpUrl: string;
  clientKey: string;
  toggleEnabledPending: boolean;
  onToggleEnabled: () => void;
  onEditAuth: () => void;
  onOpenAuthHelp: () => void;
  showAuthSettings: boolean;
  authDraft: { mode: Profile["dataPlaneAuth"]["mode"]; acceptXApiKey: boolean } | null;
}) {
  const authModeLabel = formatDataPlaneAuthMode(profile?.dataPlaneAuth.mode);
  const authBadgeMode: "api_key" | "jwt" | "none" = profile?.dataPlaneAuth.mode.startsWith("apiKey")
    ? "api_key"
    : profile?.dataPlaneAuth.mode.startsWith("jwt")
      ? "jwt"
      : "none";

  const jsonText = useMemo(() => {
    return getMcpJsonText(clientKey, mcpUrl, profile, showAuthSettings ? authDraft : null);
  }, [authDraft, clientKey, mcpUrl, profile, showAuthSettings]);

  return (
    <div className="rounded-2xl border border-zinc-800/60 bg-gradient-to-br from-violet-500/5 to-transparent p-6 mb-6">
      <div className="flex items-start justify-between gap-6">
        <div>
          <div className="flex items-center justify-between gap-4 mb-2">
            <h2 className="text-sm font-medium text-zinc-400">MCP Endpoint URL</h2>
            <Toggle
              checked={!!profile?.enabled}
              onChange={() => onToggleEnabled()}
              disabled={!profile || toggleEnabledPending}
              label={profile?.enabled ? "Enabled" : "Disabled"}
              switchSide="right"
            />
          </div>
          <div className="flex items-center gap-3">
            <code
              className={`px-4 py-2.5 rounded-xl border text-sm font-mono ${
                profile?.enabled
                  ? "bg-emerald-500/5 border-emerald-500/25 text-emerald-200"
                  : "bg-zinc-950/60 border-zinc-800 text-zinc-200"
              }`}
            >
              {mcpUrl}
            </code>
            <CopyButton text={mcpUrl} />
          </div>
          <p className="mt-3 text-xs text-zinc-500">
            Use this URL in your MCP client configuration. Auth mode:{" "}
            <span className="text-zinc-200">{authModeLabel}</span>.
          </p>
        </div>
        <div className="flex items-center gap-4">
          <AuthBadge mode={authBadgeMode} />
        </div>
      </div>

      {/* Claude Desktop Config */}
      <div className="mt-6 pt-6 border-t border-zinc-800/60">
        <div className="flex items-center justify-between gap-3 mb-3">
          <h3 className="text-sm font-medium text-zinc-300">MCP client config (mcp.json)</h3>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onEditAuth}
              className="inline-flex items-center gap-2 rounded-lg px-2 py-1 text-xs text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60 transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
              aria-label="Edit profile auth settings"
              disabled={!profile}
            >
              <LockIcon className="w-4 h-4" />
              Auth
            </button>
            <button
              type="button"
              onClick={onOpenAuthHelp}
              className="inline-flex items-center gap-2 rounded-lg px-2 py-1 text-xs text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60 transition-colors"
              aria-label="How MCP client auth works"
            >
              <InfoIcon className="w-4 h-4" />
              Auth help
            </button>
          </div>
        </div>
        <div className="relative rounded-xl bg-zinc-950/80 border border-zinc-800 p-4 font-mono text-xs overflow-x-auto">
          <pre className="text-zinc-400">{jsonText}</pre>
          <CopyButton text={jsonText} className="absolute top-3 right-3" />
        </div>
      </div>
    </div>
  );
}
