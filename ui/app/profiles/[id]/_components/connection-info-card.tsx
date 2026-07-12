"use client";

import { useMemo } from "react";
import type { Profile } from "@/src/lib/types";
import { formatDataPlaneAuthMode } from "@/src/lib/display";
import {
  AuthModeBadge,
  Button,
  CopyBlock,
  EndpointWell,
  SectionCard,
  Toggle,
} from "@/components/ui";
import { InfoIconAlt, LockIcon } from "@/components/icons";

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

  const jsonText = useMemo(() => {
    return getMcpJsonText(clientKey, mcpUrl, profile, showAuthSettings ? authDraft : null);
  }, [authDraft, clientKey, mcpUrl, profile, showAuthSettings]);

  return (
    <SectionCard
      title="MCP endpoint URL"
      right={
        <Toggle
          checked={!!profile?.enabled}
          onChange={() => onToggleEnabled()}
          disabled={!profile || toggleEnabledPending}
          label={profile?.enabled ? "Enabled" : "Disabled"}
          switchSide="right"
        />
      }
      className="mb-6"
      bodyClassName="space-y-6"
    >
      <div>
        <div className="flex items-center gap-3">
          <EndpointWell url={mcpUrl} live={!!profile?.enabled} className="min-w-0 flex-1" />
          {profile ? <AuthModeBadge mode={profile.dataPlaneAuth.mode} /> : null}
        </div>
        <p className="mt-3 text-xs text-faint">
          Use this URL in your MCP client configuration. Auth mode:{" "}
          <span className="text-fg">{authModeLabel}</span>.
        </p>
      </div>

      {/* MCP client config */}
      <div className="border-t border-edge pt-5">
        <div className="mb-3 flex items-center justify-between gap-3">
          <h3 className="eyebrow">MCP client config (mcp.json)</h3>
          <div className="flex items-center gap-2">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={onEditAuth}
              disabled={!profile}
              aria-label="Edit profile auth settings"
            >
              <LockIcon className="size-4" />
              Auth
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={onOpenAuthHelp}
              aria-label="How MCP client auth works"
            >
              <InfoIcon className="size-4" />
              Auth help
            </Button>
          </div>
        </div>
        <CopyBlock value={jsonText} language="json" />
      </div>
    </SectionCard>
  );
}
