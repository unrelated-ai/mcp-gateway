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
import {
  authSettingsFromDraft,
  buildMcpClientConfig,
  type AuthDraft,
} from "@/src/lib/data-plane-auth";

function getMcpJsonText(
  clientKey: string,
  mcpUrl: string,
  profile: Profile | null,
  authOverride: AuthDraft | null,
): string {
  const effectiveAuth = authOverride
    ? authSettingsFromDraft(authOverride)
    : (profile?.dataPlaneAuth ?? null);
  return buildMcpClientConfig(
    clientKey,
    mcpUrl,
    profile?.description?.trim() || null,
    effectiveAuth,
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
  authDraft: AuthDraft | null;
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
