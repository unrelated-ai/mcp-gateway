"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button, Modal, ModalActions, SectionCard, Toggle } from "@/components/ui";
import { InfoIcon } from "@/components/icons";
import { qk } from "@/src/lib/queryKeys";
import * as tenantApi from "@/src/lib/tenantApi";
import type { McpCapability, McpProfileSettings, Profile } from "@/src/lib/types";
import { buildPutProfileBody } from "@/src/lib/profilePut";
import { useQueuedAutosave } from "@/src/lib/useQueuedAutosave";
import { asMcpSettings, defaultMcpSettings, normalizeMcpSettings } from "@/src/lib/mcpSettings";

const ALL_CAPABILITIES: Array<{
  key: McpCapability;
  label: string;
  description: string;
  help: string;
}> = [
  {
    key: "logging",
    label: "Logging",
    description: "`logging/*` + `notifications/message`",
    help: "Lets clients receive and emit logging-related MCP messages. Useful for debugging and observability in MCP-aware clients.",
  },
  {
    key: "completions",
    label: "Completions",
    description: "`completion/complete`",
    help: "Enables the MCP completion endpoint. Some clients use this to offer autocomplete-like UX powered by the upstream.",
  },
  {
    key: "resources-subscribe",
    label: "Resources subscribe",
    description: "`resources/subscribe`",
    help: "Allows clients to subscribe to resource updates. If disabled, clients can still list/read resources, but won’t receive subscription-driven updates.",
  },
  {
    key: "tools-list-changed",
    label: "Tools list changed",
    description: "`notifications/tools/list_changed`",
    help: "Allows upstreams to notify clients that the tool list changed. Helps clients refresh tool catalogs without polling.",
  },
  {
    key: "resources-list-changed",
    label: "Resources list changed",
    description: "`notifications/resources/list_changed`",
    help: "Allows upstreams to notify clients that the resource list changed. Helps clients refresh resource catalogs without polling.",
  },
  {
    key: "prompts-list-changed",
    label: "Prompts list changed",
    description: "`notifications/prompts/list_changed`",
    help: "Allows upstreams to notify clients that the prompt list changed. Helps clients refresh prompts without polling.",
  },
];

function uniqSortedCaps(xs: McpCapability[]): McpCapability[] {
  const order = new Map<McpCapability, number>(ALL_CAPABILITIES.map((c, i) => [c.key, i]));
  return [...new Set(xs)].sort((a, b) => (order.get(a) ?? 0) - (order.get(b) ?? 0));
}

function enabledCapsFrom(settings: McpProfileSettings): Set<McpCapability> {
  if (settings.capabilities.allow.length > 0) {
    return new Set(settings.capabilities.allow);
  }
  const denied = new Set(settings.capabilities.deny);
  return new Set(ALL_CAPABILITIES.map((c) => c.key).filter((k) => !denied.has(k)));
}

export function McpSettingsCard({ profile }: { profile: Profile | null }) {
  const queryClient = useQueryClient();

  const initial = useMemo(() => {
    return asMcpSettings(profile?.mcp ?? defaultMcpSettings());
  }, [profile?.mcp]);

  const initialEnabled = useMemo(() => enabledCapsFrom(initial), [initial]);
  const [enabledCaps, setEnabledCaps] = useState<Set<McpCapability>>(initialEnabled);
  const [showCapsHelp, setShowCapsHelp] = useState(false);

  const buildNext = useCallback(
    (nextEnabledCaps: Set<McpCapability>): McpProfileSettings => {
      // Keep other (currently-hidden) MCP settings intact for now.
      return normalizeMcpSettings({
        ...initial,
        capabilities: {
          allow: [],
          deny: uniqSortedCaps(
            ALL_CAPABILITIES.map((c) => c.key).filter((k) => !nextEnabledCaps.has(k)),
          ),
        },
      });
    },
    [initial],
  );

  const [saveError, setSaveError] = useState<string | null>(null);

  const saveMutation = useMutation({
    mutationFn: async (nextMcp: McpProfileSettings) => {
      if (!profile) throw new Error("Profile not loaded");
      await tenantApi.putProfile(profile.id, buildPutProfileBody(profile, { mcp: nextMcp }));
      return nextMcp;
    },
    onSuccess: async (nextMcp) => {
      if (!profile) return;
      await queryClient.invalidateQueries({ queryKey: qk.profile(profile.id) });
      await queryClient.invalidateQueries({ queryKey: qk.profiles() });
      queryClient.setQueryData(qk.profile(profile.id), (old: Profile | undefined) => {
        if (!old) return old;
        return { ...old, mcp: nextMcp };
      });
      setSaveError(null);
    },
    onError: (e) => {
      setSaveError(e instanceof Error ? e.message : "Failed to save MCP settings");
    },
  });

  const mcpKey = useCallback((m: McpProfileSettings) => JSON.stringify(m), []);
  const autosave = useQueuedAutosave<McpProfileSettings>({
    isPending: saveMutation.isPending,
    mutate: (m) => saveMutation.mutate(m),
    computeKey: mcpKey,
  });

  useEffect(() => {
    autosave.setLastSavedKey(JSON.stringify(initial));
  }, [autosave, initial]);

  const commit = useCallback(
    (nextMcp: McpProfileSettings) => {
      if (!profile) return;
      autosave.commit(nextMcp);
    },
    [autosave, profile],
  );

  const toggleCap = (cap: McpCapability, checked: boolean) => {
    const nextCaps = new Set(enabledCaps);
    if (checked) nextCaps.add(cap);
    else nextCaps.delete(cap);
    setEnabledCaps(nextCaps);
    commit(buildNext(nextCaps));
  };

  return (
    <SectionCard
      title="MCP proxy settings"
      subtitle="Controls which MCP capabilities are advertised for this profile."
      right={
        saveMutation.isPending ? <div className="text-xs text-zinc-500 px-2">Saving…</div> : null
      }
      bodyClassName="space-y-6"
    >
      {saveError ? (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-200">
          {saveError}
        </div>
      ) : null}

      {/* Capabilities */}
      <div className="space-y-3">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="text-sm font-semibold text-zinc-100">Capabilities</div>
            <div className="mt-1 text-xs text-zinc-500">
              These toggles control what MCP features the Gateway advertises to clients.
            </div>
          </div>
          <button
            type="button"
            onClick={() => setShowCapsHelp(true)}
            className="inline-flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60 transition-colors"
            aria-label="MCP capabilities help"
          >
            <InfoIcon className="w-4 h-4" />
            Help
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {ALL_CAPABILITIES.map((c) => (
            <Toggle
              key={c.key}
              checked={enabledCaps.has(c.key)}
              onChange={(checked) => toggleCap(c.key, checked)}
              label={c.label}
              description={`${c.description} (${c.key})`}
            />
          ))}
        </div>
      </div>

      {!profile ? <div className="text-sm text-zinc-500">Loading profile…</div> : null}
      <Modal open={showCapsHelp} onClose={() => setShowCapsHelp(false)} title="MCP capabilities">
        <div className="space-y-4 text-sm text-zinc-300">
          <p>
            These toggles control what the Gateway advertises as supported capabilities for this
            profile. Disabling a capability hides it from clients and may prevent related behavior.
          </p>
          <div className="space-y-3">
            {ALL_CAPABILITIES.map((c) => (
              <div key={c.key} className="rounded-xl border border-zinc-800/60 bg-zinc-950/30 p-4">
                <div className="flex items-center justify-between gap-3">
                  <div className="text-sm font-semibold text-zinc-100">{c.label}</div>
                  <div className="text-xs font-mono text-zinc-500">{c.key}</div>
                </div>
                <div className="mt-1 text-xs text-zinc-500">{c.description}</div>
                <div className="mt-2 text-sm text-zinc-300">{c.help}</div>
              </div>
            ))}
          </div>
        </div>
        <ModalActions>
          <Button type="button" onClick={() => setShowCapsHelp(false)}>
            Close
          </Button>
        </ModalActions>
      </Modal>
    </SectionCard>
  );
}
