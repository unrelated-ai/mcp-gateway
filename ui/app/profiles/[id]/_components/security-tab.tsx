"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { SectionCard, Toggle } from "@/components/ui";
import { qk } from "@/src/lib/queryKeys";
import * as tenantApi from "@/src/lib/tenantApi";
import type { McpProfileSettings, Profile, UpstreamSecurityPolicy } from "@/src/lib/types";
import { buildPutProfileBody } from "@/src/lib/profilePut";
import { useQueuedAutosave } from "@/src/lib/useQueuedAutosave";
import {
  INTERACTIVE_REQUEST_METHODS,
  allowsServerRequest,
  asMcpSettings,
  defaultMcpSettings,
  normalizeMcpSettings,
  trustedUpstreamPolicy,
  untrustedUpstreamPolicy,
} from "@/src/lib/mcpSettings";

type Preset = "trusted" | "untrusted" | "custom";
type UpstreamPreset = "default" | Preset;

function isTrustedPolicy(p: UpstreamSecurityPolicy): boolean {
  return (
    p.clientCapabilitiesMode === "passthrough" &&
    p.clientCapabilitiesAllow.length === 0 &&
    p.rewriteClientInfo === false &&
    p.serverRequests.defaultAction === "allow" &&
    p.serverRequests.allow.length === 0 &&
    p.serverRequests.deny.length === 0
  );
}

function isUntrustedPolicy(p: UpstreamSecurityPolicy): boolean {
  return (
    p.clientCapabilitiesMode === "strip" &&
    p.clientCapabilitiesAllow.length === 0 &&
    p.rewriteClientInfo === true &&
    p.serverRequests.defaultAction === "deny" &&
    p.serverRequests.allow.length === 0 &&
    p.serverRequests.deny.length === 0
  );
}

function presetForPolicy(p: UpstreamSecurityPolicy): Preset {
  if (isTrustedPolicy(p)) return "trusted";
  if (isUntrustedPolicy(p)) return "untrusted";
  return "custom";
}

function applyPreset(preset: Preset): UpstreamSecurityPolicy {
  if (preset === "trusted") return trustedUpstreamPolicy();
  if (preset === "untrusted") return untrustedUpstreamPolicy();
  return trustedUpstreamPolicy();
}

function setInteractiveAllowed(p: UpstreamSecurityPolicy, method: string, allowed: boolean) {
  const def = p.serverRequests.defaultAction;
  const allow = new Set(p.serverRequests.allow);
  const deny = new Set(p.serverRequests.deny);

  // Deny wins over allow in the backend; keep lists mutually exclusive for clarity.
  if (def === "allow") {
    if (allowed) deny.delete(method);
    else deny.add(method);
    allow.delete(method);
  } else {
    if (allowed) allow.add(method);
    else allow.delete(method);
    deny.delete(method);
  }

  return {
    ...p,
    serverRequests: {
      defaultAction: def,
      allow: [...allow],
      deny: [...deny],
    },
  };
}

function normalizePolicy(p: UpstreamSecurityPolicy): UpstreamSecurityPolicy {
  // Reuse gateway-like semantics and stable ordering via normalizeMcpSettings.
  return normalizeMcpSettings({
    ...defaultMcpSettings(),
    security: {
      signedProxiedRequestIds: true,
      upstreamDefault: p,
      upstreamOverrides: {},
    },
  }).security.upstreamDefault;
}

export function SecurityTab({ profile }: { profile: Profile | null }) {
  const queryClient = useQueryClient();

  const initialMcp = useMemo<McpProfileSettings>(() => {
    return asMcpSettings(profile?.mcp ?? defaultMcpSettings());
  }, [profile?.mcp]);

  const security = initialMcp.security;
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [showDefaultAdvanced, setShowDefaultAdvanced] = useState<boolean>(() => {
    return presetForPolicy(normalizePolicy(initialMcp.security.upstreamDefault)) === "custom";
  });
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
      setSaveError(e instanceof Error ? e.message : "Failed to save security settings");
    },
  });

  const computeKey = useCallback((m: McpProfileSettings) => JSON.stringify(m), []);
  const autosave = useQueuedAutosave<McpProfileSettings>({
    isPending: saveMutation.isPending,
    mutate: (m) => saveMutation.mutate(m),
    computeKey,
  });

  useEffect(() => {
    autosave.setLastSavedKey(JSON.stringify(initialMcp));
  }, [autosave, initialMcp]);

  const commit = useCallback(
    (nextSecurity: McpProfileSettings["security"]) => {
      if (!profile) return;
      const base = asMcpSettings(profile.mcp);
      const next = normalizeMcpSettings({ ...base, security: nextSecurity });
      // Optimistic UI update: keep the tab responsive while saving.
      queryClient.setQueryData(qk.profile(profile.id), (old: Profile | undefined) => {
        if (!old) return old;
        return { ...old, mcp: next };
      });
      setSaveError(null);
      autosave.commit(next);
    },
    [autosave, profile, queryClient],
  );

  const upstreams = profile?.upstreams ?? [];
  const defaultPreset = presetForPolicy(normalizePolicy(security.upstreamDefault));
  const defaultSelectValue: Preset = showDefaultAdvanced ? "custom" : defaultPreset;

  const setDefaultPreset = (preset: Preset) => {
    if (preset === "custom") {
      setShowDefaultAdvanced(true);
      return;
    }
    setShowDefaultAdvanced(false);
    commit({ ...security, upstreamDefault: normalizePolicy(applyPreset(preset)) });
  };

  const setOverridePreset = (upstreamId: string, preset: UpstreamPreset) => {
    const overrides = { ...security.upstreamOverrides };
    if (preset === "default") {
      delete overrides[upstreamId];
      commit({ ...security, upstreamOverrides: overrides });
      setExpanded((m) => ({ ...m, [upstreamId]: false }));
      return;
    }

    if (preset === "custom") {
      overrides[upstreamId] = normalizePolicy(overrides[upstreamId] ?? security.upstreamDefault);
      commit({ ...security, upstreamOverrides: overrides });
      setExpanded((m) => ({ ...m, [upstreamId]: true }));
      return;
    }

    overrides[upstreamId] = normalizePolicy(applyPreset(preset));
    commit({ ...security, upstreamOverrides: overrides });
    setExpanded((m) => ({ ...m, [upstreamId]: false }));
  };

  const updateOverride = (upstreamId: string, nextPolicy: UpstreamSecurityPolicy) => {
    const overrides = { ...security.upstreamOverrides };
    overrides[upstreamId] = normalizePolicy(nextPolicy);
    commit({ ...security, upstreamOverrides: overrides });
  };

  const updateDefaultPolicy = (nextPolicy: UpstreamSecurityPolicy) => {
    commit({ ...security, upstreamDefault: normalizePolicy(nextPolicy) });
  };

  return (
    <div className="space-y-6">
      <SectionCard
        title="Security"
        subtitle="Control what the Gateway advertises upstream and what upstream interactive requests are allowed through."
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

        <div className="flex items-start justify-between gap-6">
          <div className="min-w-0">
            <div className="text-sm font-semibold text-zinc-100">Signed proxied request IDs</div>
            <div className="mt-1 text-xs text-zinc-500">
              Prevents forged downstream responses by signing proxied upstream request IDs with a
              per-session key.
            </div>
          </div>
          <Toggle
            checked={!!security.signedProxiedRequestIds}
            disabled={!profile || saveMutation.isPending}
            onChange={(checked) => commit({ ...security, signedProxiedRequestIds: checked })}
          />
        </div>

        <div className="rounded-xl border border-zinc-800/60 bg-zinc-950/30 p-4 space-y-3">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="text-sm font-semibold text-zinc-100">Default upstream policy</div>
              <div className="mt-1 text-xs text-zinc-500">
                Applied to upstreams unless a per-upstream override is set.
              </div>
            </div>
            <select
              value={defaultSelectValue}
              disabled={!profile || saveMutation.isPending}
              onChange={(e) => setDefaultPreset(e.target.value as Preset)}
              className="rounded-lg border border-zinc-700/80 bg-zinc-900/50 px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:ring-2 focus:ring-violet-500/50 focus:border-violet-500/50 hover:border-zinc-600/80"
            >
              <option value="trusted">Trusted</option>
              <option value="untrusted">Untrusted</option>
              <option value="custom">Custom</option>
            </select>
          </div>

          {showDefaultAdvanced || defaultPreset === "custom" ? (
            <PolicyEditor
              policy={security.upstreamDefault}
              onChange={updateDefaultPolicy}
              disabled={!profile || saveMutation.isPending}
            />
          ) : null}
        </div>
      </SectionCard>

      <SectionCard
        title="Upstream overrides"
        subtitle="Tune trust and interactive requests per upstream attached to this profile."
        bodyClassName="space-y-4"
      >
        {upstreams.length === 0 ? (
          <div className="text-sm text-zinc-500">No upstreams attached to this profile.</div>
        ) : (
          upstreams.map((upstreamId) => {
            const override = security.upstreamOverrides[upstreamId];
            const basePreset: Preset | null = override
              ? presetForPolicy(normalizePolicy(override))
              : null;
            const isOpen = expanded[upstreamId] ?? basePreset === "custom";
            const preset: UpstreamPreset = !override
              ? "default"
              : isOpen
                ? "custom"
                : basePreset === "trusted" || basePreset === "untrusted"
                  ? basePreset
                  : "custom";
            const effective = normalizePolicy(override ?? security.upstreamDefault);

            return (
              <div
                key={upstreamId}
                className="rounded-xl border border-zinc-800/60 bg-zinc-950/30 p-4 space-y-3"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="text-sm font-semibold text-zinc-100 font-mono break-all">
                      {upstreamId}
                    </div>
                    <div className="mt-1 text-xs text-zinc-500">
                      Effective policy:{" "}
                      <span className="font-semibold text-zinc-300">
                        {preset === "default" ? `default (${defaultPreset})` : preset}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <select
                      value={preset}
                      disabled={!profile || saveMutation.isPending}
                      onChange={(e) =>
                        setOverridePreset(upstreamId, e.target.value as UpstreamPreset)
                      }
                      className="rounded-lg border border-zinc-700/80 bg-zinc-900/50 px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:ring-2 focus:ring-violet-500/50 focus:border-violet-500/50 hover:border-zinc-600/80"
                    >
                      <option value="default">Use default</option>
                      <option value="trusted">Trusted</option>
                      <option value="untrusted">Untrusted</option>
                      <option value="custom">Custom</option>
                    </select>

                    {preset === "custom" ? (
                      <button
                        type="button"
                        onClick={() => setExpanded((m) => ({ ...m, [upstreamId]: !isOpen }))}
                        className="rounded-lg px-3 py-2 text-sm text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60 transition-colors"
                      >
                        {isOpen ? "Hide" : "Edit"}
                      </button>
                    ) : null}
                  </div>
                </div>

                {preset === "custom" && isOpen ? (
                  <PolicyEditor
                    policy={effective}
                    onChange={(p) => updateOverride(upstreamId, p)}
                    disabled={!profile || saveMutation.isPending}
                  />
                ) : null}
              </div>
            );
          })
        )}
      </SectionCard>
    </div>
  );
}

function PolicyEditor({
  policy,
  onChange,
  disabled,
}: {
  policy: UpstreamSecurityPolicy;
  onChange: (next: UpstreamSecurityPolicy) => void;
  disabled: boolean;
}) {
  const interactive = INTERACTIVE_REQUEST_METHODS.map((m) => ({
    method: m,
    allowed: allowsServerRequest(policy, m),
  }));

  const setCapsKey = (key: string, checked: boolean) => {
    const next = new Set(policy.clientCapabilitiesAllow);
    if (checked) next.add(key);
    else next.delete(key);
    onChange({ ...policy, clientCapabilitiesAllow: [...next] });
  };

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <div className="space-y-3">
        <div className="text-sm font-semibold text-zinc-100">Upstream initialize</div>

        <div className="space-y-1.5">
          <label className="block text-xs font-medium text-zinc-400">Client capabilities</label>
          <select
            value={policy.clientCapabilitiesMode}
            disabled={disabled}
            onChange={(e) => {
              const v = e.target.value;
              if (v === "passthrough" || v === "strip" || v === "allowlist") {
                onChange({ ...policy, clientCapabilitiesMode: v });
              }
            }}
            className="w-full rounded-lg border border-zinc-700/80 bg-zinc-900/50 px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:ring-2 focus:ring-violet-500/50 focus:border-violet-500/50 hover:border-zinc-600/80"
          >
            <option value="passthrough">Passthrough</option>
            <option value="strip">Strip</option>
            <option value="allowlist">Allowlist</option>
          </select>
          <div className="text-xs text-zinc-500">
            Controls what the Gateway advertises upstream in{" "}
            <span className="font-mono">initialize.capabilities</span>.
          </div>
        </div>

        {policy.clientCapabilitiesMode === "allowlist" ? (
          <div className="space-y-2">
            <div className="text-xs font-medium text-zinc-400">Allow capability keys</div>
            <div className="flex flex-wrap gap-3">
              {["sampling", "roots", "elicitation"].map((k) => (
                <label key={k} className="inline-flex items-center gap-2 text-sm text-zinc-300">
                  <input
                    type="checkbox"
                    className="accent-violet-500"
                    disabled={disabled}
                    checked={policy.clientCapabilitiesAllow.includes(k)}
                    onChange={(e) => setCapsKey(k, e.target.checked)}
                  />
                  <span className="font-mono text-xs">{k}</span>
                </label>
              ))}
            </div>
          </div>
        ) : null}

        <div className="flex items-start justify-between gap-6">
          <div className="min-w-0">
            <div className="text-sm font-semibold text-zinc-100">Rewrite clientInfo</div>
            <div className="mt-1 text-xs text-zinc-500">
              If enabled, upstreams won’t learn downstream client identity (e.g. Cursor/Claude
              Desktop).
            </div>
          </div>
          <Toggle
            checked={!!policy.rewriteClientInfo}
            disabled={disabled}
            onChange={(checked) => onChange({ ...policy, rewriteClientInfo: checked })}
          />
        </div>
      </div>

      <div className="space-y-3">
        <div className="text-sm font-semibold text-zinc-100">Upstream server → client requests</div>

        <div className="space-y-1.5">
          <label className="block text-xs font-medium text-zinc-400">Default action</label>
          <select
            value={policy.serverRequests.defaultAction}
            disabled={disabled}
            onChange={(e) => {
              const v = e.target.value;
              if (v === "allow" || v === "deny") {
                onChange({
                  ...policy,
                  serverRequests: { ...policy.serverRequests, defaultAction: v },
                });
              }
            }}
            className="w-full rounded-lg border border-zinc-700/80 bg-zinc-900/50 px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:ring-2 focus:ring-violet-500/50 focus:border-violet-500/50 hover:border-zinc-600/80"
          >
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
          </select>
          <div className="text-xs text-zinc-500">
            Controls what upstream-request methods the Gateway forwards over SSE.
          </div>
        </div>

        <div className="space-y-2">
          <div className="text-xs font-medium text-zinc-400">Interactive methods</div>
          <div className="space-y-2">
            {interactive.map(({ method, allowed }) => (
              <div key={method} className="flex items-center justify-between gap-4">
                <div className="min-w-0 font-mono text-xs text-zinc-300 break-all">{method}</div>
                <Toggle
                  checked={allowed}
                  disabled={disabled}
                  onChange={(checked) => {
                    const next = setInteractiveAllowed(policy, method, checked);
                    onChange(next);
                  }}
                />
              </div>
            ))}
          </div>
          <div className="text-xs text-zinc-500">
            When blocked, the Gateway drops the request and replies upstream with a JSON-RPC error.
          </div>
        </div>
      </div>
    </div>
  );
}
