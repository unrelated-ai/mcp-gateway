"use client";

import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Input, SectionCard, Select, Toggle } from "@/components/ui";
import { qk } from "@/src/lib/queryKeys";
import * as tenantApi from "@/src/lib/tenantApi";
import type {
  McpProfileSettings,
  Profile,
  TransportLimitsSettings,
  UpstreamSecurityPolicy,
} from "@/src/lib/types";
import { useAutosave } from "@/src/lib/useAutosave";
import { SaveStatus } from "@/components/ui/save-status";
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

function parsePositiveIntegerInput(raw: string): number | null {
  if (raw.trim() === "") return null;
  const n = Number(raw);
  if (!Number.isFinite(n)) return null;
  const normalized = Math.floor(n);
  if (normalized <= 0) return null;
  return normalized;
}

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
      transportLimits: {},
    },
  }).security.upstreamDefault;
}

export function SecurityTab({ profile }: { profile: Profile | null }) {
  const queryClient = useQueryClient();

  const initialMcp = useMemo<McpProfileSettings>(() => {
    return asMcpSettings(profile?.mcp ?? defaultMcpSettings());
  }, [profile?.mcp]);

  const [draft, setDraft] = useState<McpProfileSettings["security"] | null>(null);
  const security = draft ?? initialMcp.security;
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [showDefaultAdvanced, setShowDefaultAdvanced] = useState<boolean>(() => {
    return presetForPolicy(normalizePolicy(initialMcp.security.upstreamDefault)) === "custom";
  });

  const tenantTransportLimitsQuery = useQuery({
    queryKey: qk.tenantTransportLimits(),
    queryFn: async () => {
      return await tenantApi.getTenantTransportLimits();
    },
  });

  const autosave = useAutosave<McpProfileSettings["security"]>(async (nextSecurity) => {
    if (!profile) throw new Error("Profile not loaded");
    await tenantApi.updateProfile(profile.id, (current) => ({
      mcp: normalizeMcpSettings({ ...asMcpSettings(current.mcp), security: nextSecurity }),
    }));
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: qk.profile(profile.id) }),
      queryClient.invalidateQueries({ queryKey: qk.profiles() }),
    ]);
  });

  const commit = (nextSecurity: McpProfileSettings["security"]) => {
    setDraft(nextSecurity);
    autosave.commit(nextSecurity);
  };

  const upstreams = profile?.upstreams ?? [];
  const defaultPreset = presetForPolicy(normalizePolicy(security.upstreamDefault));
  const defaultSelectValue: Preset = showDefaultAdvanced ? "custom" : defaultPreset;

  const DEFAULT_MAX_POST_BODY_BYTES = 4 * 1024 * 1024;
  const DEFAULT_MAX_SSE_EVENT_BYTES = 8 * 1024 * 1024;
  const tenantTransportLimits = tenantTransportLimitsQuery.data ?? null;

  const profileTransportLimits: TransportLimitsSettings = security.transportLimits ?? {};
  const usesTenantDefaults = Object.values(profileTransportLimits).every((v) => v == null);
  const effectiveMaxPostBodyBytes =
    profileTransportLimits.maxPostBodyBytes ??
    tenantTransportLimits?.maxPostBodyBytes ??
    DEFAULT_MAX_POST_BODY_BYTES;
  const effectiveMaxSseEventBytes =
    profileTransportLimits.maxSseEventBytes ??
    tenantTransportLimits?.maxSseEventBytes ??
    DEFAULT_MAX_SSE_EVENT_BYTES;

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
        bodyClassName="space-y-6"
      >
        <SaveStatus {...autosave} onRetry={autosave.retry} label="Security settings" />

        <div className="flex items-start justify-between gap-6">
          <div className="min-w-0">
            <div className="text-sm font-medium text-fg">Signed proxied request IDs</div>
            <div className="mt-1 text-xs text-faint">
              Prevents forged downstream responses by signing proxied upstream request IDs with a
              per-session key.
            </div>
          </div>
          <Toggle
            checked={!!security.signedProxiedRequestIds}
            disabled={!profile || autosave.status === "saving"}
            onChange={(checked) => commit({ ...security, signedProxiedRequestIds: checked })}
          />
        </div>

        <div className="rounded-lg border border-edge bg-well p-4 space-y-3">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="eyebrow">Default upstream policy</div>
              <div className="mt-1 text-xs text-faint">
                Applied to upstreams unless a per-upstream override is set.
              </div>
            </div>
            <div className="w-36 shrink-0">
              <Select
                aria-label="Default upstream policy preset"
                value={defaultSelectValue}
                disabled={!profile || autosave.status === "saving"}
                onChange={(e) => setDefaultPreset(e.target.value as Preset)}
              >
                <option value="trusted">Trusted</option>
                <option value="untrusted">Untrusted</option>
                <option value="custom">Custom</option>
              </Select>
            </div>
          </div>

          {showDefaultAdvanced || defaultPreset === "custom" ? (
            <PolicyEditor
              policy={security.upstreamDefault}
              onChange={updateDefaultPolicy}
              disabled={!profile || autosave.status === "saving"}
            />
          ) : null}
        </div>
      </SectionCard>

      <SectionCard
        title="Transport limits"
        subtitle="Per-profile transport limits. When disabled, the profile uses tenant defaults from /settings."
        bodyClassName="space-y-4"
      >
        <div className="flex items-start justify-between gap-6">
          <div className="min-w-0">
            <div className="text-sm font-medium text-fg">Use tenant defaults</div>
            <div className="mt-1 text-xs text-faint">
              If enabled, this profile inherits tenant-level transport limits.
            </div>
          </div>
          <Toggle
            checked={usesTenantDefaults}
            disabled={!profile || autosave.status === "saving"}
            onChange={(checked) => {
              if (checked) {
                commit({ ...security, transportLimits: {} });
                return;
              }
              commit({
                ...security,
                transportLimits: {
                  ...profileTransportLimits,
                  maxPostBodyBytes: effectiveMaxPostBodyBytes,
                  maxSseEventBytes: effectiveMaxSseEventBytes,
                },
              });
            }}
          />
        </div>

        <div className="rounded-lg border border-edge bg-well p-4 space-y-3">
          <div className="eyebrow">Max POST body bytes</div>
          <div className="text-xs text-faint">
            Effective: <code className="font-mono text-muted">{effectiveMaxPostBodyBytes}</code> (~
            {Math.round((effectiveMaxPostBodyBytes / 1024 / 1024) * 10) / 10} MiB)
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {[1, 4, 8, 16, 32].map((mib) => {
              const bytes = mib * 1024 * 1024;
              return (
                <button
                  key={mib}
                  type="button"
                  disabled={usesTenantDefaults || !profile || autosave.status === "saving"}
                  onClick={() =>
                    commit({
                      ...security,
                      transportLimits: { ...profileTransportLimits, maxPostBodyBytes: bytes },
                    })
                  }
                  className={`h-8 rounded-md border px-3 text-xs font-medium transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-50 ${
                    effectiveMaxPostBodyBytes === bytes
                      ? "border-accent/40 bg-accent/10 text-accent"
                      : "border-edge bg-surface text-muted hover:bg-raised hover:text-fg"
                  }`}
                >
                  {mib} MiB
                </button>
              );
            })}
            <div className="w-[220px] max-w-full">
              <Input
                type="number"
                min={1}
                step={1}
                aria-label="Custom max POST body bytes"
                disabled={usesTenantDefaults || !profile || autosave.status === "saving"}
                value={
                  usesTenantDefaults
                    ? effectiveMaxPostBodyBytes
                    : (profileTransportLimits.maxPostBodyBytes ?? "")
                }
                onChange={(e) => {
                  const v = parsePositiveIntegerInput(e.target.value);
                  commit({
                    ...security,
                    transportLimits: { ...profileTransportLimits, maxPostBodyBytes: v },
                  });
                }}
              />
            </div>
          </div>
        </div>

        <div className="rounded-lg border border-edge bg-well p-4 space-y-3">
          <div className="eyebrow">Max SSE event bytes</div>
          <div className="text-xs text-faint">
            Effective: <code className="font-mono text-muted">{effectiveMaxSseEventBytes}</code> (~
            {Math.round((effectiveMaxSseEventBytes / 1024 / 1024) * 10) / 10} MiB)
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {[1, 4, 8, 16, 32].map((mib) => {
              const bytes = mib * 1024 * 1024;
              return (
                <button
                  key={mib}
                  type="button"
                  disabled={usesTenantDefaults || !profile || autosave.status === "saving"}
                  onClick={() =>
                    commit({
                      ...security,
                      transportLimits: { ...profileTransportLimits, maxSseEventBytes: bytes },
                    })
                  }
                  className={`h-8 rounded-md border px-3 text-xs font-medium transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-50 ${
                    effectiveMaxSseEventBytes === bytes
                      ? "border-accent/40 bg-accent/10 text-accent"
                      : "border-edge bg-surface text-muted hover:bg-raised hover:text-fg"
                  }`}
                >
                  {mib} MiB
                </button>
              );
            })}
            <div className="w-[220px] max-w-full">
              <Input
                type="number"
                min={1}
                step={1}
                aria-label="Custom max SSE event bytes"
                disabled={usesTenantDefaults || !profile || autosave.status === "saving"}
                value={
                  usesTenantDefaults
                    ? effectiveMaxSseEventBytes
                    : (profileTransportLimits.maxSseEventBytes ?? "")
                }
                onChange={(e) => {
                  const v = parsePositiveIntegerInput(e.target.value);
                  commit({
                    ...security,
                    transportLimits: { ...profileTransportLimits, maxSseEventBytes: v },
                  });
                }}
              />
            </div>
          </div>
        </div>

        <div className="rounded-lg border border-edge bg-well p-4 space-y-3">
          <div className="eyebrow">JSON complexity caps (optional)</div>
          <div className="text-xs text-faint">
            These apply after parsing JSON. Leave blank to inherit tenant defaults / process
            defaults.
          </div>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Input
              type="number"
              min={1}
              step={1}
              label="Max depth"
              placeholder="Inherit"
              disabled={usesTenantDefaults || !profile || autosave.status === "saving"}
              value={profileTransportLimits.maxJsonDepth ?? ""}
              onChange={(e) => {
                const v = parsePositiveIntegerInput(e.target.value);
                commit({
                  ...security,
                  transportLimits: { ...profileTransportLimits, maxJsonDepth: v },
                });
              }}
            />
            <Input
              type="number"
              min={1}
              step={1}
              label="Max array length"
              placeholder="Inherit"
              disabled={usesTenantDefaults || !profile || autosave.status === "saving"}
              value={profileTransportLimits.maxJsonArrayLen ?? ""}
              onChange={(e) => {
                const v = parsePositiveIntegerInput(e.target.value);
                commit({
                  ...security,
                  transportLimits: { ...profileTransportLimits, maxJsonArrayLen: v },
                });
              }}
            />
            <Input
              type="number"
              min={1}
              step={1}
              label="Max object keys"
              placeholder="Inherit"
              disabled={usesTenantDefaults || !profile || autosave.status === "saving"}
              value={profileTransportLimits.maxJsonObjectKeys ?? ""}
              onChange={(e) => {
                const v = parsePositiveIntegerInput(e.target.value);
                commit({
                  ...security,
                  transportLimits: { ...profileTransportLimits, maxJsonObjectKeys: v },
                });
              }}
            />
            <Input
              type="number"
              min={1}
              step={1}
              label="Max string bytes"
              placeholder="Inherit"
              disabled={usesTenantDefaults || !profile || autosave.status === "saving"}
              value={profileTransportLimits.maxJsonStringBytes ?? ""}
              onChange={(e) => {
                const v = parsePositiveIntegerInput(e.target.value);
                commit({
                  ...security,
                  transportLimits: { ...profileTransportLimits, maxJsonStringBytes: v },
                });
              }}
            />
          </div>

          {tenantTransportLimitsQuery.isError ? (
            <div className="mt-2 text-xs text-danger">Failed to load tenant defaults.</div>
          ) : null}
        </div>
      </SectionCard>

      <SectionCard
        title="Upstream overrides"
        subtitle="Tune trust and interactive requests per upstream attached to this profile."
        bodyClassName="space-y-4"
      >
        {upstreams.length === 0 ? (
          <div className="text-sm text-muted">No upstreams attached to this profile.</div>
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
              <div key={upstreamId} className="rounded-lg border border-edge bg-well p-4 space-y-3">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="font-mono text-sm font-medium text-fg break-all">
                      {upstreamId}
                    </div>
                    <div className="mt-1 text-xs text-faint">
                      Effective policy:{" "}
                      <span className="font-medium text-muted">
                        {preset === "default" ? `default (${defaultPreset})` : preset}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <div className="w-40 shrink-0">
                      <Select
                        aria-label={`Policy preset for ${upstreamId}`}
                        value={preset}
                        disabled={!profile || autosave.status === "saving"}
                        onChange={(e) =>
                          setOverridePreset(upstreamId, e.target.value as UpstreamPreset)
                        }
                      >
                        <option value="default">Use default</option>
                        <option value="trusted">Trusted</option>
                        <option value="untrusted">Untrusted</option>
                        <option value="custom">Custom</option>
                      </Select>
                    </div>

                    {preset === "custom" ? (
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        onClick={() => setExpanded((m) => ({ ...m, [upstreamId]: !isOpen }))}
                      >
                        {isOpen ? "Hide" : "Edit"}
                      </Button>
                    ) : null}
                  </div>
                </div>

                {preset === "custom" && isOpen ? (
                  <PolicyEditor
                    policy={effective}
                    onChange={(p) => updateOverride(upstreamId, p)}
                    disabled={!profile || autosave.status === "saving"}
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
        <div className="eyebrow">Upstream initialize</div>

        <div className="space-y-1.5">
          <Select
            label="Client capabilities"
            value={policy.clientCapabilitiesMode}
            disabled={disabled}
            onChange={(e) => {
              const v = e.target.value;
              if (v === "passthrough" || v === "strip" || v === "allowlist") {
                onChange({ ...policy, clientCapabilitiesMode: v });
              }
            }}
          >
            <option value="passthrough">Passthrough</option>
            <option value="strip">Strip</option>
            <option value="allowlist">Allowlist</option>
          </Select>
          <div className="text-xs text-faint">
            Controls what the Gateway advertises upstream in{" "}
            <span className="font-mono">initialize.capabilities</span>.
          </div>
        </div>

        {policy.clientCapabilitiesMode === "allowlist" ? (
          <div className="space-y-2">
            <div className="eyebrow">Allow capability keys</div>
            <div className="space-y-2">
              {["sampling", "roots", "elicitation"].map((k) => (
                <div key={k} className="flex items-center justify-between gap-4">
                  <div className="min-w-0 font-mono text-xs text-muted break-all">{k}</div>
                  <Toggle
                    checked={policy.clientCapabilitiesAllow.includes(k)}
                    disabled={disabled}
                    onChange={(checked) => setCapsKey(k, checked)}
                  />
                </div>
              ))}
            </div>
          </div>
        ) : null}

        <div className="flex items-start justify-between gap-6">
          <div className="min-w-0">
            <div className="text-sm font-medium text-fg">Rewrite clientInfo</div>
            <div className="mt-1 text-xs text-faint">
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
        <div className="eyebrow">Upstream server → client requests</div>

        <div className="space-y-1.5">
          <Select
            label="Default action"
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
          >
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
          </Select>
          <div className="text-xs text-faint">
            Controls what upstream-request methods the Gateway forwards over SSE.
          </div>
        </div>

        <div className="space-y-2">
          <div className="eyebrow">Interactive methods</div>
          <div className="space-y-2">
            {interactive.map(({ method, allowed }) => (
              <div key={method} className="flex items-center justify-between gap-4">
                <div className="min-w-0 font-mono text-xs text-muted break-all">{method}</div>
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
          <div className="text-xs text-faint">
            When blocked, the Gateway drops the request and replies upstream with a JSON-RPC error.
          </div>
        </div>
      </div>
    </div>
  );
}
