"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import { useQuery } from "@tanstack/react-query";
import { Button, ConfirmModal, CopyButton, Input, Select } from "@/components/ui";
import { SectionCard, Toggle } from "@/components/ui";
import { qk } from "@/src/lib/queryKeys";
import { getTenantExpFromCookies, lockTenantSession } from "@/src/lib/tenant-session";
import { LockIcon } from "@/components/icons";
import { GATEWAY_DATA_BASE, UI_VERSION } from "@/src/lib/env";
import { useToastStore } from "@/src/lib/toast-store";
import { useMutation } from "@tanstack/react-query";
import {
  getTenantAuditSettings,
  getTenantTransportLimits,
  putTenantAuditSettings,
  putTenantTransportLimits,
} from "@/src/lib/tenantApi";
import type { TenantAuditSettings, TenantTransportLimitsSettings } from "@/src/lib/types";

export const dynamic = "force-dynamic";

type GatewayStatusResponse =
  | {
      ok: true;
      status: {
        version?: string;
        license?: string;
        uptimeSecs?: number;
        configLoaded?: boolean;
        profileCount?: number;
        oauthConfigured?: boolean;
        oauthIssuer?: string;
        publicDataBaseUrl?: string;
      };
    }
  | { ok: false; error?: string; status?: number };

function parsePositiveIntegerInput(raw: string): number | null {
  if (raw.trim() === "") return null;
  const n = Number(raw);
  if (!Number.isFinite(n)) return null;
  const normalized = Math.floor(n);
  if (normalized <= 0) return null;
  return normalized;
}

export default function SettingsPage() {
  const [showConfirmLock, setShowConfirmLock] = useState(false);
  const toast = useToastStore((s) => s.push);
  const dataBase = GATEWAY_DATA_BASE;
  const uiVersion = UI_VERSION;
  const exp = getTenantExpFromCookies();
  const expHuman = exp ? new Date(exp * 1000).toLocaleString() : "unknown";
  const gatewayStatusQuery = useQuery({
    queryKey: qk.gatewayStatus(),
    queryFn: async () => {
      const res = await fetch("/api/gateway/status", { cache: "no-store" });
      if (!res.ok) {
        return { ok: false, status: res.status } satisfies GatewayStatusResponse;
      }
      return (await res.json()) as GatewayStatusResponse;
    },
  });
  const gatewayStatus = gatewayStatusQuery.data ?? null;
  const gatewayVersionLabel = gatewayStatusQuery.isPending
    ? "loading…"
    : gatewayStatus?.ok
      ? gatewayStatus.status.version
        ? `v${gatewayStatus.status.version}`
        : "unknown"
      : "unavailable";
  const gatewayLicenseLabel = gatewayStatusQuery.isPending
    ? "loading…"
    : gatewayStatus?.ok
      ? (gatewayStatus.status.license ?? "unknown")
      : "unavailable";

  const auditSettingsQuery = useQuery({
    queryKey: qk.tenantAuditSettings(),
    queryFn: async () => {
      return await getTenantAuditSettings();
    },
  });

  const transportLimitsQuery = useQuery({
    queryKey: qk.tenantTransportLimits(),
    queryFn: async () => {
      return await getTenantTransportLimits();
    },
  });

  const [auditEnabledDraft, setAuditEnabledDraft] = useState<boolean | null>(null);
  const [auditRetentionDaysDraft, setAuditRetentionDaysDraft] = useState<number | null>(null);
  const [auditDefaultLevelDraft, setAuditDefaultLevelDraft] = useState<string | null>(null);

  const DEFAULT_MAX_POST_BODY_BYTES = 4 * 1024 * 1024;
  const DEFAULT_MAX_SSE_EVENT_BYTES = 8 * 1024 * 1024;

  const [maxPostBodyBytesDraft, setMaxPostBodyBytesDraft] = useState<number | null>(null);
  const [maxSseEventBytesDraft, setMaxSseEventBytesDraft] = useState<number | null>(null);
  const [maxJsonDepthDraft, setMaxJsonDepthDraft] = useState<number | null>(null);
  const [maxJsonArrayLenDraft, setMaxJsonArrayLenDraft] = useState<number | null>(null);
  const [maxJsonObjectKeysDraft, setMaxJsonObjectKeysDraft] = useState<number | null>(null);
  const [maxJsonStringBytesDraft, setMaxJsonStringBytesDraft] = useState<number | null>(null);

  const effectiveAuditSettings: TenantAuditSettings | null = auditSettingsQuery.data ?? null;
  const draftEnabled = auditEnabledDraft ?? effectiveAuditSettings?.enabled ?? false;
  const draftRetentionDays = auditRetentionDaysDraft ?? effectiveAuditSettings?.retentionDays ?? 30;
  const draftDefaultLevel =
    auditDefaultLevelDraft ?? effectiveAuditSettings?.defaultLevel ?? "metadata";

  const effectiveTransportLimits: TenantTransportLimitsSettings | null =
    transportLimitsQuery.data ?? null;
  const draftMaxPostBodyBytes =
    maxPostBodyBytesDraft ??
    effectiveTransportLimits?.maxPostBodyBytes ??
    DEFAULT_MAX_POST_BODY_BYTES;
  const draftMaxSseEventBytes =
    maxSseEventBytesDraft ??
    effectiveTransportLimits?.maxSseEventBytes ??
    DEFAULT_MAX_SSE_EVENT_BYTES;
  const draftMaxJsonDepth = maxJsonDepthDraft ?? effectiveTransportLimits?.maxJsonDepth ?? null;
  const draftMaxJsonArrayLen =
    maxJsonArrayLenDraft ?? effectiveTransportLimits?.maxJsonArrayLen ?? null;
  const draftMaxJsonObjectKeys =
    maxJsonObjectKeysDraft ?? effectiveTransportLimits?.maxJsonObjectKeys ?? null;
  const draftMaxJsonStringBytes =
    maxJsonStringBytesDraft ?? effectiveTransportLimits?.maxJsonStringBytes ?? null;

  const saveAuditSettingsMutation = useMutation({
    mutationFn: async (settings: TenantAuditSettings) => {
      return await putTenantAuditSettings(settings);
    },
    onSuccess: async () => {
      await auditSettingsQuery.refetch();
    },
    onError: (e) => {
      toast({
        title: "Failed to save audit settings",
        message: e instanceof Error ? e.message : "Request failed",
        variant: "error",
      });
    },
  });

  const saveTransportLimitsMutation = useMutation({
    mutationFn: async (settings: TenantTransportLimitsSettings) => {
      return await putTenantTransportLimits(settings);
    },
    onSuccess: async () => {
      await transportLimitsQuery.refetch();
    },
    onError: (e) => {
      toast({
        title: "Failed to save transport limits",
        message: e instanceof Error ? e.message : "Request failed",
        variant: "error",
      });
    },
  });

  const transportLimitsDebounceRef = useRef<number | null>(null);
  const transportLimitsLastSavedKeyRef = useRef<string | null>(null);

  const desiredSettings: TenantAuditSettings | null = useMemo(() => {
    if (!effectiveAuditSettings) return null;
    return {
      enabled: draftEnabled,
      retentionDays: draftRetentionDays,
      defaultLevel: draftDefaultLevel,
    };
  }, [effectiveAuditSettings, draftDefaultLevel, draftEnabled, draftRetentionDays]);

  const desiredTransportLimits: TenantTransportLimitsSettings | null = useMemo(() => {
    if (!effectiveTransportLimits) return null;
    return {
      maxPostBodyBytes: draftMaxPostBodyBytes,
      maxSseEventBytes: draftMaxSseEventBytes,
      maxJsonDepth: draftMaxJsonDepth,
      maxJsonArrayLen: draftMaxJsonArrayLen,
      maxJsonObjectKeys: draftMaxJsonObjectKeys,
      maxJsonStringBytes: draftMaxJsonStringBytes,
    };
  }, [
    draftMaxJsonArrayLen,
    draftMaxJsonDepth,
    draftMaxJsonObjectKeys,
    draftMaxJsonStringBytes,
    draftMaxPostBodyBytes,
    draftMaxSseEventBytes,
    effectiveTransportLimits,
  ]);

  const effectiveTransportLimitsBaseline: TenantTransportLimitsSettings | null = useMemo(() => {
    if (!effectiveTransportLimits) return null;
    return {
      maxPostBodyBytes: effectiveTransportLimits.maxPostBodyBytes ?? DEFAULT_MAX_POST_BODY_BYTES,
      maxSseEventBytes: effectiveTransportLimits.maxSseEventBytes ?? DEFAULT_MAX_SSE_EVENT_BYTES,
      maxJsonDepth: effectiveTransportLimits.maxJsonDepth ?? null,
      maxJsonArrayLen: effectiveTransportLimits.maxJsonArrayLen ?? null,
      maxJsonObjectKeys: effectiveTransportLimits.maxJsonObjectKeys ?? null,
      maxJsonStringBytes: effectiveTransportLimits.maxJsonStringBytes ?? null,
    };
  }, [DEFAULT_MAX_POST_BODY_BYTES, DEFAULT_MAX_SSE_EVENT_BYTES, effectiveTransportLimits]);

  // Autosave: debounce changes and only send when settings differ from the last known server value.
  const debounceRef = useRef<number | null>(null);
  const lastSavedKeyRef = useRef<string | null>(null);

  useEffect(() => {
    if (!effectiveAuditSettings || !desiredSettings) return;
    if (auditSettingsQuery.isPending || auditSettingsQuery.isError) return;

    const serverKey = JSON.stringify(effectiveAuditSettings);
    const desiredKey = JSON.stringify(desiredSettings);
    if (desiredKey === serverKey) return;
    if (desiredKey === lastSavedKeyRef.current) return;

    if (debounceRef.current != null) {
      window.clearTimeout(debounceRef.current);
    }
    debounceRef.current = window.setTimeout(() => {
      lastSavedKeyRef.current = desiredKey;
      saveAuditSettingsMutation.mutate(desiredSettings);
    }, 350);

    return () => {
      if (debounceRef.current != null) window.clearTimeout(debounceRef.current);
    };
  }, [
    auditSettingsQuery.isError,
    auditSettingsQuery.isPending,
    desiredSettings,
    effectiveAuditSettings,
    saveAuditSettingsMutation,
  ]);

  useEffect(() => {
    if (!effectiveTransportLimitsBaseline || !desiredTransportLimits) return;
    if (transportLimitsQuery.isPending || transportLimitsQuery.isError) return;

    const serverKey = JSON.stringify(effectiveTransportLimitsBaseline);
    const desiredKey = JSON.stringify(desiredTransportLimits);
    if (desiredKey === serverKey) return;
    if (desiredKey === transportLimitsLastSavedKeyRef.current) return;

    if (transportLimitsDebounceRef.current != null) {
      window.clearTimeout(transportLimitsDebounceRef.current);
    }
    transportLimitsDebounceRef.current = window.setTimeout(() => {
      transportLimitsLastSavedKeyRef.current = desiredKey;
      saveTransportLimitsMutation.mutate(desiredTransportLimits);
    }, 350);

    return () => {
      if (transportLimitsDebounceRef.current != null)
        window.clearTimeout(transportLimitsDebounceRef.current);
    };
  }, [
    desiredTransportLimits,
    effectiveTransportLimitsBaseline,
    saveTransportLimitsMutation,
    transportLimitsQuery.isError,
    transportLimitsQuery.isPending,
  ]);

  return (
    <AppShell>
      <PageHeader title="Settings" description="Gateway configuration and tenant settings" />

      <PageContent className="space-y-6">
        <SectionCard
          title="Audit"
          subtitle="Tenant-wide audit defaults. Use these to enable/disable audit logging and configure retention."
          right={
            <a
              href="/audit"
              className="text-sm font-medium text-accent transition-colors hover:text-accent-hover"
            >
              Open audit →
            </a>
          }
        >
          <div className="divide-y divide-edge">
            <div className="py-4 first:pt-0 last:pb-0">
              <SettingRow
                label="Enable audit logging"
                description="When disabled, the gateway will not store new audit events for this tenant."
                right={<Toggle checked={draftEnabled} onChange={(v) => setAuditEnabledDraft(v)} />}
              />
            </div>

            <div className="py-4 first:pt-0 last:pb-0">
              <SettingRow
                label="Default detail level"
                description={
                  <>
                    Default capture level for this tenant. Keep this at <code>metadata</code> unless
                    you really need more.
                  </>
                }
                right={
                  <div className="w-[220px] max-w-full">
                    <Select
                      aria-label="Default detail level"
                      value={draftDefaultLevel}
                      onChange={(e) => setAuditDefaultLevelDraft(e.target.value)}
                    >
                      <option value="off">off</option>
                      <option value="summary">summary</option>
                      <option value="metadata">metadata</option>
                      <option value="payload">payload</option>
                    </Select>
                  </div>
                }
              />
            </div>

            <div className="py-4 first:pt-0 last:pb-0">
              <SettingRow
                label="Retention"
                description="How long to keep audit events."
                right={
                  <div className="flex flex-wrap justify-end gap-2">
                    {[1, 7, 30, 90, 365].map((d) => (
                      <Button
                        key={d}
                        type="button"
                        variant="secondary"
                        size="sm"
                        aria-pressed={draftRetentionDays === d}
                        onClick={() => setAuditRetentionDaysDraft(d)}
                        className={draftRetentionDays === d ? "border-accent/60 text-accent" : ""}
                      >
                        {d}d
                      </Button>
                    ))}
                  </div>
                }
              />
            </div>

            <div className="pt-4">
              <div className="flex items-center gap-3">
                {saveAuditSettingsMutation.isPending ? (
                  <span className="text-sm text-faint">Saving…</span>
                ) : auditSettingsQuery.isPending ? (
                  <span className="text-sm text-faint">Loading…</span>
                ) : auditSettingsQuery.isError ? (
                  <span className="text-sm text-danger">Failed to load audit settings</span>
                ) : null}
              </div>
            </div>
          </div>
        </SectionCard>

        <SectionCard
          title="Transport limits"
          subtitle="Tenant-wide defaults for request/SSE payload limits (DoS hardening). Profiles can override."
        >
          <div className="divide-y divide-edge">
            <div className="py-4 first:pt-0 last:pb-0">
              <SettingRow
                label="Max POST body bytes"
                description={
                  <>
                    Limits downstream JSON-RPC request bodies on{" "}
                    <code>POST /&#123;profile_id&#125;/mcp</code>. Default is{" "}
                    <code>{DEFAULT_MAX_POST_BODY_BYTES}</code> (~
                    {Math.round((DEFAULT_MAX_POST_BODY_BYTES / 1024 / 1024) * 10) / 10} MiB) unless
                    overridden.
                  </>
                }
                right={
                  <div className="flex flex-col items-end gap-2">
                    <div className="flex flex-wrap justify-end gap-2">
                      {[1, 4, 8, 16, 32].map((mib) => {
                        const bytes = mib * 1024 * 1024;
                        const active = draftMaxPostBodyBytes === bytes;
                        return (
                          <Button
                            key={mib}
                            type="button"
                            variant="secondary"
                            size="sm"
                            aria-pressed={active}
                            onClick={() => setMaxPostBodyBytesDraft(bytes)}
                            className={active ? "border-accent/60 text-accent" : ""}
                          >
                            {mib} MiB
                          </Button>
                        );
                      })}
                    </div>
                    <div className="w-[200px] max-w-full">
                      <Input
                        type="number"
                        min={1}
                        step={1}
                        label="Custom value (bytes)"
                        value={draftMaxPostBodyBytes}
                        onChange={(e) => {
                          const parsed = parsePositiveIntegerInput(e.target.value);
                          if (parsed !== null) setMaxPostBodyBytesDraft(parsed);
                        }}
                      />
                    </div>
                  </div>
                }
              />
            </div>

            <div className="py-4 first:pt-0 last:pb-0">
              <SettingRow
                label="Max SSE event bytes"
                description={
                  <>
                    Limits a single SSE <code>data:</code> payload from upstream servers. Default is{" "}
                    <code>{DEFAULT_MAX_SSE_EVENT_BYTES}</code> (~
                    {Math.round((DEFAULT_MAX_SSE_EVENT_BYTES / 1024 / 1024) * 10) / 10} MiB) unless
                    overridden.
                  </>
                }
                right={
                  <div className="flex flex-col items-end gap-2">
                    <div className="flex flex-wrap justify-end gap-2">
                      {[1, 4, 8, 16, 32].map((mib) => {
                        const bytes = mib * 1024 * 1024;
                        const active = draftMaxSseEventBytes === bytes;
                        return (
                          <Button
                            key={mib}
                            type="button"
                            variant="secondary"
                            size="sm"
                            aria-pressed={active}
                            onClick={() => setMaxSseEventBytesDraft(bytes)}
                            className={active ? "border-accent/60 text-accent" : ""}
                          >
                            {mib} MiB
                          </Button>
                        );
                      })}
                    </div>
                    <div className="w-[200px] max-w-full">
                      <Input
                        type="number"
                        min={1}
                        step={1}
                        label="Custom value (bytes)"
                        value={draftMaxSseEventBytes}
                        onChange={(e) => {
                          const parsed = parsePositiveIntegerInput(e.target.value);
                          if (parsed !== null) setMaxSseEventBytesDraft(parsed);
                        }}
                      />
                    </div>
                  </div>
                }
              />
            </div>

            <div className="py-4 first:pt-0 last:pb-0">
              <SettingRow
                label="JSON complexity caps (optional)"
                description={
                  <>
                    Extra guardrails applied after parsing JSON. Leave blank to disable individual
                    caps.
                  </>
                }
                right={
                  <div className="flex flex-wrap justify-end gap-3">
                    <div className="w-[140px] max-w-full">
                      <Input
                        type="number"
                        min={1}
                        step={1}
                        label="Max depth"
                        value={draftMaxJsonDepth ?? ""}
                        onChange={(e) =>
                          setMaxJsonDepthDraft(parsePositiveIntegerInput(e.target.value))
                        }
                      />
                    </div>
                    <div className="w-[140px] max-w-full">
                      <Input
                        type="number"
                        min={1}
                        step={1}
                        label="Max array length"
                        value={draftMaxJsonArrayLen ?? ""}
                        onChange={(e) =>
                          setMaxJsonArrayLenDraft(parsePositiveIntegerInput(e.target.value))
                        }
                      />
                    </div>
                    <div className="w-[140px] max-w-full">
                      <Input
                        type="number"
                        min={1}
                        step={1}
                        label="Max object keys"
                        value={draftMaxJsonObjectKeys ?? ""}
                        onChange={(e) =>
                          setMaxJsonObjectKeysDraft(parsePositiveIntegerInput(e.target.value))
                        }
                      />
                    </div>
                    <div className="w-[160px] max-w-full">
                      <Input
                        type="number"
                        min={1}
                        step={1}
                        label="Max string bytes"
                        value={draftMaxJsonStringBytes ?? ""}
                        onChange={(e) =>
                          setMaxJsonStringBytesDraft(parsePositiveIntegerInput(e.target.value))
                        }
                      />
                    </div>
                  </div>
                }
              />
            </div>

            <div className="pt-4">
              <div className="flex items-center gap-3">
                {saveTransportLimitsMutation.isPending ? (
                  <span className="text-sm text-faint">Saving…</span>
                ) : transportLimitsQuery.isPending ? (
                  <span className="text-sm text-faint">Loading…</span>
                ) : transportLimitsQuery.isError ? (
                  <span className="text-sm text-danger">Failed to load transport limits</span>
                ) : null}
              </div>
            </div>
          </div>
        </SectionCard>

        {/* Environment info */}
        <SectionCard title="Gateway environment">
          <div className="space-y-4">
            <ConfigRow
              label="Data plane URL"
              value={dataBase}
              description="Public URL for MCP client connections"
              copyable
            />
            <ConfigRow
              label="Gateway status"
              value={
                gatewayStatusQuery.isPending ? "loading" : gatewayStatus?.ok ? "online" : "error"
              }
              description="Derived from the Gateway control plane /status"
            />
            <ConfigRow
              label="Operating mode"
              value="Mode 3 (Postgres)"
              description="Multi-tenant mode with Postgres backend"
            />
            <ConfigRow
              label="Session storage"
              value="HttpOnly browser cookie"
              description="The tenant token is HttpOnly; only non-sensitive tenant ID and expiry helpers are client-readable"
            />
          </div>
        </SectionCard>

        {/* Current tenant */}
        <SectionCard title="Current tenant">
          <div className="space-y-4">
            <ConfigRow
              label="Session expires"
              value={expHuman}
              description="When the current unlock token expires"
            />
          </div>
          <div className="mt-4 border-t border-edge pt-4">
            <Button variant="secondary" size="sm" onClick={() => setShowConfirmLock(true)}>
              <LockIcon className="size-4" />
              Lock tenant session
            </Button>
          </div>
        </SectionCard>

        {/* About */}
        <section className="rounded-lg border border-edge bg-surface p-5">
          <div className="flex items-center gap-4">
            <div className="flex size-12 items-center justify-center rounded-lg bg-accent-strong">
              <span className="text-xl font-black leading-none tracking-tight text-white">U</span>
            </div>
            <div>
              <h3 className="text-sm font-semibold text-fg">MCP Gateway</h3>
              <div className="mt-0.5 text-xs text-faint">
                by{" "}
                <a
                  href="https://unrelated.ai"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-accent transition-colors hover:text-accent-hover"
                >
                  unrelated.ai
                </a>
              </div>
            </div>
          </div>
          <div className="mt-4 grid grid-cols-3 gap-4 border-t border-edge pt-4 text-center">
            <div>
              <div className="font-mono text-sm font-medium text-fg">{gatewayVersionLabel}</div>
              <div className="eyebrow mt-0.5">Version</div>
            </div>
            <div>
              <div className="font-mono text-sm font-medium text-fg">{gatewayLicenseLabel}</div>
              <div className="eyebrow mt-0.5">License</div>
            </div>
            <div>
              <a
                href="https://github.com/unrelated-ai/mcp-gateway"
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm font-semibold text-accent transition-colors hover:text-accent-hover"
              >
                GitHub
              </a>
              <div className="eyebrow mt-0.5">Repository</div>
            </div>
          </div>
        </section>

        {/* Web UI */}
        <section className="rounded-lg border border-edge bg-surface p-5">
          <div className="flex items-center gap-4">
            <div className="flex size-12 items-center justify-center rounded-lg border border-edge-strong bg-raised">
              <span className="text-base font-black leading-none tracking-tight text-muted">U</span>
            </div>
            <div>
              <h3 className="text-sm font-semibold text-fg">Web UI</h3>
              <div className="mt-0.5 text-xs text-faint">
                Dashboard for managing profiles and sources.
              </div>
            </div>
          </div>
          <div className="mt-4 grid grid-cols-3 gap-4 border-t border-edge pt-4 text-center">
            <div>
              <div className="font-mono text-sm font-medium text-fg">{uiVersion}</div>
              <div className="eyebrow mt-0.5">Version</div>
            </div>
            <div>
              <div className="font-mono text-sm font-medium text-fg">MIT</div>
              <div className="eyebrow mt-0.5">License</div>
            </div>
            <div>
              <a
                href="https://github.com/unrelated-ai/mcp-gateway"
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm font-semibold text-accent transition-colors hover:text-accent-hover"
              >
                GitHub
              </a>
              <div className="eyebrow mt-0.5">Repository</div>
            </div>
          </div>
        </section>
      </PageContent>

      {/* Lock confirmation modal */}
      <ConfirmModal
        open={showConfirmLock}
        onClose={() => setShowConfirmLock(false)}
        onConfirm={() => {
          lockTenantSession();
        }}
        title="Lock session?"
        description="This will clear your session and return you to the unlock screen. You'll need your tenant token to access the dashboard again."
        confirmLabel="Lock session"
      />
    </AppShell>
  );
}

function ConfigRow({
  label,
  value,
  description,
  copyable = false,
}: {
  label: string;
  value: string;
  description?: string;
  copyable?: boolean;
}) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-edge py-2 first:pt-0 last:border-0 last:pb-0">
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium text-fg">{label}</div>
        {description && <div className="mt-0.5 text-xs text-faint">{description}</div>}
      </div>
      <div className="flex items-center gap-2">
        <code
          title={value}
          className="max-w-[260px] truncate rounded bg-well px-2 py-1 font-mono text-sm text-muted sm:max-w-[360px] md:max-w-[520px] lg:max-w-[680px]"
        >
          {value}
        </code>
        {copyable && <CopyButton value={value} variant="icon" />}
      </div>
    </div>
  );
}

function SettingRow({
  label,
  description,
  right,
}: {
  label: string;
  description?: React.ReactNode;
  right: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium text-fg">{label}</div>
        {description ? <div className="mt-0.5 text-xs text-faint">{description}</div> : null}
      </div>
      <div className="shrink-0">{right}</div>
    </div>
  );
}
