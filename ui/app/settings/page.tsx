"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import { useQuery } from "@tanstack/react-query";
import { ConfirmModal, CopyButton } from "@/components/ui";
import { SectionCard, Toggle } from "@/components/ui";
import { qk } from "@/src/lib/queryKeys";
import { clearTenantSessionCookies, getTenantExpFromCookies } from "@/src/lib/tenant-session";
import { LockIcon, ServerIconDevice, UserIcon } from "@/components/icons";
import { GATEWAY_DATA_BASE, UI_VERSION } from "@/src/lib/env";
import { useToastStore } from "@/src/lib/toast-store";
import { useMutation } from "@tanstack/react-query";
import { getTenantAuditSettings, putTenantAuditSettings } from "@/src/lib/tenantApi";
import type { TenantAuditSettings } from "@/src/lib/types";

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
        oidcConfigured?: boolean;
        oidcIssuer?: string;
      };
    }
  | { ok: false; error?: string; status?: number };

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

  const [auditEnabledDraft, setAuditEnabledDraft] = useState<boolean | null>(null);
  const [auditRetentionDaysDraft, setAuditRetentionDaysDraft] = useState<number | null>(null);
  const [auditDefaultLevelDraft, setAuditDefaultLevelDraft] = useState<string | null>(null);

  const effectiveAuditSettings: TenantAuditSettings | null = auditSettingsQuery.data ?? null;
  const draftEnabled = auditEnabledDraft ?? effectiveAuditSettings?.enabled ?? false;
  const draftRetentionDays = auditRetentionDaysDraft ?? effectiveAuditSettings?.retentionDays ?? 30;
  const draftDefaultLevel =
    auditDefaultLevelDraft ?? effectiveAuditSettings?.defaultLevel ?? "metadata";

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

  // Initialize drafts from server once (avoid overwriting user edits).
  useEffect(() => {
    if (!effectiveAuditSettings) return;
    if (auditEnabledDraft === null) setAuditEnabledDraft(effectiveAuditSettings.enabled);
    if (auditRetentionDaysDraft === null)
      setAuditRetentionDaysDraft(effectiveAuditSettings.retentionDays);
    if (auditDefaultLevelDraft === null)
      setAuditDefaultLevelDraft(effectiveAuditSettings.defaultLevel);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [effectiveAuditSettings]);

  const desiredSettings: TenantAuditSettings | null = useMemo(() => {
    if (!effectiveAuditSettings) return null;
    return {
      enabled: draftEnabled,
      retentionDays: draftRetentionDays,
      defaultLevel: draftDefaultLevel,
    };
  }, [effectiveAuditSettings, draftDefaultLevel, draftEnabled, draftRetentionDays]);

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
              className="text-sm font-medium text-violet-400 hover:text-violet-300 transition-colors"
            >
              Open Audit →
            </a>
          }
        >
          <div className="divide-y divide-zinc-800/40">
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
                  <select
                    value={draftDefaultLevel}
                    onChange={(e) => setAuditDefaultLevelDraft(e.target.value)}
                    className="w-[220px] max-w-full rounded-lg border border-zinc-800/70 bg-zinc-950/60 px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:ring-2 focus:ring-violet-500"
                  >
                    <option value="off">off</option>
                    <option value="summary">summary</option>
                    <option value="metadata">metadata</option>
                    <option value="payload">payload</option>
                  </select>
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
                      <button
                        key={d}
                        type="button"
                        onClick={() => setAuditRetentionDaysDraft(d)}
                        className={`px-3 py-2 rounded-lg text-sm font-medium border transition-colors ${
                          draftRetentionDays === d
                            ? "border-violet-500/50 bg-violet-500/15 text-violet-200"
                            : "border-zinc-800/70 bg-zinc-950/40 text-zinc-300 hover:bg-zinc-800/40 hover:text-zinc-200"
                        }`}
                      >
                        {d}d
                      </button>
                    ))}
                  </div>
                }
              />
            </div>

            <div className="pt-4">
              <div className="flex items-center gap-3">
                {saveAuditSettingsMutation.isPending ? (
                  <span className="text-sm text-zinc-500">Saving…</span>
                ) : auditSettingsQuery.isPending ? (
                  <span className="text-sm text-zinc-500">Loading…</span>
                ) : auditSettingsQuery.isError ? (
                  <span className="text-sm text-red-300">Failed to load audit settings</span>
                ) : null}
              </div>
            </div>
          </div>
        </SectionCard>

        {/* Environment Info */}
        <section className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 overflow-hidden">
          <div className="px-5 py-4 border-b border-zinc-800/60">
            <h2 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
              <ServerIconDevice className="w-5 h-5 text-violet-400" />
              Gateway Environment
            </h2>
          </div>
          <div className="p-5 space-y-4">
            <ConfigRow
              label="Data Plane URL"
              value={dataBase}
              description="Public URL for MCP client connections"
              copyable
            />
            <ConfigRow
              label="Gateway Status"
              value={
                gatewayStatusQuery.isPending ? "loading" : gatewayStatus?.ok ? "online" : "error"
              }
              description="Derived from the Gateway control plane /status"
            />
            <ConfigRow
              label="Operating Mode"
              value="Mode 3 (Postgres)"
              description="Multi-tenant mode with Postgres backend"
            />
            <ConfigRow
              label="Session Storage"
              value="Browser cookie"
              description="UI stores the tenant session in browser-set cookies (not httpOnly yet)"
            />
          </div>
        </section>

        {/* Current Tenant */}
        <section className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 overflow-hidden">
          <div className="px-5 py-4 border-b border-zinc-800/60">
            <h2 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
              <UserIcon className="w-5 h-5 text-emerald-400" />
              Current Tenant
            </h2>
          </div>
          <div className="p-5 space-y-4">
            <ConfigRow
              label="Session Expires"
              value={expHuman}
              description="When the current unlock token expires"
            />
          </div>
          <div className="px-5 py-4 border-t border-zinc-800/60 bg-zinc-950/40">
            <button
              onClick={() => setShowConfirmLock(true)}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-amber-400 hover:text-amber-300 hover:bg-amber-500/10 transition-colors"
            >
              <LockIcon className="w-4 h-4" />
              Lock Tenant Session
            </button>
          </div>
        </section>

        {/* About */}
        <section className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 p-5">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-violet-500 to-violet-600 flex items-center justify-center shadow-lg shadow-violet-500/20">
              <span className="text-white font-black text-xl leading-none tracking-tight">U</span>
            </div>
            <div>
              <h3 className="text-sm font-semibold text-zinc-100">MCP Gateway</h3>
              <div className="text-xs text-zinc-500 mt-0.5">
                by{" "}
                <a
                  href="https://unrelated.ai"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-violet-400 hover:text-violet-300 transition-colors"
                >
                  unrelated.ai
                </a>
              </div>
            </div>
          </div>
          <div className="mt-4 pt-4 border-t border-zinc-800/60 grid grid-cols-3 gap-4 text-center">
            <div>
              <div className="text-sm font-semibold text-zinc-200">{gatewayVersionLabel}</div>
              <div className="text-xs text-zinc-500">Version</div>
            </div>
            <div>
              <div className="text-sm font-semibold text-zinc-200">{gatewayLicenseLabel}</div>
              <div className="text-xs text-zinc-500">License</div>
            </div>
            <div>
              <a
                href="https://github.com/unrelated-ai/mcp-gateway"
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm font-semibold text-violet-400 hover:text-violet-300 transition-colors"
              >
                GitHub
              </a>
              <div className="text-xs text-zinc-500">Repository</div>
            </div>
          </div>
        </section>

        {/* Web UI */}
        <section className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 p-5">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-emerald-500 to-emerald-600 flex items-center justify-center shadow-lg shadow-emerald-500/20">
              <span className="text-white font-black text-base leading-none tracking-tight">U</span>
            </div>
            <div>
              <h3 className="text-sm font-semibold text-zinc-100">Web UI</h3>
              <div className="text-xs text-zinc-500 mt-0.5">
                Dashboard for managing profiles and sources.
              </div>
            </div>
          </div>
          <div className="mt-4 pt-4 border-t border-zinc-800/60 grid grid-cols-3 gap-4 text-center">
            <div>
              <div className="text-sm font-semibold text-zinc-200">{uiVersion}</div>
              <div className="text-xs text-zinc-500">Version</div>
            </div>
            <div>
              <div className="text-sm font-semibold text-zinc-200">MIT</div>
              <div className="text-xs text-zinc-500">License</div>
            </div>
            <div>
              <a
                href="https://github.com/unrelated-ai/mcp-gateway"
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm font-semibold text-emerald-400 hover:text-emerald-300 transition-colors"
              >
                GitHub
              </a>
              <div className="text-xs text-zinc-500">Repository</div>
            </div>
          </div>
        </section>
      </PageContent>

      {/* Lock Confirmation Modal */}
      <ConfirmModal
        open={showConfirmLock}
        onClose={() => setShowConfirmLock(false)}
        onConfirm={() => {
          clearTenantSessionCookies();
          window.location.href = "/unlock";
        }}
        title="Lock session?"
        description="This will clear your session and return you to the unlock screen. You'll need your tenant token to access the dashboard again."
        confirmLabel="Lock Session"
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
    <div className="flex items-start justify-between gap-4 py-2 border-b border-zinc-800/40 last:border-0 last:pb-0 first:pt-0">
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium text-zinc-200">{label}</div>
        {description && <div className="text-xs text-zinc-500 mt-0.5">{description}</div>}
      </div>
      <div className="flex items-center gap-2">
        <code
          title={value}
          className="text-sm font-mono text-zinc-400 bg-zinc-800/60 px-2 py-1 rounded truncate max-w-[260px] sm:max-w-[360px] md:max-w-[520px] lg:max-w-[680px]"
        >
          {value}
        </code>
        {copyable && (
          <CopyButton
            text={value}
            variant="icon"
            className="text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800 transition-colors"
          />
        )}
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
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium text-zinc-200">{label}</div>
        {description ? <div className="text-xs text-zinc-500 mt-0.5">{description}</div> : null}
      </div>
      <div className="shrink-0">{right}</div>
    </div>
  );
}
