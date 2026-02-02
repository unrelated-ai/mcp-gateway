"use client";

import { useMemo, useState } from "react";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import { useQuery } from "@tanstack/react-query";
import {
  listAuditEvents,
  listProfiles,
  toolCallStatsByApiKey,
  toolCallStatsByTool,
} from "@/src/lib/tenantApi";
import type {
  AuditEventRow,
  Profile,
  ToolCallStatsByApiKey,
  ToolCallStatsByTool,
} from "@/src/lib/types";

type Tab = "events" | "analytics";

function nowUnixSecs(): number {
  return Math.floor(Date.now() / 1000);
}

function asString(v: unknown): string | null {
  return typeof v === "string" && v.trim() ? v.trim() : null;
}

function asBool(v: unknown): boolean | null {
  return typeof v === "boolean" ? v : null;
}

function asNumber(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function actionLabel(action: string): string {
  switch (action) {
    case "mcp.tools_call":
      return "Tool call";
    case "tenant.profile_put":
      return "Profile updated";
    case "tenant.profile_delete":
      return "Profile deleted";
    case "tenant.tool_source_put":
      return "Tool source updated";
    case "tenant.tool_source_delete":
      return "Tool source deleted";
    case "tenant.secret_put":
      return "Secret updated";
    case "tenant.secret_delete":
      return "Secret deleted";
    case "tenant.api_key_create":
      return "API key created";
    case "tenant.api_key_revoke":
      return "API key revoked";
    case "admin.audit_cleanup":
      return "Audit cleanup";
    case "admin.tenant_put":
      return "Tenant updated";
    case "admin.tenant_delete":
      return "Tenant deleted";
    case "admin.profile_put":
      return "Profile updated (admin)";
    case "admin.profile_delete":
      return "Profile deleted (admin)";
    case "admin.secret_put":
      return "Secret updated (admin)";
    case "admin.secret_delete":
      return "Secret deleted (admin)";
    case "admin.tool_source_put":
      return "Tool source updated (admin)";
    case "admin.tool_source_delete":
      return "Tool source deleted (admin)";
    default:
      return action;
  }
}

function eventSummary(e: AuditEventRow): string | null {
  const meta = (e.meta ?? {}) as Record<string, unknown>;

  if (e.action === "tenant.profile_put" || e.action === "admin.profile_put") {
    const name = asString(meta.name);
    const enabled = asBool(meta.enabled);
    if (name && enabled != null) return `${name} (${enabled ? "enabled" : "disabled"})`;
    if (name) return name;
  }

  if (e.action === "tenant.tool_source_put" || e.action === "admin.tool_source_put") {
    const sourceId = asString(meta.source_id);
    const kind = asString(meta.kind);
    const enabled = asBool(meta.enabled);
    const bits = [sourceId, kind].filter(Boolean) as string[];
    const base = bits.join(" · ");
    if (enabled != null) return `${base}${base ? " · " : ""}${enabled ? "enabled" : "disabled"}`;
    return base || null;
  }

  if (e.action === "tenant.secret_put" || e.action === "admin.secret_put") {
    const name = asString(meta.name);
    const valueLen = asNumber(meta.value_len);
    if (name && valueLen != null) return `${name} · ${valueLen} bytes`;
    if (name) return name;
  }

  if (e.action === "tenant.secret_delete" || e.action === "admin.secret_delete") {
    const name = asString(meta.name);
    if (name) return name;
  }

  if (e.action === "tenant.api_key_create") {
    const name = asString(meta.name);
    const profileId = asString(meta.profile_id);
    const parts = [name, profileId ? `profile ${profileId}` : null].filter(Boolean) as string[];
    return parts.join(" · ") || null;
  }

  if (e.action === "tenant.api_key_revoke") {
    const apiKeyId = asString(meta.api_key_id);
    if (apiKeyId) return apiKeyId;
  }

  if (e.action === "admin.audit_cleanup") {
    const deleted = asNumber(meta.deleted);
    if (deleted != null) return `${deleted} row(s) deleted`;
  }

  return null;
}

export function AuditClient({ initialProfileId }: { initialProfileId?: string }) {
  const [tab, setTab] = useState<Tab>("events");
  const [profileId, setProfileId] = useState<string>(initialProfileId ?? "all");
  const [outcome, setOutcome] = useState<"all" | "ok" | "error">("all");
  const [range, setRange] = useState<"1h" | "24h" | "7d">("24h");
  const [selectedEvent, setSelectedEvent] = useState<AuditEventRow | null>(null);

  const fromUnixSecs = useMemo(() => {
    const now = nowUnixSecs();
    if (range === "1h") return now - 60 * 60;
    if (range === "7d") return now - 7 * 24 * 60 * 60;
    return now - 24 * 60 * 60;
  }, [range]);

  const profilesQuery = useQuery({
    queryKey: ["auditProfiles"],
    queryFn: async () => {
      const res = await listProfiles();
      return res.profiles;
    },
  });

  const effectiveProfileId = profileId === "all" ? undefined : profileId;
  const okFilter = outcome === "all" ? undefined : outcome === "ok";

  const eventsQuery = useQuery({
    queryKey: ["auditEvents", { fromUnixSecs, profileId: effectiveProfileId, ok: okFilter }],
    queryFn: async () => {
      const res = await listAuditEvents({
        fromUnixSecs,
        profileId: effectiveProfileId,
        ok: okFilter,
        limit: 200,
      });
      return res.events;
    },
    enabled: tab === "events",
  });

  const statsByToolQuery = useQuery({
    queryKey: ["auditStatsByTool", { fromUnixSecs, profileId: effectiveProfileId }],
    queryFn: async () => {
      const res = await toolCallStatsByTool({
        fromUnixSecs,
        profileId: effectiveProfileId,
        limit: 100,
      });
      return res.items;
    },
    enabled: tab === "analytics",
  });

  const statsByApiKeyQuery = useQuery({
    queryKey: ["auditStatsByApiKey", { fromUnixSecs, profileId: effectiveProfileId }],
    queryFn: async () => {
      const res = await toolCallStatsByApiKey({
        fromUnixSecs,
        profileId: effectiveProfileId,
        limit: 100,
      });
      return res.items;
    },
    enabled: tab === "analytics",
  });

  return (
    <AppShell>
      <PageHeader title="Audit" description="Audit events and per-tool/per-token analytics" />
      <PageContent className="space-y-4">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div className="flex flex-wrap items-center gap-2">
            <TabButton active={tab === "events"} onClick={() => setTab("events")}>
              Events
            </TabButton>
            <TabButton active={tab === "analytics"} onClick={() => setTab("analytics")}>
              Analytics
            </TabButton>
          </div>

          <div className="flex flex-col gap-2 md:flex-row md:items-center">
            <select
              value={range}
              onChange={(e) => setRange(e.target.value as "1h" | "24h" | "7d")}
              className="rounded-lg border border-zinc-800/70 bg-zinc-950/60 px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:ring-2 focus:ring-violet-500"
            >
              <option value="1h">Last 1h</option>
              <option value="24h">Last 24h</option>
              <option value="7d">Last 7d</option>
            </select>

            <select
              value={profileId}
              onChange={(e) => setProfileId(e.target.value)}
              className="rounded-lg border border-zinc-800/70 bg-zinc-950/60 px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:ring-2 focus:ring-violet-500"
            >
              <option value="all">All profiles</option>
              {(profilesQuery.data ?? []).map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>

            <select
              value={outcome}
              onChange={(e) => setOutcome(e.target.value as "all" | "ok" | "error")}
              className="rounded-lg border border-zinc-800/70 bg-zinc-950/60 px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:ring-2 focus:ring-violet-500"
            >
              <option value="all">All outcomes</option>
              <option value="ok">OK only</option>
              <option value="error">Errors only</option>
            </select>
          </div>
        </div>

        {tab === "events" ? (
          <EventsTable
            profiles={profilesQuery.data ?? []}
            events={eventsQuery.data ?? []}
            loading={eventsQuery.isPending}
            onSelect={(e) => setSelectedEvent(e)}
          />
        ) : (
          <AnalyticsView
            byTool={statsByToolQuery.data ?? []}
            byApiKey={statsByApiKeyQuery.data ?? []}
            loading={statsByToolQuery.isPending || statsByApiKeyQuery.isPending}
          />
        )}

        <EventDetailsDrawer
          event={selectedEvent}
          profiles={profilesQuery.data ?? []}
          onClose={() => setSelectedEvent(null)}
        />
      </PageContent>
    </AppShell>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
        active
          ? "bg-violet-500/15 text-violet-300"
          : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60"
      }`}
    >
      {children}
    </button>
  );
}

function EventsTable({
  profiles,
  events,
  loading,
  onSelect,
}: {
  profiles: Profile[];
  events: AuditEventRow[];
  loading: boolean;
  onSelect: (ev: AuditEventRow) => void;
}) {
  const profileNameById = useMemo(() => {
    const m = new Map<string, string>();
    for (const p of profiles) m.set(p.id, p.name);
    return m;
  }, [profiles]);

  return (
    <div className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 overflow-hidden">
      <div className="px-5 py-4 border-b border-zinc-800/60 flex items-center justify-between">
        <div className="text-sm font-semibold text-zinc-100">Events</div>
        {loading ? <div className="text-xs text-zinc-500">Loading…</div> : null}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-zinc-950/40 text-zinc-400">
            <tr>
              <th className="text-left font-medium px-4 py-3">Time</th>
              <th className="text-left font-medium px-4 py-3">Event</th>
              <th className="text-left font-medium px-4 py-3">Profile</th>
              <th className="text-left font-medium px-4 py-3">Tool</th>
              <th className="text-left font-medium px-4 py-3">OK</th>
              <th className="text-left font-medium px-4 py-3">Duration</th>
            </tr>
          </thead>
          <tbody>
            {events.length === 0 ? (
              <tr>
                <td className="px-4 py-6 text-zinc-500" colSpan={6}>
                  No events found for current filters.
                </td>
              </tr>
            ) : (
              events.map((e) => {
                const ts = new Date(e.tsUnixSecs * 1000).toLocaleString();
                const profileLabel = e.profileId
                  ? (profileNameById.get(e.profileId) ?? e.profileId)
                  : "—";
                const tool = e.toolRef ?? "—";
                const title = actionLabel(e.action);
                const summary = eventSummary(e);
                return (
                  <tr
                    key={e.id}
                    className="border-t border-zinc-800/50 hover:bg-zinc-800/20 cursor-pointer"
                    onClick={() => onSelect(e)}
                    title="View event details"
                  >
                    <td className="px-4 py-3 text-zinc-300 whitespace-nowrap">{ts}</td>
                    <td className="px-4 py-3">
                      <div className="text-zinc-200">{title}</div>
                      <div className="text-xs text-zinc-500 font-mono">
                        {summary ? `${e.action} · ${summary}` : e.action}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-zinc-300">{profileLabel}</td>
                    <td className="px-4 py-3 text-zinc-300 font-mono">{tool}</td>
                    <td className="px-4 py-3">
                      <span className={e.ok ? "text-emerald-300" : "text-red-300"}>
                        {e.ok ? "ok" : "error"}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-zinc-300">
                      {e.durationMs != null ? `${e.durationMs}ms` : "—"}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function formatJson(v: unknown): string {
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

function EventDetailsDrawer({
  event,
  profiles,
  onClose,
}: {
  event: AuditEventRow | null;
  profiles: Profile[];
  onClose: () => void;
}) {
  const profileNameById = useMemo(() => {
    const m = new Map<string, string>();
    for (const p of profiles) m.set(p.id, p.name);
    return m;
  }, [profiles]);

  if (!event) return null;

  const ts = new Date(event.tsUnixSecs * 1000).toLocaleString();
  const profileLabel = event.profileId
    ? (profileNameById.get(event.profileId) ?? event.profileId)
    : "—";

  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <div className="absolute right-0 top-0 h-full w-full max-w-2xl bg-zinc-950 border-l border-zinc-800/60 shadow-2xl flex flex-col">
        <div className="px-5 py-4 border-b border-zinc-800/60 flex items-center justify-between">
          <div>
            <div className="text-sm font-semibold text-zinc-100">{actionLabel(event.action)}</div>
            <div className="text-xs text-zinc-500 font-mono">{event.action}</div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-2 rounded-lg text-sm font-medium text-zinc-300 hover:text-zinc-100 hover:bg-zinc-800/60 transition-colors"
          >
            Close
          </button>
        </div>

        <div className="p-5 overflow-y-auto space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <Info label="Time" value={ts} />
            <Info
              label="Outcome"
              value={event.ok ? "ok" : "error"}
              valueClass={event.ok ? "text-emerald-300" : "text-red-300"}
            />
            <Info
              label="Duration"
              value={event.durationMs != null ? `${event.durationMs}ms` : "—"}
            />
            <Info label="Profile" value={profileLabel} />
            <Info label="Tool" value={event.toolRef ?? "—"} mono />
            <Info label="API key id" value={event.apiKeyId ?? "—"} mono />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <Info label="HTTP method" value={event.httpMethod ?? "—"} mono />
            <Info label="HTTP route" value={event.httpRoute ?? "—"} mono />
            <Info
              label="Status"
              value={event.statusCode != null ? String(event.statusCode) : "—"}
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <Info label="Error kind" value={event.errorKind ?? "—"} mono />
            <Info label="Error message" value={event.errorMessage ?? "—"} />
          </div>

          <div className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 overflow-hidden">
            <div className="px-4 py-3 border-b border-zinc-800/60 flex items-center justify-between">
              <div className="text-sm font-semibold text-zinc-100">Meta</div>
              <button
                type="button"
                onClick={async () => {
                  try {
                    await navigator.clipboard.writeText(formatJson(event.meta));
                  } catch {
                    // ignore
                  }
                }}
                className="px-3 py-1.5 rounded-lg text-xs font-medium text-zinc-300 hover:text-zinc-100 hover:bg-zinc-800/60 transition-colors"
              >
                Copy JSON
              </button>
            </div>
            <pre className="p-4 text-xs text-zinc-200 overflow-x-auto">
              {formatJson(event.meta)}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}

function Info({
  label,
  value,
  mono,
  valueClass,
}: {
  label: string;
  value: string;
  mono?: boolean;
  valueClass?: string;
}) {
  return (
    <div className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 px-4 py-3">
      <div className="text-xs text-zinc-500">{label}</div>
      <div className={`mt-1 text-sm text-zinc-200 ${mono ? "font-mono" : ""} ${valueClass ?? ""}`}>
        {value}
      </div>
    </div>
  );
}

function AnalyticsView({
  byTool,
  byApiKey,
  loading,
}: {
  byTool: ToolCallStatsByTool[];
  byApiKey: ToolCallStatsByApiKey[];
  loading: boolean;
}) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 overflow-hidden">
        <div className="px-5 py-4 border-b border-zinc-800/60 flex items-center justify-between">
          <div className="text-sm font-semibold text-zinc-100">Tool calls by tool</div>
          {loading ? <div className="text-xs text-zinc-500">Loading…</div> : null}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-zinc-950/40 text-zinc-400">
              <tr>
                <th className="text-left font-medium px-4 py-3">Tool</th>
                <th className="text-right font-medium px-4 py-3">Total</th>
                <th className="text-right font-medium px-4 py-3">OK</th>
                <th className="text-right font-medium px-4 py-3">Err</th>
                <th className="text-right font-medium px-4 py-3">p99</th>
              </tr>
            </thead>
            <tbody>
              {byTool.length === 0 ? (
                <tr>
                  <td className="px-4 py-6 text-zinc-500" colSpan={5}>
                    No data.
                  </td>
                </tr>
              ) : (
                byTool.map((r) => (
                  <tr key={r.toolRef} className="border-t border-zinc-800/50">
                    <td className="px-4 py-3 text-zinc-200 font-mono">{r.toolRef}</td>
                    <td className="px-4 py-3 text-zinc-300 text-right">{r.total}</td>
                    <td className="px-4 py-3 text-emerald-300 text-right">{r.ok}</td>
                    <td className="px-4 py-3 text-red-300 text-right">{r.err}</td>
                    <td className="px-4 py-3 text-zinc-300 text-right">{r.p99DurationMs ?? "—"}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 overflow-hidden">
        <div className="px-5 py-4 border-b border-zinc-800/60 flex items-center justify-between">
          <div className="text-sm font-semibold text-zinc-100">Tool calls by API key</div>
          {loading ? <div className="text-xs text-zinc-500">Loading…</div> : null}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-zinc-950/40 text-zinc-400">
              <tr>
                <th className="text-left font-medium px-4 py-3">API key id</th>
                <th className="text-right font-medium px-4 py-3">Total</th>
                <th className="text-right font-medium px-4 py-3">OK</th>
                <th className="text-right font-medium px-4 py-3">Err</th>
                <th className="text-right font-medium px-4 py-3">p99</th>
              </tr>
            </thead>
            <tbody>
              {byApiKey.length === 0 ? (
                <tr>
                  <td className="px-4 py-6 text-zinc-500" colSpan={5}>
                    No data.
                  </td>
                </tr>
              ) : (
                byApiKey.map((r) => (
                  <tr key={r.apiKeyId} className="border-t border-zinc-800/50">
                    <td className="px-4 py-3 text-zinc-200 font-mono">{r.apiKeyId}</td>
                    <td className="px-4 py-3 text-zinc-300 text-right">{r.total}</td>
                    <td className="px-4 py-3 text-emerald-300 text-right">{r.ok}</td>
                    <td className="px-4 py-3 text-red-300 text-right">{r.err}</td>
                    <td className="px-4 py-3 text-zinc-300 text-right">{r.p99DurationMs ?? "—"}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
