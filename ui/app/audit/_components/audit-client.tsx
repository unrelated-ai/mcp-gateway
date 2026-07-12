"use client";

import { useMemo, useState, type ReactNode } from "react";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import { useQuery } from "@tanstack/react-query";
import {
  Badge,
  CopyButton,
  Drawer,
  Select,
  TBody,
  TD,
  TH,
  THead,
  TR,
  Table,
  Tabs,
} from "@/components/ui";
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

const TAB_ITEMS = [
  { value: "events", label: "Events" },
  { value: "analytics", label: "Analytics" },
] as const;

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
          <Tabs<Tab> items={TAB_ITEMS} value={tab} onChange={setTab} className="md:flex-1" />

          <div className="flex flex-col gap-2 md:flex-row md:items-center">
            <Select
              aria-label="Time range"
              value={range}
              onChange={(e) => setRange(e.target.value as "1h" | "24h" | "7d")}
            >
              <option value="1h">Last 1h</option>
              <option value="24h">Last 24h</option>
              <option value="7d">Last 7d</option>
            </Select>

            <Select
              aria-label="Profile"
              value={profileId}
              onChange={(e) => setProfileId(e.target.value)}
            >
              <option value="all">All profiles</option>
              {(profilesQuery.data ?? []).map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </Select>

            <Select
              aria-label="Outcome"
              value={outcome}
              onChange={(e) => setOutcome(e.target.value as "all" | "ok" | "error")}
            >
              <option value="all">All outcomes</option>
              <option value="ok">OK only</option>
              <option value="error">Errors only</option>
            </Select>
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
    <div className="overflow-hidden rounded-lg border border-edge bg-surface">
      <div className="flex items-center justify-between border-b border-edge px-5 py-3.5">
        <div className="eyebrow">Events</div>
        {loading ? <div className="text-xs text-faint">Loading…</div> : null}
      </div>
      <Table>
        <THead>
          <tr>
            <TH>Time</TH>
            <TH>Event</TH>
            <TH>Profile</TH>
            <TH>Tool</TH>
            <TH>Outcome</TH>
            <TH>Duration</TH>
          </tr>
        </THead>
        <TBody>
          {events.length === 0 ? (
            <tr>
              <TD className="py-6 text-muted" colSpan={6}>
                No events found for current filters.
              </TD>
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
                <TR
                  key={e.id}
                  tabIndex={0}
                  aria-label={`View details for ${title}`}
                  className="cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent"
                  onClick={(event) => {
                    event.currentTarget.focus();
                    onSelect(e);
                  }}
                  onKeyDown={(event) => {
                    if (event.key !== "Enter" && event.key !== " ") return;
                    event.preventDefault();
                    onSelect(e);
                  }}
                  title="View event details"
                >
                  <TD className="whitespace-nowrap text-muted">{ts}</TD>
                  <TD>
                    <div className="text-fg">{title}</div>
                    <div className="font-mono text-xs text-faint">
                      {summary ? `${e.action} · ${summary}` : e.action}
                    </div>
                  </TD>
                  <TD className="text-muted">{profileLabel}</TD>
                  <TD className="font-mono text-muted">{tool}</TD>
                  <TD>
                    <Badge tone={e.ok ? "ok" : "danger"}>{e.ok ? "OK" : "Error"}</Badge>
                  </TD>
                  <TD className="text-muted">{e.durationMs != null ? `${e.durationMs}ms` : "—"}</TD>
                </TR>
              );
            })
          )}
        </TBody>
      </Table>
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
    <Drawer
      open
      onClose={onClose}
      title={actionLabel(event.action)}
      description={<span className="font-mono">{event.action}</span>}
      widthClassName="max-w-2xl"
    >
      <div className="space-y-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Info label="Time" value={ts} />
          <Info
            label="Outcome"
            value={<Badge tone={event.ok ? "ok" : "danger"}>{event.ok ? "OK" : "Error"}</Badge>}
          />
          <Info label="Duration" value={event.durationMs != null ? `${event.durationMs}ms` : "—"} />
          <Info label="Profile" value={profileLabel} />
          <Info label="Tool" value={event.toolRef ?? "—"} mono />
          <Info label="API key id" value={event.apiKeyId ?? "—"} mono />
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <Info label="HTTP method" value={event.httpMethod ?? "—"} mono />
          <Info label="Status" value={event.statusCode != null ? String(event.statusCode) : "—"} />
          <Info label="Error kind" value={event.errorKind ?? "—"} mono />
        </div>

        <DetailBlock
          label="HTTP route"
          copyValue={event.httpRoute ?? null}
          content={
            <div className="overflow-x-auto whitespace-nowrap font-mono text-sm text-fg">
              {event.httpRoute ?? "—"}
            </div>
          }
        />

        <DetailBlock
          label="Error message"
          copyValue={event.errorMessage ?? null}
          content={
            <pre className="overflow-x-auto whitespace-pre-wrap break-words font-mono text-xs text-fg">
              {event.errorMessage ?? "—"}
            </pre>
          }
        />

        <DetailBlock
          label="Meta"
          copyValue={formatJson(event.meta)}
          copyLabel="Copy JSON"
          content={
            <pre className="overflow-x-auto font-mono text-xs text-fg">
              {formatJson(event.meta)}
            </pre>
          }
        />
      </div>
    </Drawer>
  );
}

function Info({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="rounded-lg border border-edge bg-well px-4 py-3">
      <div className="eyebrow">{label}</div>
      <div className={`mt-1 text-sm text-fg ${mono ? "font-mono" : ""}`}>{value}</div>
    </div>
  );
}

function DetailBlock({
  label,
  content,
  copyValue,
  copyLabel = "Copy",
}: {
  label: string;
  content: ReactNode;
  copyValue: string | null;
  copyLabel?: string;
}) {
  return (
    <div className="overflow-hidden rounded-lg border border-edge bg-well">
      <div className="flex items-center justify-between gap-3 border-b border-edge px-4 py-2">
        <div className="eyebrow">{label}</div>
        {copyValue ? <CopyButton value={copyValue} label={copyLabel} /> : null}
      </div>
      <div className="p-4">{content}</div>
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
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <div className="overflow-hidden rounded-lg border border-edge bg-surface">
        <div className="flex items-center justify-between border-b border-edge px-5 py-3.5">
          <div className="eyebrow">Tool calls by tool</div>
          {loading ? <div className="text-xs text-faint">Loading…</div> : null}
        </div>
        <Table>
          <THead>
            <tr>
              <TH>Tool</TH>
              <TH className="text-right">Total</TH>
              <TH className="text-right">OK</TH>
              <TH className="text-right">Err</TH>
              <TH className="text-right">p99</TH>
            </tr>
          </THead>
          <TBody>
            {byTool.length === 0 ? (
              <tr>
                <TD className="py-6 text-muted" colSpan={5}>
                  No data.
                </TD>
              </tr>
            ) : (
              byTool.map((r) => (
                <TR key={r.toolRef}>
                  <TD className="font-mono">{r.toolRef}</TD>
                  <TD className="text-right font-mono text-muted">{r.total}</TD>
                  <TD className="text-right font-mono text-ok">{r.ok}</TD>
                  <TD className="text-right font-mono text-danger">{r.err}</TD>
                  <TD className="text-right font-mono text-muted">{r.p99DurationMs ?? "—"}</TD>
                </TR>
              ))
            )}
          </TBody>
        </Table>
      </div>

      <div className="overflow-hidden rounded-lg border border-edge bg-surface">
        <div className="flex items-center justify-between border-b border-edge px-5 py-3.5">
          <div className="eyebrow">Tool calls by API key</div>
          {loading ? <div className="text-xs text-faint">Loading…</div> : null}
        </div>
        <Table>
          <THead>
            <tr>
              <TH>API key id</TH>
              <TH className="text-right">Total</TH>
              <TH className="text-right">OK</TH>
              <TH className="text-right">Err</TH>
              <TH className="text-right">p99</TH>
            </tr>
          </THead>
          <TBody>
            {byApiKey.length === 0 ? (
              <tr>
                <TD className="py-6 text-muted" colSpan={5}>
                  No data.
                </TD>
              </tr>
            ) : (
              byApiKey.map((r) => (
                <TR key={r.apiKeyId}>
                  <TD className="font-mono">{r.apiKeyId}</TD>
                  <TD className="text-right font-mono text-muted">{r.total}</TD>
                  <TD className="text-right font-mono text-ok">{r.ok}</TD>
                  <TD className="text-right font-mono text-danger">{r.err}</TD>
                  <TD className="text-right font-mono text-muted">{r.p99DurationMs ?? "—"}</TD>
                </TR>
              ))
            )}
          </TBody>
        </Table>
      </div>
    </div>
  );
}
