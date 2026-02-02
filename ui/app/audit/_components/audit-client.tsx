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

export function AuditClient({ initialProfileId }: { initialProfileId?: string }) {
  const [tab, setTab] = useState<Tab>("events");
  const [profileId, setProfileId] = useState<string>(initialProfileId ?? "all");
  const [outcome, setOutcome] = useState<"all" | "ok" | "error">("all");
  const [range, setRange] = useState<"1h" | "24h" | "7d">("24h");

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
          />
        ) : (
          <AnalyticsView
            byTool={statsByToolQuery.data ?? []}
            byApiKey={statsByApiKeyQuery.data ?? []}
            loading={statsByToolQuery.isPending || statsByApiKeyQuery.isPending}
          />
        )}
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
}: {
  profiles: Profile[];
  events: AuditEventRow[];
  loading: boolean;
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
              <th className="text-left font-medium px-4 py-3">Action</th>
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
                return (
                  <tr key={e.id} className="border-t border-zinc-800/50">
                    <td className="px-4 py-3 text-zinc-300 whitespace-nowrap">{ts}</td>
                    <td className="px-4 py-3 text-zinc-200 font-mono">{e.action}</td>
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
