"use client";

import { useParams, useRouter } from "next/navigation";
import { useCallback, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import { Button, ConfirmModal, CopyButton, Input, QueryParamAuthWarning } from "@/components/ui";
import { qk } from "@/src/lib/queryKeys";
import * as tenantApi from "@/src/lib/tenantApi";
import { useToastStore } from "@/src/lib/toast-store";

type EndpointDraft = {
  id: string;
  url: string;
  enabled: boolean;
  lifecycle: tenantApi.UpstreamEndpointLifecycle;
  authType: "none" | "bearer" | "basic" | "header" | "query";
  bearerToken: string;
  basicUsername: string;
  basicPassword: string;
  headerName: string;
  headerValue: string;
  queryName: string;
  queryValue: string;
};

function endpointToDraft(ep: tenantApi.Upstream["endpoints"][number]): EndpointDraft {
  const auth = ep.auth ?? { type: "none" as const };
  const authType = auth.type;
  return {
    id: ep.id,
    url: ep.url,
    enabled: ep.enabled,
    lifecycle: ep.lifecycle,
    authType,
    bearerToken: authType === "bearer" ? auth.token : "",
    basicUsername: authType === "basic" ? auth.username : "",
    basicPassword: authType === "basic" ? auth.password : "",
    headerName: authType === "header" ? auth.name : "",
    headerValue: authType === "header" ? auth.value : "",
    queryName: authType === "query" ? auth.name : "",
    queryValue: authType === "query" ? auth.value : "",
  };
}

function draftToEndpoint(d: EndpointDraft): {
  id: string;
  url: string;
  enabled: boolean;
  lifecycle: tenantApi.UpstreamEndpointLifecycle;
  auth?: tenantApi.AuthConfig;
} {
  const url = d.url.trim();
  const authType = d.authType;
  if (authType === "none") {
    return { id: d.id, url, enabled: d.enabled, lifecycle: d.lifecycle, auth: { type: "none" } };
  }
  if (authType === "bearer")
    return {
      id: d.id,
      url,
      enabled: d.enabled,
      lifecycle: d.lifecycle,
      auth: { type: "bearer", token: d.bearerToken },
    };
  if (authType === "basic")
    return {
      id: d.id,
      url,
      enabled: d.enabled,
      lifecycle: d.lifecycle,
      auth: { type: "basic", username: d.basicUsername, password: d.basicPassword },
    };
  if (authType === "header")
    return {
      id: d.id,
      url,
      enabled: d.enabled,
      lifecycle: d.lifecycle,
      auth: { type: "header", name: d.headerName, value: d.headerValue },
    };
  return {
    id: d.id,
    url,
    enabled: d.enabled,
    lifecycle: d.lifecycle,
    auth: { type: "query", name: d.queryName, value: d.queryValue },
  };
}

function formatLastSeen(unix: number | null | undefined): string {
  if (unix == null) return "never";
  const now = Math.floor(Date.now() / 1000);
  const delta = Math.max(0, now - unix);
  if (delta < 60) return `${delta}s ago`;
  if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
  if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
  return `${Math.floor(delta / 86400)}d ago`;
}

function formatAuthTypeLabel(authType: EndpointDraft["authType"]): string {
  switch (authType) {
    case "bearer":
      return "Bearer";
    case "basic":
      return "Basic";
    case "header":
      return "Header";
    case "query":
      return "Query";
    default:
      return "None";
  }
}

export default function UpstreamDetailPage() {
  const params = useParams();
  const router = useRouter();
  const upstreamId = String(params.upstreamId ?? "");
  const isManagedUpstreamId = upstreamId.startsWith("managed_");

  const queryClient = useQueryClient();
  const pushToast = useToastStore((s) => s.push);

  const upstreamQuery = useQuery({
    queryKey: qk.upstream(upstreamId),
    enabled: !!upstreamId,
    queryFn: () => tenantApi.getUpstream(upstreamId),
  });
  const upstream = upstreamQuery.data ?? null;

  const managedDeploymentsQuery = useQuery({
    queryKey: qk.managedMcpDeployments(),
    enabled: isManagedUpstreamId,
    queryFn: tenantApi.listManagedMcpDeploymentRequests,
  });
  const managedDeployablesQuery = useQuery({
    queryKey: qk.managedMcpDeployables(),
    enabled: isManagedUpstreamId,
    queryFn: tenantApi.listManagedMcpDeployables,
  });
  const latestManagedRequest = useMemo(() => {
    if (!isManagedUpstreamId) return null;
    let latest: tenantApi.ManagedMcpDeploymentRequest | null = null;
    for (const request of managedDeploymentsQuery.data?.requests ?? []) {
      if (request.upstreamId !== upstreamId) continue;
      if (!latest) {
        latest = request;
        continue;
      }
      if (
        request.updatedAtUnix > latest.updatedAtUnix ||
        (request.updatedAtUnix === latest.updatedAtUnix &&
          request.createdAtUnix > latest.createdAtUnix)
      ) {
        latest = request;
      }
    }
    return latest;
  }, [isManagedUpstreamId, managedDeploymentsQuery.data?.requests, upstreamId]);
  const managedDeployable = useMemo(() => {
    const deployableId = latestManagedRequest?.deployableId;
    if (!deployableId) return null;
    return (
      (managedDeployablesQuery.data?.deployables ?? []).find((d) => d.id === deployableId) ?? null
    );
  }, [latestManagedRequest?.deployableId, managedDeployablesQuery.data?.deployables]);

  const [activeTab, setActiveTab] = useState<"endpoints" | "discovery">("endpoints");
  const [draft, setDraft] = useState<EndpointDraft[] | null>(null);
  const [showDelete, setShowDelete] = useState(false);
  const [deleteEndpointId, setDeleteEndpointId] = useState<string | null>(null);

  const [surface, setSurface] = useState<tenantApi.UpstreamSurface | null>(null);
  const [surfaceError, setSurfaceError] = useState<string | null>(null);

  const sessionActivityQuery = useQuery({
    queryKey: qk.upstreamSessionActivity(upstreamId, 300),
    enabled: !!upstreamId && activeTab === "endpoints" && !isManagedUpstreamId,
    queryFn: () => tenantApi.getUpstreamSessionActivity(upstreamId, 300),
    refetchInterval: 15000,
  });
  const sessionActivityByEndpoint = useMemo(() => {
    const map = new Map<string, tenantApi.UpstreamEndpointActivity>();
    for (const row of sessionActivityQuery.data?.endpoints ?? []) {
      map.set(row.endpointId, row);
    }
    return map;
  }, [sessionActivityQuery.data]);

  const canEdit = upstream?.owner === "tenant";
  const isManagedUpstream = upstream?.id.startsWith("managed_") ?? false;

  const initialDraft = useMemo(() => {
    if (!upstream) return null;
    return upstream.endpoints.map(endpointToDraft);
  }, [upstream]);

  const effectiveDraft = draft ?? initialDraft;

  const updateDraft = useCallback(
    (update: (rows: EndpointDraft[]) => EndpointDraft[]) => {
      setDraft((prev) => update(prev ?? initialDraft ?? []));
    },
    [initialDraft],
  );

  const dirty = useMemo(() => {
    if (!upstream || !effectiveDraft) return false;
    const a = JSON.stringify(
      upstream.endpoints.map((e) => ({
        id: e.id,
        url: e.url,
        enabled: e.enabled,
        lifecycle: e.lifecycle,
        auth: e.auth ?? null,
      })),
    );
    const b = JSON.stringify(effectiveDraft.map(draftToEndpoint));
    return a !== b;
  }, [upstream, effectiveDraft]);

  const saveMutation = useMutation({
    mutationFn: async () => {
      if (!upstream || !effectiveDraft) throw new Error("Upstream not loaded");
      await tenantApi.putUpstream(upstreamId, {
        enabled: upstream.enabled,
        endpoints: effectiveDraft.map(draftToEndpoint),
      });
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: qk.upstream(upstreamId) });
      await queryClient.invalidateQueries({ queryKey: qk.upstreams() });
      pushToast({ variant: "success", message: "Upstream saved" });
      setDraft(null);
    },
    onError: (e) => {
      pushToast({
        variant: "error",
        message: e instanceof Error ? e.message : "Failed to save upstream",
      });
    },
  });

  const patchEndpointMutation = useMutation({
    mutationFn: async (args: {
      endpointId: string;
      enabled?: boolean;
      lifecycle?: tenantApi.UpstreamEndpointLifecycle;
    }) => {
      await tenantApi.patchUpstreamEndpoint(upstreamId, args.endpointId, {
        enabled: args.enabled,
        lifecycle: args.lifecycle,
      });
      return args.endpointId;
    },
    onSuccess: async (endpointId) => {
      await queryClient.invalidateQueries({ queryKey: qk.upstream(upstreamId) });
      await queryClient.invalidateQueries({ queryKey: qk.upstreams() });
      await queryClient.invalidateQueries({
        queryKey: qk.upstreamSessionActivity(upstreamId, 300),
      });
      setDraft(null);
      pushToast({ variant: "success", message: `Endpoint "${endpointId}" updated` });
    },
    onError: (e) => {
      pushToast({
        variant: "error",
        message: e instanceof Error ? e.message : "Failed to update endpoint",
      });
    },
  });

  const deleteEndpointMutation = useMutation({
    mutationFn: async (endpointId: string) => {
      await tenantApi.deleteUpstreamEndpoint(upstreamId, endpointId);
      return endpointId;
    },
    onSuccess: async (endpointId) => {
      await queryClient.invalidateQueries({ queryKey: qk.upstream(upstreamId) });
      await queryClient.invalidateQueries({ queryKey: qk.upstreams() });
      await queryClient.invalidateQueries({
        queryKey: qk.upstreamSessionActivity(upstreamId, 300),
      });
      setDraft(null);
      setDeleteEndpointId(null);
      pushToast({ variant: "success", message: `Endpoint "${endpointId}" deleted` });
    },
    onError: (e) => {
      pushToast({
        variant: "error",
        message: e instanceof Error ? e.message : "Failed to delete endpoint",
      });
    },
  });

  const probeMutation = useMutation({
    mutationFn: () => tenantApi.probeUpstreamSurface(upstreamId),
    onSuccess: (resp) => {
      setSurface(resp);
      setSurfaceError(null);
    },
    onError: (e) => {
      setSurface(null);
      setSurfaceError(e instanceof Error ? e.message : "Failed to probe upstream");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => tenantApi.deleteUpstream(upstreamId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: qk.upstreams() });
      pushToast({ variant: "success", message: "Upstream deleted" });
      router.push("/sources");
    },
    onError: (e) => {
      pushToast({
        variant: "error",
        message: e instanceof Error ? e.message : "Failed to delete upstream",
      });
    },
  });

  const headerTitle = upstream
    ? isManagedUpstream
      ? (managedDeployable?.displayName ?? latestManagedRequest?.deployableId ?? upstream.id)
      : upstream.id
    : "Upstream";
  const headerDescription = isManagedUpstream
    ? "Managed MCP upstream."
    : "Streamable HTTP MCP upstream.";

  return (
    <AppShell>
      <PageHeader
        title={headerTitle}
        description={headerDescription}
        breadcrumb={[
          { label: "Sources", href: "/sources" },
          { label: "Upstreams", href: "/sources" },
          { label: upstreamId },
        ]}
        actions={
          canEdit ? (
            <div className="flex items-center gap-2">
              <button
                onClick={() => setShowDelete(true)}
                className="px-4 py-2 rounded-lg text-sm font-medium text-red-400 hover:text-red-300 hover:bg-red-500/10 transition-colors"
              >
                Delete
              </button>
            </div>
          ) : null
        }
      />

      <PageContent className="space-y-6">
        {!upstream ? (
          <div className="text-sm text-zinc-400">
            {upstreamQuery.isPending ? "Loading…" : "Not found"}
          </div>
        ) : (
          <>
            {isManagedUpstream ? (
              <section className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 p-4">
                <div className="text-xs font-medium text-zinc-400">Managed deployment</div>
                <div className="mt-1 text-sm text-zinc-200">
                  {managedDeployable?.displayName ??
                    latestManagedRequest?.deployableId ??
                    "Managed MCP upstream"}
                </div>
                <div className="mt-1 text-xs text-zinc-500 space-y-1">
                  {managedDeployable ? (
                    <div>
                      Deployable ID:{" "}
                      <span className="font-mono text-zinc-300">{managedDeployable.id}</span>
                    </div>
                  ) : null}
                  <div>
                    Upstream ID: <span className="font-mono text-zinc-300">{upstream.id}</span>
                  </div>
                </div>
              </section>
            ) : null}

            <div className="flex items-center gap-1 border-b border-zinc-800/60">
              {(
                [
                  { key: "endpoints", label: "Endpoints" },
                  { key: "discovery", label: "Discovery" },
                ] as const
              ).map((t) => (
                <button
                  key={t.key}
                  onClick={() => setActiveTab(t.key)}
                  className={`px-4 py-2.5 text-sm font-medium transition-colors relative ${
                    activeTab === t.key ? "text-white" : "text-zinc-500 hover:text-zinc-300"
                  }`}
                >
                  {t.label}
                  {activeTab === t.key && (
                    <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-violet-500 rounded-full" />
                  )}
                </button>
              ))}
            </div>

            {activeTab === "endpoints" && (
              <div className="space-y-4">
                <div className="flex items-center justify-between gap-4">
                  <div className="space-y-1">
                    <div className="text-sm text-zinc-400">
                      {isManagedUpstream
                        ? "Managed endpoint used by the Gateway to connect to this deployment."
                        : "Endpoints used by the Gateway to connect to this upstream."}
                    </div>
                    {!isManagedUpstream ? (
                      <div className="text-xs text-zinc-500">
                        Network class:{" "}
                        <span className="text-zinc-300">{upstream.networkClass}</span> · Session
                        TTL:{" "}
                        <span className="text-zinc-300">
                          {sessionActivityQuery.data?.ttlSecs ?? 300}s
                        </span>
                      </div>
                    ) : null}
                  </div>
                  <div className="flex items-center gap-2">
                    {!isManagedUpstream ? (
                      <Button
                        type="button"
                        variant="ghost"
                        onClick={() =>
                          queryClient.invalidateQueries({
                            queryKey: qk.upstreamSessionActivity(upstreamId, 300),
                          })
                        }
                        disabled={sessionActivityQuery.isFetching}
                      >
                        {sessionActivityQuery.isFetching ? "Refreshing…" : "Refresh activity"}
                      </Button>
                    ) : null}
                    {canEdit ? (
                      <>
                        <Button
                          type="button"
                          variant="ghost"
                          disabled={!dirty || saveMutation.isPending}
                          onClick={() => setDraft(null)}
                        >
                          Reset
                        </Button>
                        <Button
                          type="button"
                          disabled={!dirty}
                          loading={saveMutation.isPending}
                          onClick={() => saveMutation.mutate()}
                        >
                          Save
                        </Button>
                      </>
                    ) : null}
                  </div>
                </div>

                <div className="space-y-3">
                  {(effectiveDraft ?? []).map((ep) => {
                    const activity = sessionActivityByEndpoint.get(ep.id);
                    const patchingThis =
                      patchEndpointMutation.isPending &&
                      patchEndpointMutation.variables?.endpointId === ep.id;
                    const deletingThis =
                      deleteEndpointMutation.isPending &&
                      deleteEndpointMutation.variables === ep.id;
                    const endpointBusy = patchingThis || deletingThis || saveMutation.isPending;
                    const managedReadOnly = isManagedUpstream && !canEdit;
                    const urlTone = ep.enabled
                      ? "bg-emerald-500/5 border-emerald-500/25 text-emerald-200"
                      : "bg-zinc-950/60 border-zinc-800 text-zinc-200";
                    return (
                      <div
                        key={ep.id}
                        className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 p-5"
                      >
                        <div className="flex items-start justify-between gap-4">
                          <div className="min-w-0">
                            <div className="text-xs text-zinc-500">
                              {managedReadOnly ? "Managed endpoint" : "Endpoint"}
                            </div>
                            {managedReadOnly ? (
                              <>
                                <div className="text-sm font-semibold text-zinc-200">
                                  {managedDeployable?.displayName ??
                                    latestManagedRequest?.deployableId ??
                                    "Managed MCP"}
                                </div>
                                {managedDeployable ? (
                                  <div className="mt-1 text-xs text-zinc-500">
                                    Deployable ID:{" "}
                                    <span className="font-mono text-zinc-300">
                                      {managedDeployable.id}
                                    </span>
                                  </div>
                                ) : null}
                                <div className="mt-1 text-xs text-zinc-500">
                                  Revision:{" "}
                                  <span className="font-mono text-zinc-300 break-all">{ep.id}</span>
                                </div>
                              </>
                            ) : (
                              <>
                                {(effectiveDraft?.length ?? 0) > 1 || ep.id !== "e1" ? (
                                  <div className="text-sm font-semibold text-zinc-200 font-mono">
                                    {ep.id}
                                  </div>
                                ) : (
                                  <div className="text-sm font-semibold text-zinc-200">Primary</div>
                                )}
                                <div className="mt-1 text-xs text-zinc-500">
                                  Active sessions:{" "}
                                  <span className="text-zinc-300">
                                    {activity?.activeSessions ?? 0}
                                  </span>{" "}
                                  · last seen{" "}
                                  <span className="text-zinc-300">
                                    {formatLastSeen(activity?.lastSeenUnix)}
                                  </span>
                                </div>
                              </>
                            )}
                          </div>
                          {canEdit ? (
                            <div className="flex items-center gap-2">
                              <Button
                                type="button"
                                variant="ghost"
                                disabled={endpointBusy}
                                onClick={() =>
                                  patchEndpointMutation.mutate({
                                    endpointId: ep.id,
                                    enabled: true,
                                    lifecycle: "active",
                                  })
                                }
                              >
                                Activate
                              </Button>
                              <Button
                                type="button"
                                variant="ghost"
                                disabled={endpointBusy}
                                onClick={() =>
                                  patchEndpointMutation.mutate({
                                    endpointId: ep.id,
                                    lifecycle: "draining",
                                  })
                                }
                              >
                                Drain
                              </Button>
                              <Button
                                type="button"
                                variant="ghost"
                                disabled={endpointBusy}
                                onClick={() =>
                                  patchEndpointMutation.mutate({
                                    endpointId: ep.id,
                                    enabled: false,
                                    lifecycle: "disabled",
                                  })
                                }
                              >
                                Disable
                              </Button>
                              <Button
                                type="button"
                                variant="ghost"
                                disabled={endpointBusy}
                                onClick={() => setDeleteEndpointId(ep.id)}
                              >
                                Delete endpoint
                              </Button>
                            </div>
                          ) : (
                            <div className="text-xs text-zinc-500">read-only</div>
                          )}
                        </div>

                        <div className="mt-4 space-y-4">
                          {managedReadOnly ? (
                            <div>
                              <div className="text-xs font-medium text-zinc-400 mb-2">URL</div>
                              <div className="flex items-center gap-2">
                                <code
                                  className={`flex-1 min-w-0 px-4 py-2.5 rounded-xl border text-sm font-mono break-all ${urlTone}`}
                                >
                                  {ep.url}
                                </code>
                                <CopyButton text={ep.url} label="Copy URL" size="md" />
                              </div>
                            </div>
                          ) : null}

                          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                            {!managedReadOnly ? (
                              <Input
                                label="URL"
                                value={ep.url}
                                disabled={!canEdit}
                                onChange={(e) =>
                                  updateDraft((rows) =>
                                    rows.map((r) =>
                                      r.id === ep.id ? { ...r, url: e.target.value } : r,
                                    ),
                                  )
                                }
                                className="md:col-span-2"
                              />
                            ) : null}

                            <div className={managedReadOnly ? "md:col-span-2" : ""}>
                              <div className="text-xs font-medium text-zinc-400 mb-2">
                                Lifecycle
                              </div>
                              {managedReadOnly ? (
                                <div className="inline-flex items-center h-10 px-3 rounded-xl border border-zinc-800 bg-zinc-950/40 text-sm text-zinc-200">
                                  {ep.lifecycle}
                                </div>
                              ) : (
                                <select
                                  value={ep.lifecycle}
                                  disabled={!canEdit}
                                  onChange={(e) =>
                                    updateDraft((rows) =>
                                      rows.map((r) =>
                                        r.id === ep.id
                                          ? {
                                              ...r,
                                              lifecycle: e.target
                                                .value as tenantApi.UpstreamEndpointLifecycle,
                                            }
                                          : r,
                                      ),
                                    )
                                  }
                                  className="w-full h-10 rounded-xl bg-zinc-900 border border-zinc-800 px-3 text-sm text-zinc-200"
                                >
                                  <option value="active">active</option>
                                  <option value="draining">draining</option>
                                  <option value="disabled">disabled</option>
                                </select>
                              )}
                            </div>

                            <div>
                              <div className="text-xs font-medium text-zinc-400 mb-2">Enabled</div>
                              {managedReadOnly ? (
                                <span className="inline-flex items-center h-10 px-3 rounded-xl border border-zinc-800 bg-zinc-950/40 text-sm text-zinc-200">
                                  {ep.enabled ? "enabled" : "disabled"}
                                </span>
                              ) : (
                                <label className="inline-flex items-center gap-2 text-sm text-zinc-300 h-10">
                                  <input
                                    type="checkbox"
                                    checked={ep.enabled}
                                    disabled={!canEdit}
                                    onChange={(e) =>
                                      updateDraft((rows) =>
                                        rows.map((r) =>
                                          r.id === ep.id ? { ...r, enabled: e.target.checked } : r,
                                        ),
                                      )
                                    }
                                    className="rounded border-zinc-700 bg-zinc-900"
                                  />
                                  {ep.enabled ? "enabled" : "disabled"}
                                </label>
                              )}
                            </div>
                          </div>
                        </div>

                        <div className="mt-4">
                          <div className="text-xs font-medium text-zinc-400 mb-2">Auth</div>
                          {managedReadOnly ? (
                            <>
                              <div className="inline-flex items-center h-10 px-3 rounded-xl border border-zinc-800 bg-zinc-950/40 text-sm text-zinc-200">
                                {formatAuthTypeLabel(ep.authType)}
                              </div>
                              <div className="mt-2 text-xs text-zinc-500">
                                Managed upstream auth is controlled by deployment settings.
                              </div>
                            </>
                          ) : (
                            <>
                              <select
                                value={ep.authType}
                                disabled={!canEdit}
                                onChange={(e) =>
                                  updateDraft((rows) =>
                                    rows.map((r) =>
                                      r.id === ep.id
                                        ? {
                                            ...r,
                                            authType: e.target.value as EndpointDraft["authType"],
                                          }
                                        : r,
                                    ),
                                  )
                                }
                                className="w-full h-10 rounded-xl bg-zinc-900 border border-zinc-800 px-3 text-sm text-zinc-200"
                              >
                                <option value="none">None</option>
                                <option value="bearer">Bearer</option>
                                <option value="basic">Basic</option>
                                <option value="header">Header</option>
                                <option value="query">Query</option>
                              </select>
                              <div className="mt-2 text-xs text-zinc-500">
                                Used only for Gateway → upstream connections.
                              </div>
                              {ep.authType === "query" ? (
                                <QueryParamAuthWarning className="mt-2" />
                              ) : null}
                            </>
                          )}
                        </div>

                        {!managedReadOnly && ep.authType === "bearer" && (
                          <div className="mt-4">
                            <Input
                              label="Bearer token"
                              type="password"
                              value={ep.bearerToken}
                              disabled={!canEdit}
                              onChange={(e) =>
                                updateDraft((rows) =>
                                  rows.map((r) =>
                                    r.id === ep.id ? { ...r, bearerToken: e.target.value } : r,
                                  ),
                                )
                              }
                            />
                          </div>
                        )}
                        {!managedReadOnly && ep.authType === "basic" && (
                          <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                            <Input
                              label="Username"
                              value={ep.basicUsername}
                              disabled={!canEdit}
                              onChange={(e) =>
                                updateDraft((rows) =>
                                  rows.map((r) =>
                                    r.id === ep.id ? { ...r, basicUsername: e.target.value } : r,
                                  ),
                                )
                              }
                            />
                            <Input
                              label="Password"
                              type="password"
                              value={ep.basicPassword}
                              disabled={!canEdit}
                              onChange={(e) =>
                                updateDraft((rows) =>
                                  rows.map((r) =>
                                    r.id === ep.id ? { ...r, basicPassword: e.target.value } : r,
                                  ),
                                )
                              }
                            />
                          </div>
                        )}
                        {!managedReadOnly && ep.authType === "header" && (
                          <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                            <Input
                              label="Header name"
                              value={ep.headerName}
                              disabled={!canEdit}
                              onChange={(e) =>
                                updateDraft((rows) =>
                                  rows.map((r) =>
                                    r.id === ep.id ? { ...r, headerName: e.target.value } : r,
                                  ),
                                )
                              }
                            />
                            <Input
                              label="Header value"
                              type="password"
                              value={ep.headerValue}
                              disabled={!canEdit}
                              onChange={(e) =>
                                updateDraft((rows) =>
                                  rows.map((r) =>
                                    r.id === ep.id ? { ...r, headerValue: e.target.value } : r,
                                  ),
                                )
                              }
                            />
                          </div>
                        )}
                        {!managedReadOnly && ep.authType === "query" && (
                          <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                            <Input
                              label="Query name"
                              value={ep.queryName}
                              disabled={!canEdit}
                              onChange={(e) =>
                                updateDraft((rows) =>
                                  rows.map((r) =>
                                    r.id === ep.id ? { ...r, queryName: e.target.value } : r,
                                  ),
                                )
                              }
                            />
                            <Input
                              label="Query value"
                              type="password"
                              value={ep.queryValue}
                              disabled={!canEdit}
                              onChange={(e) =>
                                updateDraft((rows) =>
                                  rows.map((r) =>
                                    r.id === ep.id ? { ...r, queryValue: e.target.value } : r,
                                  ),
                                )
                              }
                            />
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {activeTab === "discovery" && (
              <div className="space-y-4">
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <div className="text-sm font-medium text-zinc-300">Discovered surface</div>
                    <div className="text-xs text-zinc-500">
                      Probes tools/resources/prompts via the Gateway (no browser MCP).
                    </div>
                  </div>
                  <Button
                    type="button"
                    variant="secondary"
                    onClick={() => probeMutation.mutate()}
                    loading={probeMutation.isPending}
                  >
                    Probe
                  </Button>
                </div>

                {surfaceError ? (
                  <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-200">
                    {surfaceError}
                  </div>
                ) : null}

                {surface ? (
                  <div className="space-y-6">
                    <div className="text-xs text-zinc-500">
                      Tools: <span className="text-zinc-200">{surface.tools.length}</span> ·
                      Resources: <span className="text-zinc-200">{surface.resources.length}</span> ·
                      Prompts: <span className="text-zinc-200">{surface.prompts.length}</span>
                    </div>

                    <div className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 overflow-hidden">
                      <div className="px-5 py-4 border-b border-zinc-800/60">
                        <div className="text-sm font-medium text-zinc-200">Sources</div>
                        <div className="mt-1 text-xs text-zinc-500">
                          Per-endpoint status and counts.
                        </div>
                      </div>
                      <div className="divide-y divide-zinc-800/40">
                        {surface.sources.map((s) => (
                          <div key={s.sourceId} className="p-5">
                            <div className="flex items-start justify-between gap-4">
                              <div className="min-w-0">
                                <div className="text-sm text-zinc-200 font-mono break-all">
                                  {s.sourceId}
                                </div>
                                {!s.ok && s.error ? (
                                  <div className="mt-1 text-xs text-red-200 break-words">
                                    {s.error}
                                  </div>
                                ) : null}
                              </div>
                              <div className="text-xs text-zinc-500 shrink-0">
                                tools {s.toolsCount} · res {s.resourcesCount} · prompts{" "}
                                {s.promptsCount}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 overflow-hidden">
                      <div className="px-5 py-4 border-b border-zinc-800/60">
                        <div className="text-sm font-medium text-zinc-200">Tools</div>
                      </div>
                      <div className="divide-y divide-zinc-800/40">
                        {surface.tools.length === 0 ? (
                          <div className="p-5 text-sm text-zinc-500">No tools discovered.</div>
                        ) : (
                          surface.tools.slice(0, 200).map((t) => (
                            <div key={t.name} className="p-5">
                              <div className="text-sm font-semibold text-violet-300 font-mono">
                                {t.name}
                              </div>
                              {t.description ? (
                                <div className="mt-1 text-xs text-zinc-500">{t.description}</div>
                              ) : null}
                            </div>
                          ))
                        )}
                      </div>
                      {surface.tools.length > 200 ? (
                        <div className="px-5 py-3 text-xs text-zinc-500">
                          Showing first 200 tools.
                        </div>
                      ) : null}
                    </div>

                    <div className="grid gap-6 md:grid-cols-2">
                      <div className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 p-5">
                        <div className="flex items-center justify-between mb-3">
                          <div className="text-sm font-semibold text-zinc-100">Resources</div>
                          <div className="text-xs text-zinc-500">{surface.resources.length}</div>
                        </div>
                        {surface.resources.length === 0 ? (
                          <div className="text-sm text-zinc-500">No resources discovered.</div>
                        ) : (
                          <div className="space-y-2">
                            {surface.resources.slice(0, 50).map((r) => (
                              <div
                                key={r.uri}
                                className="rounded-lg border border-zinc-800/60 bg-zinc-950/40 px-3 py-2"
                              >
                                <div className="font-mono text-xs text-zinc-200 break-all">
                                  {r.uri}
                                </div>
                                {r.name ? (
                                  <div className="text-xs text-zinc-500 mt-1">{r.name}</div>
                                ) : null}
                              </div>
                            ))}
                            {surface.resources.length > 50 ? (
                              <div className="text-xs text-zinc-500">Showing first 50.</div>
                            ) : null}
                          </div>
                        )}
                      </div>

                      <div className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 p-5">
                        <div className="flex items-center justify-between mb-3">
                          <div className="text-sm font-semibold text-zinc-100">Prompts</div>
                          <div className="text-xs text-zinc-500">{surface.prompts.length}</div>
                        </div>
                        {surface.prompts.length === 0 ? (
                          <div className="text-sm text-zinc-500">No prompts discovered.</div>
                        ) : (
                          <div className="space-y-2">
                            {surface.prompts.slice(0, 50).map((p) => (
                              <div
                                key={p.name}
                                className="rounded-lg border border-zinc-800/60 bg-zinc-950/40 px-3 py-2"
                              >
                                <div className="font-mono text-xs text-zinc-200 break-all">
                                  {p.name}
                                </div>
                                {p.description ? (
                                  <div className="text-xs text-zinc-500 mt-1">{p.description}</div>
                                ) : null}
                              </div>
                            ))}
                            {surface.prompts.length > 50 ? (
                              <div className="text-xs text-zinc-500">Showing first 50.</div>
                            ) : null}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 p-5 text-sm text-zinc-400">
                    Click “Probe” to discover tools and other capabilities.
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </PageContent>

      <ConfirmModal
        open={showDelete}
        onClose={() => setShowDelete(false)}
        onConfirm={() => deleteMutation.mutate()}
        title={`Delete upstream "${upstreamId}"?`}
        description="This will permanently delete it. Any profiles using it will break until you attach a replacement."
        confirmLabel="Delete"
        danger
        loading={deleteMutation.isPending}
      />
      <ConfirmModal
        open={!!deleteEndpointId}
        onClose={() => {
          if (!deleteEndpointMutation.isPending) setDeleteEndpointId(null);
        }}
        onConfirm={() => {
          if (!deleteEndpointId) return;
          deleteEndpointMutation.mutate(deleteEndpointId);
        }}
        title={deleteEndpointId ? `Delete endpoint "${deleteEndpointId}"?` : "Delete endpoint?"}
        description="This permanently removes the endpoint from this upstream. Ongoing sessions on this endpoint may fail and reconnect elsewhere."
        confirmLabel="Delete endpoint"
        danger
        loading={deleteEndpointMutation.isPending}
      />
    </AppShell>
  );
}
