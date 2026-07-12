"use client";

import { useParams, useRouter } from "next/navigation";
import { useCallback, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import {
  Badge,
  Button,
  Callout,
  Checkbox,
  ConfirmModal,
  EmptyState,
  EndpointWell,
  Input,
  QueryParamAuthWarning,
  SectionCard,
  Select,
  SkeletonRows,
  StatusBadge,
  Table,
  Tabs,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "@/components/ui";
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
            <Button variant="danger" onClick={() => setShowDelete(true)}>
              Delete
            </Button>
          ) : null
        }
      />

      <PageContent className="space-y-6">
        {!upstream ? (
          upstreamQuery.isPending ? (
            <SkeletonRows rows={3} />
          ) : (
            <EmptyState
              title="Upstream not found"
              description="This upstream doesn't exist or was deleted."
            />
          )
        ) : (
          <>
            {isManagedUpstream ? (
              <SectionCard title="Managed deployment">
                <div className="text-sm text-fg">
                  {managedDeployable?.displayName ??
                    latestManagedRequest?.deployableId ??
                    "Managed MCP upstream"}
                </div>
                <div className="mt-2 space-y-1 text-xs text-faint">
                  {managedDeployable ? (
                    <div>
                      Deployable ID:{" "}
                      <span className="font-mono text-muted">{managedDeployable.id}</span>
                    </div>
                  ) : null}
                  <div>
                    Upstream ID: <span className="font-mono text-muted">{upstream.id}</span>
                  </div>
                </div>
              </SectionCard>
            ) : null}

            <Tabs
              items={
                [
                  { value: "endpoints", label: "Endpoints" },
                  { value: "discovery", label: "Discovery" },
                ] as const
              }
              value={activeTab}
              onChange={setActiveTab}
            />

            {activeTab === "endpoints" && (
              <div className="space-y-4">
                <div className="flex items-center justify-between gap-4">
                  <div className="space-y-1">
                    <div className="text-sm text-muted">
                      {isManagedUpstream
                        ? "Managed endpoint used by the Gateway to connect to this deployment."
                        : "Endpoints used by the Gateway to connect to this upstream."}
                    </div>
                    {!isManagedUpstream ? (
                      <div className="text-xs text-faint">
                        Network class:{" "}
                        <span className="font-mono text-muted">{upstream.networkClass}</span> ·
                        Session TTL:{" "}
                        <span className="font-mono text-muted">
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

                {(effectiveDraft ?? []).length === 0 ? (
                  <EmptyState title="No endpoints" />
                ) : (
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
                      return (
                        <SectionCard
                          key={ep.id}
                          title={managedReadOnly ? "Managed endpoint" : "Endpoint"}
                          subtitle={
                            managedReadOnly ? (
                              <div className="space-y-1">
                                <div className="font-medium text-fg">
                                  {managedDeployable?.displayName ??
                                    latestManagedRequest?.deployableId ??
                                    "Managed MCP"}
                                </div>
                                {managedDeployable ? (
                                  <div className="text-xs text-faint">
                                    Deployable ID:{" "}
                                    <span className="font-mono text-muted">
                                      {managedDeployable.id}
                                    </span>
                                  </div>
                                ) : null}
                                <div className="text-xs text-faint">
                                  Revision:{" "}
                                  <span className="break-all font-mono text-muted">{ep.id}</span>
                                </div>
                              </div>
                            ) : (
                              <div className="space-y-1">
                                {(effectiveDraft?.length ?? 0) > 1 || ep.id !== "e1" ? (
                                  <div className="font-mono font-medium text-fg">{ep.id}</div>
                                ) : (
                                  <div className="font-medium text-fg">Primary</div>
                                )}
                                <div className="text-xs text-faint">
                                  Active sessions:{" "}
                                  <span className="font-mono text-muted">
                                    {activity?.activeSessions ?? 0}
                                  </span>{" "}
                                  · last seen{" "}
                                  <span className="text-muted">
                                    {formatLastSeen(activity?.lastSeenUnix)}
                                  </span>
                                </div>
                              </div>
                            )
                          }
                          right={
                            canEdit ? (
                              <div className="flex items-center gap-1">
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="sm"
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
                                  size="sm"
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
                                  size="sm"
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
                                  size="sm"
                                  disabled={endpointBusy}
                                  onClick={() => setDeleteEndpointId(ep.id)}
                                >
                                  Delete endpoint
                                </Button>
                              </div>
                            ) : (
                              <span className="text-xs text-faint">Read-only</span>
                            )
                          }
                        >
                          <div className="space-y-4">
                            {managedReadOnly ? (
                              <div className="space-y-1.5">
                                <div className="eyebrow">URL</div>
                                <EndpointWell url={ep.url} live={ep.enabled} />
                              </div>
                            ) : null}

                            <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
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
                                {managedReadOnly ? (
                                  <div className="space-y-1.5">
                                    <div className="block text-sm font-medium text-fg">
                                      Lifecycle
                                    </div>
                                    <div className="flex h-9 items-center">
                                      <Badge tone="neutral">{ep.lifecycle}</Badge>
                                    </div>
                                  </div>
                                ) : (
                                  <Select
                                    label="Lifecycle"
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
                                  >
                                    <option value="active">Active</option>
                                    <option value="draining">Draining</option>
                                    <option value="disabled">Disabled</option>
                                  </Select>
                                )}
                              </div>

                              <div className="space-y-1.5">
                                <div className="block text-sm font-medium text-fg">Enabled</div>
                                <div className="flex h-9 items-center">
                                  {managedReadOnly ? (
                                    <StatusBadge enabled={ep.enabled} />
                                  ) : (
                                    <Checkbox
                                      checked={ep.enabled}
                                      disabled={!canEdit}
                                      size="sm"
                                      label={ep.enabled ? "Enabled" : "Disabled"}
                                      onChange={(checked) =>
                                        updateDraft((rows) =>
                                          rows.map((r) =>
                                            r.id === ep.id ? { ...r, enabled: checked } : r,
                                          ),
                                        )
                                      }
                                    />
                                  )}
                                </div>
                              </div>
                            </div>

                            <div>
                              {managedReadOnly ? (
                                <div className="space-y-1.5">
                                  <div className="block text-sm font-medium text-fg">Auth</div>
                                  <div className="flex h-9 items-center">
                                    <Badge tone="neutral">{formatAuthTypeLabel(ep.authType)}</Badge>
                                  </div>
                                  <p className="text-xs text-faint">
                                    Managed upstream auth is controlled by deployment settings.
                                  </p>
                                </div>
                              ) : (
                                <>
                                  <Select
                                    label="Auth"
                                    hint="Used only for Gateway → upstream connections."
                                    value={ep.authType}
                                    disabled={!canEdit}
                                    onChange={(e) =>
                                      updateDraft((rows) =>
                                        rows.map((r) =>
                                          r.id === ep.id
                                            ? {
                                                ...r,
                                                authType: e.target
                                                  .value as EndpointDraft["authType"],
                                              }
                                            : r,
                                        ),
                                      )
                                    }
                                  >
                                    <option value="none">None</option>
                                    <option value="bearer">Bearer</option>
                                    <option value="basic">Basic</option>
                                    <option value="header">Header</option>
                                    <option value="query">Query</option>
                                  </Select>
                                  {ep.authType === "query" ? (
                                    <QueryParamAuthWarning className="mt-2" />
                                  ) : null}
                                </>
                              )}
                            </div>

                            {!managedReadOnly && ep.authType === "bearer" && (
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
                            )}
                            {!managedReadOnly && ep.authType === "basic" && (
                              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                                <Input
                                  label="Username"
                                  value={ep.basicUsername}
                                  disabled={!canEdit}
                                  onChange={(e) =>
                                    updateDraft((rows) =>
                                      rows.map((r) =>
                                        r.id === ep.id
                                          ? { ...r, basicUsername: e.target.value }
                                          : r,
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
                                        r.id === ep.id
                                          ? { ...r, basicPassword: e.target.value }
                                          : r,
                                      ),
                                    )
                                  }
                                />
                              </div>
                            )}
                            {!managedReadOnly && ep.authType === "header" && (
                              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
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
                              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
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
                        </SectionCard>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {activeTab === "discovery" && (
              <div className="space-y-4">
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <div className="text-sm font-medium text-fg">Discovered surface</div>
                    <div className="text-xs text-faint">
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

                {surfaceError ? <Callout tone="danger">{surfaceError}</Callout> : null}

                {surface ? (
                  <div className="space-y-6">
                    <div className="text-xs text-faint">
                      Tools: <span className="font-mono text-fg">{surface.tools.length}</span> ·
                      Resources:{" "}
                      <span className="font-mono text-fg">{surface.resources.length}</span> ·
                      Prompts: <span className="font-mono text-fg">{surface.prompts.length}</span>
                    </div>

                    <SectionCard
                      title="Sources"
                      subtitle="Per-endpoint status and counts."
                      className="overflow-hidden"
                      bodyClassName="p-0"
                    >
                      <Table>
                        <THead>
                          <TR>
                            <TH>Source</TH>
                            <TH>Status</TH>
                            <TH className="text-right">Tools</TH>
                            <TH className="text-right">Resources</TH>
                            <TH className="text-right">Prompts</TH>
                          </TR>
                        </THead>
                        <TBody>
                          {surface.sources.map((s) => (
                            <TR key={s.sourceId}>
                              <TD>
                                <div className="break-all font-mono text-[13px]">{s.sourceId}</div>
                                {!s.ok && s.error ? (
                                  <div className="mt-1 break-words text-xs text-danger">
                                    {s.error}
                                  </div>
                                ) : null}
                              </TD>
                              <TD>
                                <Badge tone={s.ok ? "ok" : "danger"} dot>
                                  {s.ok ? "OK" : "Error"}
                                </Badge>
                              </TD>
                              <TD className="text-right font-mono">{s.toolsCount}</TD>
                              <TD className="text-right font-mono">{s.resourcesCount}</TD>
                              <TD className="text-right font-mono">{s.promptsCount}</TD>
                            </TR>
                          ))}
                        </TBody>
                      </Table>
                    </SectionCard>

                    <SectionCard title="Tools" className="overflow-hidden" bodyClassName="p-0">
                      {surface.tools.length === 0 ? (
                        <div className="p-5">
                          <EmptyState title="No tools discovered" />
                        </div>
                      ) : (
                        <div className="divide-y divide-edge">
                          {surface.tools.slice(0, 200).map((t) => (
                            <div key={t.name} className="px-5 py-4">
                              <div className="font-mono text-sm font-medium text-accent">
                                {t.name}
                              </div>
                              {t.description ? (
                                <div className="mt-1 text-xs text-faint">{t.description}</div>
                              ) : null}
                            </div>
                          ))}
                        </div>
                      )}
                      {surface.tools.length > 200 ? (
                        <div className="border-t border-edge px-5 py-3 text-xs text-faint">
                          Showing first 200 tools.
                        </div>
                      ) : null}
                    </SectionCard>

                    <div className="grid gap-6 md:grid-cols-2">
                      <SectionCard
                        title="Resources"
                        right={
                          <span className="font-mono text-xs text-faint">
                            {surface.resources.length}
                          </span>
                        }
                      >
                        {surface.resources.length === 0 ? (
                          <EmptyState title="No resources discovered" />
                        ) : (
                          <div className="space-y-2">
                            {surface.resources.slice(0, 50).map((r) => (
                              <div
                                key={r.uri}
                                className="rounded-md border border-edge bg-well px-3 py-2"
                              >
                                <div className="break-all font-mono text-xs text-fg">{r.uri}</div>
                                {r.name ? (
                                  <div className="mt-1 text-xs text-faint">{r.name}</div>
                                ) : null}
                              </div>
                            ))}
                            {surface.resources.length > 50 ? (
                              <div className="text-xs text-faint">Showing first 50.</div>
                            ) : null}
                          </div>
                        )}
                      </SectionCard>

                      <SectionCard
                        title="Prompts"
                        right={
                          <span className="font-mono text-xs text-faint">
                            {surface.prompts.length}
                          </span>
                        }
                      >
                        {surface.prompts.length === 0 ? (
                          <EmptyState title="No prompts discovered" />
                        ) : (
                          <div className="space-y-2">
                            {surface.prompts.slice(0, 50).map((p) => (
                              <div
                                key={p.name}
                                className="rounded-md border border-edge bg-well px-3 py-2"
                              >
                                <div className="break-all font-mono text-xs text-fg">{p.name}</div>
                                {p.description ? (
                                  <div className="mt-1 text-xs text-faint">{p.description}</div>
                                ) : null}
                              </div>
                            ))}
                            {surface.prompts.length > 50 ? (
                              <div className="text-xs text-faint">Showing first 50.</div>
                            ) : null}
                          </div>
                        )}
                      </SectionCard>
                    </div>
                  </div>
                ) : (
                  <EmptyState
                    title="Nothing probed yet"
                    description="Probe to discover tools and other capabilities."
                  />
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
