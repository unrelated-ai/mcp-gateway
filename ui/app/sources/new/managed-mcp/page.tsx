"use client";

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import { Button } from "@/components/ui";
import { InfoIcon, ServerIconWireframe } from "@/components/icons";
import { qk } from "@/src/lib/queryKeys";
import * as tenantApi from "@/src/lib/tenantApi";
import { useToastStore } from "@/src/lib/toast-store";

type GatewayStatusResponse =
  | {
      ok: true;
      status: {
        topology?: string;
      };
    }
  | { ok: false; error?: string; status?: number };

function formatUnix(unix: number): string {
  return new Date(unix * 1000).toLocaleString();
}

function isInFlight(status: tenantApi.ManagedMcpDeploymentStatus): boolean {
  return status === "pending" || status === "reconciling";
}

function statusTone(status: tenantApi.ManagedMcpDeploymentStatus): string {
  if (status === "ready") return "bg-emerald-500/10 text-emerald-300 border-emerald-500/20";
  if (status === "failed") return "bg-red-500/10 text-red-300 border-red-500/20";
  if (status === "reconciling") return "bg-amber-500/10 text-amber-300 border-amber-500/20";
  return "bg-zinc-500/10 text-zinc-300 border-zinc-500/20";
}

export default function ManagedMcpDeployPage() {
  const queryClient = useQueryClient();
  const pushToast = useToastStore((s) => s.push);
  const [deployingId, setDeployingId] = useState<string | null>(null);
  const [updatingRequestId, setUpdatingRequestId] = useState<string | null>(null);
  const [replicaDrafts, setReplicaDrafts] = useState<Record<string, string>>({});

  const gatewayStatusQuery = useQuery({
    queryKey: qk.gatewayStatus(),
    queryFn: async () => {
      const res = await fetch("/api/gateway/status", { cache: "no-store" });
      return (await res.json()) as GatewayStatusResponse;
    },
  });
  const managedMcpSupported =
    gatewayStatusQuery.data?.ok && gatewayStatusQuery.data.status.topology === "operator-oss";

  const deployablesQuery = useQuery({
    queryKey: qk.managedMcpDeployables(),
    queryFn: tenantApi.listManagedMcpDeployables,
  });

  const deploymentsQuery = useQuery({
    queryKey: qk.managedMcpDeployments(),
    queryFn: tenantApi.listManagedMcpDeploymentRequests,
    refetchInterval: (query) => {
      const requests = query.state.data?.requests ?? [];
      if (!requests.some((request) => isInFlight(request.status))) return false;
      return 2000;
    },
  });

  const latestRequestByDeployable = useMemo(() => {
    const latest = new Map<string, tenantApi.ManagedMcpDeploymentRequest>();
    for (const request of deploymentsQuery.data?.requests ?? []) {
      const current = latest.get(request.deployableId);
      if (!current) {
        latest.set(request.deployableId, request);
        continue;
      }
      if (
        request.updatedAtUnix > current.updatedAtUnix ||
        (request.updatedAtUnix === current.updatedAtUnix &&
          request.createdAtUnix > current.createdAtUnix)
      ) {
        latest.set(request.deployableId, request);
      }
    }
    return latest;
  }, [deploymentsQuery.data?.requests]);

  const deployMutation = useMutation({
    mutationFn: async (deployableId: string) => {
      if (!managedMcpSupported) {
        throw new Error("Managed MCP requires Gateway topology operator-oss");
      }
      const response = await tenantApi.createManagedMcpDeploymentRequest(deployableId);
      return response.request;
    },
    onMutate: (deployableId) => {
      setDeployingId(deployableId);
    },
    onSuccess: async (request) => {
      await queryClient.invalidateQueries({ queryKey: qk.managedMcpDeployments() });
      if (request.status === "ready") {
        await queryClient.invalidateQueries({ queryKey: qk.upstreams() });
        pushToast({ variant: "success", message: "Managed MCP already deployed" });
      } else {
        pushToast({ variant: "success", message: "Deployment requested" });
      }
    },
    onError: (e) => {
      pushToast({
        variant: "error",
        message: e instanceof Error ? e.message : "Failed to request deployment",
      });
    },
    onSettled: () => {
      setDeployingId(null);
    },
  });

  const updateMutation = useMutation({
    mutationFn: async (input: {
      requestId: string;
      patch: { enabled?: boolean; replicas?: number };
    }) => {
      const response = await tenantApi.updateManagedMcpDeploymentRequest(
        input.requestId,
        input.patch,
      );
      return response.request;
    },
    onMutate: ({ requestId }) => {
      setUpdatingRequestId(requestId);
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: qk.managedMcpDeployments() });
      pushToast({ variant: "success", message: "Managed deployment update requested" });
    },
    onError: (e) => {
      pushToast({
        variant: "error",
        message: e instanceof Error ? e.message : "Failed to update managed deployment",
      });
    },
    onSettled: () => {
      setUpdatingRequestId(null);
    },
  });

  const deployables = deployablesQuery.data?.deployables ?? [];

  return (
    <AppShell>
      <PageHeader
        title="Deployment"
        description="Pick an approved deployable and request a cluster deployment. This creates a source in Gateway only; profile attachment remains manual."
        breadcrumb={[{ label: "Sources", href: "/sources" }, { label: "Deployment" }]}
      />

      <PageContent className="space-y-6">
        {!gatewayStatusQuery.isPending && !managedMcpSupported && (
          <section className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4 text-sm text-amber-200">
            Managed MCP requires Gateway topology <strong>operator-oss</strong>. Current topology:{" "}
            <span className="font-mono">
              {gatewayStatusQuery.data?.ok
                ? (gatewayStatusQuery.data.status.topology ?? "unknown")
                : "unavailable"}
            </span>
            .
          </section>
        )}

        <section className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 p-4 text-sm text-zinc-300">
          <div className="flex items-start gap-3">
            <InfoIcon className="w-5 h-5 text-violet-300 mt-0.5 shrink-0" />
            <p>
              Managed deployment only registers the source/upstream in Gateway. It does{" "}
              <strong>not</strong> auto-attach that source to any profile.
            </p>
          </div>
        </section>

        <section className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 overflow-hidden">
          <div className="px-5 py-4 border-b border-zinc-800/60">
            <h2 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
              <ServerIconWireframe className="w-5 h-5 text-violet-400" />
              Available deployables
            </h2>
            <p className="mt-1 text-xs text-zinc-500">
              Catalog is controlled by admins. Only enabled entries appear here.
            </p>
          </div>
          <div className="p-5">
            {deployablesQuery.isPending && <div className="text-sm text-zinc-400">Loading…</div>}
            {deployablesQuery.error && (
              <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-200">
                {deployablesQuery.error instanceof Error
                  ? deployablesQuery.error.message
                  : "Failed to load deployables"}
              </div>
            )}
            {deploymentsQuery.error && (
              <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-200">
                {deploymentsQuery.error instanceof Error
                  ? deploymentsQuery.error.message
                  : "Failed to load deployment status"}
              </div>
            )}
            {!deployablesQuery.isPending && !deployablesQuery.error && deployables.length === 0 && (
              <div className="text-sm text-zinc-500">
                No deployables are available right now. Ask an admin to publish entries.
              </div>
            )}
            {!deployablesQuery.isPending && !deployablesQuery.error && deployables.length > 0 && (
              <div className="space-y-3">
                {deployables.map((deployable) => {
                  const latest = latestRequestByDeployable.get(deployable.id);
                  const inFlight = latest ? isInFlight(latest.status) : false;
                  const isReady = latest?.status === "ready" && !!latest.upstreamId;
                  const controlsBusy =
                    !!latest &&
                    (inFlight || (updateMutation.isPending && updatingRequestId === latest.id));
                  const canDeploy =
                    !deployMutation.isPending && !inFlight && !isReady && managedMcpSupported;
                  const deployLabel = inFlight
                    ? "Deploying..."
                    : latest?.status === "failed"
                      ? "Retry deploy"
                      : "Deploy";
                  const draftReplicasRaw = latest
                    ? (replicaDrafts[latest.id] ?? String(latest.desiredReplicas))
                    : "1";
                  const parsedDraftReplicas = Number.parseInt(draftReplicasRaw, 10);
                  const draftReplicasValid =
                    Number.isFinite(parsedDraftReplicas) &&
                    parsedDraftReplicas >= 1 &&
                    parsedDraftReplicas <= 50;
                  const replicasDirty =
                    !!latest &&
                    draftReplicasValid &&
                    parsedDraftReplicas !== latest.desiredReplicas;

                  return (
                    <article
                      key={deployable.id}
                      className="rounded-xl border border-zinc-800/60 bg-zinc-950/30 p-4 flex items-start justify-between gap-4"
                    >
                      <div className="min-w-0">
                        <h3 className="text-base font-semibold text-zinc-100">
                          {deployable.displayName}
                        </h3>
                        {deployable.description ? (
                          <p className="mt-1 text-sm text-zinc-400">{deployable.description}</p>
                        ) : null}
                        {latest ? (
                          <div className="mt-2 flex items-center gap-2 text-xs">
                            <span
                              className={`px-2 py-0.5 rounded-md border font-medium ${statusTone(latest.status)}`}
                            >
                              {latest.status}
                            </span>
                            <span className="text-zinc-500">
                              Updated {formatUnix(latest.updatedAtUnix)}
                            </span>
                          </div>
                        ) : (
                          <div className="mt-2 text-xs text-zinc-500">Not deployed yet.</div>
                        )}
                        {latest ? (
                          <div className="mt-1 text-xs text-zinc-500">
                            Desired state: {latest.desiredEnabled ? "enabled" : "disabled"} ·
                            replicas {latest.desiredReplicas}
                          </div>
                        ) : null}
                        {latest?.status === "failed" && latest.message ? (
                          <p className="mt-2 text-xs text-red-300 break-words">{latest.message}</p>
                        ) : null}
                        <div className="mt-2 space-y-1 text-xs text-zinc-500">
                          <p>
                            ID: <span className="font-mono">{deployable.id}</span>
                          </p>
                          <p>
                            Image: <span className="font-mono break-all">{deployable.image}</span>
                          </p>
                        </div>
                      </div>
                      {isReady && latest ? (
                        <div className="shrink-0 space-y-2 w-[220px]">
                          <Button
                            type="button"
                            variant="ghost"
                            disabled={controlsBusy || updateMutation.isPending}
                            onClick={() => {
                              const nextEnabled = !latest.desiredEnabled;
                              const nextReplicas = nextEnabled
                                ? Math.max(latest.desiredReplicas, 1)
                                : 0;
                              updateMutation.mutate({
                                requestId: latest.id,
                                patch: { enabled: nextEnabled, replicas: nextReplicas },
                              });
                            }}
                          >
                            {latest.desiredEnabled ? "Disable" : "Enable"}
                          </Button>
                          <div className="rounded-lg border border-zinc-800/60 bg-zinc-900/50 p-2 space-y-2">
                            <label className="text-xs text-zinc-400">Replicas</label>
                            <input
                              type="number"
                              min={1}
                              max={50}
                              inputMode="numeric"
                              value={draftReplicasRaw}
                              disabled={
                                !latest.desiredEnabled ||
                                controlsBusy ||
                                updateMutation.isPending ||
                                (updatingRequestId != null && updatingRequestId !== latest.id)
                              }
                              onChange={(e) => {
                                const value = e.target.value;
                                setReplicaDrafts((prev) => ({ ...prev, [latest.id]: value }));
                              }}
                              className="w-full h-9 rounded-md bg-zinc-950 border border-zinc-800 px-2 text-sm text-zinc-200"
                            />
                            <Button
                              type="button"
                              disabled={
                                !latest.desiredEnabled ||
                                !draftReplicasValid ||
                                !replicasDirty ||
                                controlsBusy ||
                                updateMutation.isPending
                              }
                              onClick={() =>
                                updateMutation.mutate({
                                  requestId: latest.id,
                                  patch: { replicas: parsedDraftReplicas },
                                })
                              }
                            >
                              Apply
                            </Button>
                          </div>
                        </div>
                      ) : (
                        <Button
                          type="button"
                          onClick={() => deployMutation.mutate(deployable.id)}
                          loading={deployMutation.isPending && deployingId === deployable.id}
                          disabled={!canDeploy}
                        >
                          {deployLabel}
                        </Button>
                      )}
                    </article>
                  );
                })}
              </div>
            )}
          </div>
        </section>
      </PageContent>
    </AppShell>
  );
}
