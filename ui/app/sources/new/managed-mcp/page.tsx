"use client";

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import {
  Badge,
  Button,
  Callout,
  Input,
  SectionCard,
  SkeletonRows,
  type Tone,
} from "@/components/ui";
import { InfoIcon } from "@/components/icons";
import { qk } from "@/src/lib/queryKeys";
import * as tenantApi from "@/src/lib/tenantApi";
import { useToastStore } from "@/src/lib/toast-store";

type GatewayStatusResponse =
  | {
      ok: true;
      status: {
        topology?: string;
        managedMcp?: {
          backendMode?: string;
          enabled?: boolean;
          reconcilerHealthy?: boolean;
          acceptingRequests?: boolean;
          heartbeatTtlSecs?: number;
          lastHeartbeatUnix?: number | null;
          message?: string | null;
        };
      };
    }
  | { ok: false; error?: string; status?: number };

function formatUnix(unix: number): string {
  return new Date(unix * 1000).toLocaleString();
}

function isInFlight(status: tenantApi.ManagedMcpDeploymentStatus): boolean {
  return status === "pending" || status === "reconciling";
}

function statusTone(status: tenantApi.ManagedMcpDeploymentStatus): Tone {
  if (status === "ready") return "ok";
  if (status === "failed") return "danger";
  if (status === "reconciling") return "warn";
  return "neutral";
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
      if (!res.ok) {
        throw new Error(`Failed to load gateway status (HTTP ${res.status}).`);
      }
      return (await res.json()) as GatewayStatusResponse;
    },
  });
  const managedMcpSupported =
    gatewayStatusQuery.data?.ok &&
    gatewayStatusQuery.data.status.managedMcp?.acceptingRequests === true;
  const managedMcpStatus = gatewayStatusQuery.data?.ok
    ? gatewayStatusQuery.data.status.managedMcp
    : undefined;
  const managedMcpUnavailableMessage =
    managedMcpStatus?.message ??
    (managedMcpStatus
      ? "Managed deployment backend is not ready."
      : "Gateway status does not expose managed deployment readiness.");

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
        throw new Error(managedMcpUnavailableMessage);
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
          <Callout tone="warn" size="md">
            Managed deployment is unavailable. Backend mode:{" "}
            <span className="font-mono">{managedMcpStatus?.backendMode ?? "unknown"}</span>
            {managedMcpStatus ? (
              <> ({managedMcpStatus.reconcilerHealthy ? "healthy" : "unhealthy"}).</>
            ) : (
              "."
            )}{" "}
            Current topology:{" "}
            <span className="font-mono">
              {gatewayStatusQuery.data?.ok
                ? (gatewayStatusQuery.data.status.topology ?? "unknown")
                : "unavailable"}
            </span>
            . {managedMcpUnavailableMessage}
          </Callout>
        )}

        <Callout tone="info" size="md">
          <div className="flex items-start gap-3">
            <InfoIcon className="mt-0.5 size-5 shrink-0 text-info" />
            <p>
              Managed deployment only registers the source/upstream in Gateway. It does{" "}
              <strong>not</strong> auto-attach that source to any profile.
            </p>
          </div>
        </Callout>

        <SectionCard
          title="Available deployables"
          subtitle="Catalog is controlled by admins. Only enabled entries appear here."
        >
          {deployablesQuery.isPending && <SkeletonRows rows={2} />}
          {deployablesQuery.error && (
            <Callout tone="danger" size="md">
              {deployablesQuery.error instanceof Error
                ? deployablesQuery.error.message
                : "Failed to load deployables"}
            </Callout>
          )}
          {deploymentsQuery.error && (
            <Callout tone="danger" size="md">
              {deploymentsQuery.error instanceof Error
                ? deploymentsQuery.error.message
                : "Failed to load deployment status"}
            </Callout>
          )}
          {!deployablesQuery.isPending && !deployablesQuery.error && deployables.length === 0 && (
            <div className="text-sm text-faint">
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
                  !!latest && draftReplicasValid && parsedDraftReplicas !== latest.desiredReplicas;

                return (
                  <article
                    key={deployable.id}
                    className="flex items-start justify-between gap-4 rounded-lg border border-edge bg-well p-4"
                  >
                    <div className="min-w-0">
                      <h3 className="text-base font-semibold text-fg">{deployable.displayName}</h3>
                      {deployable.description ? (
                        <p className="mt-1 text-sm text-muted">{deployable.description}</p>
                      ) : null}
                      {latest ? (
                        <div className="mt-2 flex items-center gap-2 text-xs">
                          <Badge tone={statusTone(latest.status)} dot>
                            {latest.status}
                          </Badge>
                          <span className="text-faint">
                            Updated {formatUnix(latest.updatedAtUnix)}
                          </span>
                        </div>
                      ) : (
                        <div className="mt-2 text-xs text-faint">Not deployed yet.</div>
                      )}
                      {latest ? (
                        <div className="mt-1 text-xs text-faint">
                          Desired state: {latest.desiredEnabled ? "enabled" : "disabled"} · replicas{" "}
                          {latest.desiredReplicas}
                        </div>
                      ) : null}
                      {latest?.status === "failed" && latest.message ? (
                        <p className="mt-2 break-words text-xs text-danger">{latest.message}</p>
                      ) : null}
                      <div className="mt-2 space-y-1 text-xs text-faint">
                        <p>
                          ID: <span className="font-mono">{deployable.id}</span>
                        </p>
                        <p>
                          Image: <span className="break-all font-mono">{deployable.image}</span>
                        </p>
                      </div>
                    </div>
                    {isReady && latest ? (
                      <div className="w-[220px] shrink-0 space-y-2">
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
                        <div className="space-y-2 rounded-lg border border-edge bg-raised p-3">
                          <Input
                            label="Replicas"
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
        </SectionCard>
      </PageContent>
    </AppShell>
  );
}
