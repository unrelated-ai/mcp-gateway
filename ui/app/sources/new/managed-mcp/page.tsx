"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import { Button } from "@/components/ui";
import { CheckCircleIcon, InfoIcon, ServerIconWireframe } from "@/components/icons";
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

function statusTone(status: tenantApi.ManagedMcpDeploymentStatus): string {
  if (status === "ready") return "bg-emerald-500/10 text-emerald-300 border-emerald-500/20";
  if (status === "failed") return "bg-red-500/10 text-red-300 border-red-500/20";
  if (status === "reconciling") return "bg-amber-500/10 text-amber-300 border-amber-500/20";
  return "bg-zinc-500/10 text-zinc-300 border-zinc-500/20";
}

export default function ManagedMcpDeployPage() {
  const queryClient = useQueryClient();
  const pushToast = useToastStore((s) => s.push);
  const [activeRequestId, setActiveRequestId] = useState<string | null>(null);
  const [deployingId, setDeployingId] = useState<string | null>(null);
  const notifiedRequestRef = useRef<string | null>(null);

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

  const requestQuery = useQuery({
    queryKey: qk.managedMcpDeployment(activeRequestId ?? "none"),
    queryFn: async () => {
      if (!activeRequestId) throw new Error("request id is required");
      const response = await tenantApi.getManagedMcpDeploymentRequest(activeRequestId);
      return response.request;
    },
    enabled: !!activeRequestId,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      if (status === "ready" || status === "failed") return false;
      return 2000;
    },
  });

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
      notifiedRequestRef.current = null;
    },
    onSuccess: (request) => {
      setActiveRequestId(request.id);
      pushToast({ variant: "success", message: "Deployment requested" });
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

  useEffect(() => {
    const request = requestQuery.data;
    if (!request) return;
    if (request.status !== "ready" && request.status !== "failed") return;
    if (notifiedRequestRef.current === request.id) return;
    notifiedRequestRef.current = request.id;

    if (request.status === "ready") {
      void queryClient.invalidateQueries({ queryKey: qk.upstreams() });
      pushToast({ variant: "success", message: "Managed MCP is ready" });
      return;
    }

    pushToast({
      variant: "error",
      message: request.message?.trim() || "Managed MCP deployment failed",
    });
  }, [pushToast, queryClient, requestQuery.data]);

  const deployables = deployablesQuery.data?.deployables ?? [];

  return (
    <AppShell>
      <PageHeader
        title="Deploy managed MCP"
        description="Pick an approved deployable and request a cluster deployment. This creates a source in Gateway only; profile attachment remains manual."
        breadcrumb={[{ label: "Sources", href: "/sources" }, { label: "Managed MCP" }]}
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

        {activeRequestId && (
          <section className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 p-5 space-y-3">
            <div className="flex items-center justify-between gap-3">
              <h2 className="text-sm font-semibold text-zinc-100">Latest deployment request</h2>
              {requestQuery.data ? (
                <span
                  className={`px-2 py-1 rounded-md border text-xs font-medium ${statusTone(requestQuery.data.status)}`}
                >
                  {requestQuery.data.status}
                </span>
              ) : null}
            </div>
            {requestQuery.isPending && (
              <p className="text-sm text-zinc-400">Loading request status…</p>
            )}
            {requestQuery.error && (
              <p className="text-sm text-red-300">
                {requestQuery.error instanceof Error
                  ? requestQuery.error.message
                  : "Failed to load deployment status"}
              </p>
            )}
            {requestQuery.data && (
              <div className="space-y-2 text-sm text-zinc-300">
                <p>
                  Request: <span className="font-mono text-zinc-100">{requestQuery.data.id}</span>
                </p>
                <p>
                  Deployable:{" "}
                  <span className="font-mono text-zinc-100">{requestQuery.data.deployableId}</span>
                </p>
                <p>Updated: {formatUnix(requestQuery.data.updatedAtUnix)}</p>
                {requestQuery.data.message ? (
                  <p className="text-zinc-400">{requestQuery.data.message}</p>
                ) : null}
                {requestQuery.data.status === "ready" && requestQuery.data.upstreamId ? (
                  <div className="pt-1">
                    <Link
                      href={`/sources/upstreams/${encodeURIComponent(requestQuery.data.upstreamId)}`}
                      className="inline-flex items-center gap-2 px-3 py-2 rounded-lg border border-emerald-500/20 bg-emerald-500/10 text-emerald-200 hover:bg-emerald-500/20 transition-colors"
                    >
                      <CheckCircleIcon className="w-4 h-4" />
                      Open upstream
                    </Link>
                  </div>
                ) : null}
              </div>
            )}
          </section>
        )}

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
            {!deployablesQuery.isPending && !deployablesQuery.error && deployables.length === 0 && (
              <div className="text-sm text-zinc-500">
                No deployables are available right now. Ask an admin to publish entries.
              </div>
            )}
            {!deployablesQuery.isPending && !deployablesQuery.error && deployables.length > 0 && (
              <div className="space-y-3">
                {deployables.map((deployable) => (
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
                      <div className="mt-2 space-y-1 text-xs text-zinc-500">
                        <p>
                          ID: <span className="font-mono">{deployable.id}</span>
                        </p>
                        <p>
                          Image: <span className="font-mono break-all">{deployable.image}</span>
                        </p>
                        <p>
                          Endpoint template:{" "}
                          <span className="font-mono break-all">
                            {deployable.defaultUpstreamUrl}
                          </span>
                        </p>
                      </div>
                    </div>
                    <Button
                      type="button"
                      onClick={() => deployMutation.mutate(deployable.id)}
                      loading={deployMutation.isPending && deployingId === deployable.id}
                      disabled={deployMutation.isPending || !managedMcpSupported}
                    >
                      Deploy
                    </Button>
                  </article>
                ))}
              </div>
            )}
          </div>
        </section>
      </PageContent>
    </AppShell>
  );
}
