"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { Button, ConfirmModal, Input, Modal, ModalActions } from "@/components/ui";
import { qk } from "@/src/lib/queryKeys";
import * as tenantApi from "@/src/lib/tenantApi";
import { useToastStore } from "@/src/lib/toast-store";
import { useDisclosure } from "@/src/lib/useDisclosure";
import {
  BoltIcon,
  ChevronRightIcon,
  DatabaseIcon,
  DocumentIcon,
  GlobeIconSimple,
  PlusIcon,
  ServerIconStack,
  ServerIconWireframe,
  SourcesIcon,
  TrashIcon,
} from "@/components/icons";

type ToolSourceSummary = { id: string; type: string; enabled: boolean };

const EMPTY_UPSTREAMS: tenantApi.Upstream[] = [];
const EMPTY_SOURCES: ToolSourceSummary[] = [];

type CreateKind = "tool_http";
type GatewayStatusResponse =
  | {
      ok: true;
      status: {
        topology?: string;
      };
    }
  | { ok: false; error?: string; status?: number };

export default function SourcesPage() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const pushToast = useToastStore((s) => s.push);

  const addPicker = useDisclosure(false);
  const [createKind, setCreateKind] = useState<CreateKind | null>(null);
  const [deletingUpstreamId, setDeletingUpstreamId] = useState<string | null>(null);
  const [deletingToolSourceId, setDeletingToolSourceId] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<{
    kind: "upstream" | "toolSource";
    id: string;
  } | null>(null);

  const upstreamsQuery = useQuery({
    queryKey: qk.upstreams(),
    queryFn: tenantApi.listUpstreams,
  });
  const upstreams = upstreamsQuery.data?.upstreams ?? EMPTY_UPSTREAMS;

  const sourcesQuery = useQuery({
    queryKey: qk.toolSources(),
    queryFn: tenantApi.listToolSources,
  });
  const sources: ToolSourceSummary[] = (sourcesQuery.data?.sources ??
    EMPTY_SOURCES) as ToolSourceSummary[];

  const gatewayStatusQuery = useQuery({
    queryKey: qk.gatewayStatus(),
    queryFn: async () => {
      const res = await fetch("/api/gateway/status", { cache: "no-store" });
      return (await res.json()) as GatewayStatusResponse;
    },
  });
  const managedMcpSupported =
    gatewayStatusQuery.data?.ok && gatewayStatusQuery.data.status.topology === "operator-oss";
  const managedMcpReason = gatewayStatusQuery.isPending
    ? "Checking Gateway topology…"
    : managedMcpSupported
      ? null
      : gatewayStatusQuery.data?.ok
        ? `Requires operator topology (current: ${gatewayStatusQuery.data.status.topology ?? "unknown"}).`
        : "Gateway status unavailable.";

  const profilesQuery = useQuery({
    queryKey: qk.profiles(),
    queryFn: tenantApi.listProfiles,
  });

  const usedCounts = useMemo(() => {
    const upstreamsUsed: Record<string, number> = {};
    const toolSourcesUsed: Record<string, number> = {};
    const profiles = profilesQuery.data?.profiles ?? [];
    for (const p of profiles) {
      for (const u of p.upstreams ?? []) upstreamsUsed[u] = (upstreamsUsed[u] ?? 0) + 1;
      for (const s of p.sources ?? []) toolSourcesUsed[s] = (toolSourcesUsed[s] ?? 0) + 1;
    }
    return { upstreamsUsed, toolSourcesUsed };
  }, [profilesQuery.data]);

  const existingNamesLower = useMemo(() => {
    return new Set(
      [...upstreams.map((u) => u.id), ...sources.map((s) => s.id)].map((s) => s.toLowerCase()),
    );
  }, [upstreams, sources]);

  const deleteUpstreamMutation = useMutation({
    mutationFn: (id: string) => tenantApi.deleteUpstream(id),
    onMutate: async (id) => {
      setDeletingUpstreamId(id);
      await queryClient.cancelQueries({ queryKey: qk.upstreams() });
      const prev = queryClient.getQueryData<tenantApi.ListUpstreamsResponse>(qk.upstreams());
      queryClient.setQueryData(
        qk.upstreams(),
        (old: tenantApi.ListUpstreamsResponse | undefined) => {
          if (!old) return old;
          return { ...old, upstreams: old.upstreams.filter((u) => u.id !== id) };
        },
      );
      return { prev };
    },
    onSuccess: async () => {
      pushToast({ variant: "success", message: "Upstream deleted" });
    },
    onError: (e, _id, ctx) => {
      if (ctx?.prev) queryClient.setQueryData(qk.upstreams(), ctx.prev);
      pushToast({
        variant: "error",
        message: e instanceof Error ? e.message : "Failed to delete upstream",
      });
    },
    onSettled: async () => {
      setDeletingUpstreamId(null);
      await queryClient.invalidateQueries({ queryKey: qk.upstreams() });
      await queryClient.invalidateQueries({ queryKey: qk.profiles() });
    },
  });

  const deleteToolSourceMutation = useMutation({
    mutationFn: (id: string) => tenantApi.deleteToolSource(id),
    onMutate: async (id) => {
      setDeletingToolSourceId(id);
      await queryClient.cancelQueries({ queryKey: qk.toolSources() });
      const prev = queryClient.getQueryData<{ sources: ToolSourceSummary[] }>(qk.toolSources());
      queryClient.setQueryData(
        qk.toolSources(),
        (old: { sources: ToolSourceSummary[] } | undefined) => {
          if (!old) return old;
          return { ...old, sources: old.sources.filter((s) => s.id !== id) };
        },
      );
      return { prev };
    },
    onSuccess: async () => {
      pushToast({ variant: "success", message: "Tool source deleted" });
    },
    onError: (e, _id, ctx) => {
      if (ctx?.prev) queryClient.setQueryData(qk.toolSources(), ctx.prev);
      pushToast({
        variant: "error",
        message: e instanceof Error ? e.message : "Failed to delete tool source",
      });
    },
    onSettled: async () => {
      setDeletingToolSourceId(null);
      await queryClient.invalidateQueries({ queryKey: qk.toolSources() });
      await queryClient.invalidateQueries({ queryKey: qk.profiles() });
    },
  });

  const isDeletePending =
    (deleteTarget?.kind === "upstream" &&
      deleteUpstreamMutation.isPending &&
      deletingUpstreamId === deleteTarget.id) ||
    (deleteTarget?.kind === "toolSource" &&
      deleteToolSourceMutation.isPending &&
      deletingToolSourceId === deleteTarget.id);

  return (
    <AppShell>
      <PageHeader
        title="Sources"
        description="Upstreams (MCP servers) and tool sources (HTTP/OpenAPI) for profiles"
        actions={
          <button
            onClick={addPicker.onOpen}
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-b from-violet-500 to-violet-600 text-white font-medium text-sm shadow-lg shadow-violet-500/25 hover:from-violet-400 hover:to-violet-500 transition-all duration-150"
          >
            <PlusIcon className="w-4 h-4" />
            Add Source
          </button>
        }
      />

      <PageContent className="space-y-6">
        {/* Upstreams */}
        <section className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 overflow-hidden">
          <div className="px-5 py-4 border-b border-zinc-800/60">
            <h2 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
              <ServerIconWireframe className="w-5 h-5 text-violet-400" />
              Upstreams
            </h2>
            <p className="mt-1 text-xs text-zinc-500">
              MCP servers registered in Gateway. Profiles attach upstreams by name.
            </p>
          </div>
          <div className="p-5">
            {upstreamsQuery.isPending && <div className="text-sm text-zinc-400">Loading…</div>}
            {upstreamsQuery.error && (
              <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-200">
                {upstreamsQuery.error instanceof Error
                  ? upstreamsQuery.error.message
                  : "Failed to load upstreams"}
              </div>
            )}
            {!upstreamsQuery.isPending && !upstreamsQuery.error && upstreams.length === 0 && (
              <div className="text-sm text-zinc-500">No upstreams yet.</div>
            )}
            {!upstreamsQuery.isPending && !upstreamsQuery.error && upstreams.length > 0 && (
              <div className="space-y-3">
                {upstreams.map((u) => (
                  <Link
                    key={`${u.owner}:${u.id}`}
                    href={`/sources/upstreams/${encodeURIComponent(u.id)}`}
                    className="block rounded-xl border border-zinc-800/60 bg-zinc-950/30 p-5 hover:border-zinc-700/80 hover:bg-zinc-900/40 transition-all duration-150 group"
                  >
                    <div className="flex items-center justify-between gap-4">
                      <div className="min-w-0">
                        <div className="flex items-center gap-3">
                          <h3 className="text-base font-semibold text-zinc-100 font-mono">
                            {u.id}
                          </h3>
                          <Badge tone={u.owner === "tenant" ? "violet" : "zinc"}>
                            {u.owner === "tenant" ? "tenant" : "global"}
                          </Badge>
                          <Badge tone={u.enabled ? "emerald" : "zinc"}>
                            {u.enabled ? "enabled" : "disabled"}
                          </Badge>
                        </div>
                        <div className="mt-2 space-y-1 text-xs text-zinc-400">
                          {u.endpoints.map((ep, idx) => (
                            <div key={ep.id} className="flex items-center gap-2">
                              {u.endpoints.length > 1 ? (
                                <span className="text-zinc-500">Endpoint {idx + 1}</span>
                              ) : (
                                <span className="text-zinc-500">Endpoint</span>
                              )}
                              <span className="truncate">{ep.url}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        {u.owner === "tenant" && (
                          <button
                            onClick={(e) => {
                              e.preventDefault();
                              e.stopPropagation();
                              setDeleteTarget({ kind: "upstream", id: u.id });
                            }}
                            disabled={
                              deleteUpstreamMutation.isPending && deletingUpstreamId === u.id
                            }
                            className="inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-zinc-300 hover:text-white hover:bg-zinc-800/60 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            <TrashIcon className="w-4 h-4" />
                            Delete
                          </button>
                        )}
                        <ChevronRightIcon className="w-5 h-5 text-zinc-600 group-hover:text-zinc-400 transition-colors shrink-0" />
                      </div>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </div>
        </section>

        {/* Tool Sources */}
        <section className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 overflow-hidden">
          <div className="px-5 py-4 border-b border-zinc-800/60">
            <h2 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
              <SourcesIcon className="w-5 h-5 text-emerald-400" />
              Tool Sources
            </h2>
            <p className="mt-1 text-xs text-zinc-500">
              Gateway-local HTTP/OpenAPI sources. Profiles attach tool sources by name.
            </p>
          </div>
          <div className="p-5">
            {sourcesQuery.isPending ? (
              <div className="text-sm text-zinc-400">Loading…</div>
            ) : sourcesQuery.error ? (
              <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-200">
                {sourcesQuery.error instanceof Error
                  ? sourcesQuery.error.message
                  : "Failed to load tool sources"}
              </div>
            ) : sources.length === 0 ? (
              <div className="text-sm text-zinc-500">No tool sources yet.</div>
            ) : (
              <div className="space-y-3">
                {sources.map((source) => (
                  <Link
                    key={source.id}
                    href={`/sources/tool-sources/${source.id}`}
                    className="block rounded-xl border border-zinc-800/60 bg-zinc-950/30 p-5 hover:border-zinc-700/80 hover:bg-zinc-900/40 transition-all duration-150 group"
                  >
                    <div className="flex items-center justify-between gap-4">
                      <div className="flex items-center gap-4">
                        <SourceTypeIcon type={source.type} />
                        <div>
                          <div className="flex items-center gap-3">
                            <h3 className="text-base font-semibold text-zinc-100 group-hover:text-white transition-colors font-mono">
                              {source.id}
                            </h3>
                            <TypeBadge type={source.type} />
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            setDeleteTarget({ kind: "toolSource", id: source.id });
                          }}
                          className="inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-zinc-300 hover:text-white hover:bg-zinc-800/60 transition-all"
                          title="Delete tool source"
                        >
                          <TrashIcon className="w-4 h-4" />
                          Delete
                        </button>
                        <ChevronRightIcon className="w-5 h-5 text-zinc-600 group-hover:text-zinc-400 transition-colors shrink-0" />
                      </div>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </div>
        </section>
      </PageContent>

      <ConfirmModal
        open={!!deleteTarget}
        onClose={() => {
          if (!isDeletePending) setDeleteTarget(null);
        }}
        onConfirm={() => {
          if (!deleteTarget) return;
          if (deleteTarget.kind === "upstream") {
            deleteUpstreamMutation.mutate(deleteTarget.id, {
              onSettled: () => setDeleteTarget(null),
            });
          } else {
            deleteToolSourceMutation.mutate(deleteTarget.id, {
              onSettled: () => setDeleteTarget(null),
            });
          }
        }}
        title={
          deleteTarget?.kind === "upstream"
            ? `Delete upstream "${deleteTarget.id}"?`
            : deleteTarget
              ? `Delete tool source "${deleteTarget.id}"?`
              : "Delete source?"
        }
        description={
          deleteTarget?.kind === "upstream"
            ? (() => {
                const used = usedCounts.upstreamsUsed[deleteTarget.id] ?? 0;
                return used > 0
                  ? `This will remove the upstream from ${used} profile(s) (including disabled profiles) and permanently delete it.`
                  : "This upstream is not referenced by any profiles. It will be permanently deleted.";
              })()
            : deleteTarget
              ? (() => {
                  const used = usedCounts.toolSourcesUsed[deleteTarget.id] ?? 0;
                  return used > 0
                    ? `This will remove the tool source from ${used} profile(s) (including disabled profiles) and permanently delete it.`
                    : "This tool source is not referenced by any profiles. It will be permanently deleted.";
                })()
              : "This source will be permanently deleted."
        }
        confirmLabel="Delete"
        danger
        loading={isDeletePending}
        requireText={deleteTarget?.id}
      />

      {addPicker.open && (
        <Modal
          open
          onClose={addPicker.onClose}
          title="Add source"
          description="Choose what to add."
          size="lg"
        >
          <div className="grid grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => {
                addPicker.onClose();
                setCreateKind("tool_http");
              }}
              className="p-4 rounded-xl border border-zinc-800 bg-zinc-950/60 hover:border-blue-500/30 hover:bg-blue-500/5 transition-all"
            >
              <GlobeIconSimple className="w-8 h-8 text-blue-400 mx-auto mb-2" />
              <div className="text-sm font-medium text-zinc-200 inline-flex items-center gap-2 justify-center w-full">
                HTTP DSL
                <span className="px-1.5 py-0.5 rounded-md text-[10px] font-semibold bg-violet-500/10 text-violet-300 border border-violet-500/20">
                  Beta
                </span>
              </div>
              <div className="text-xs text-zinc-500 mt-1">
                JSON-only editor for now (no validation yet)
              </div>
            </button>
            <button
              type="button"
              onClick={() => {
                addPicker.onClose();
                router.push("/sources/new/openapi");
              }}
              className="p-4 rounded-xl border border-zinc-800 bg-zinc-950/60 hover:border-green-500/30 hover:bg-green-500/5 transition-all"
            >
              <DocumentIcon className="w-8 h-8 text-green-400 mx-auto mb-2" />
              <div className="text-sm font-medium text-zinc-200">OpenAPI</div>
              <div className="text-xs text-zinc-500 mt-1">Generate tools from spec</div>
            </button>
            <button
              type="button"
              onClick={() => {
                addPicker.onClose();
                router.push("/sources/new/upstream?kind=mcp");
              }}
              className="p-4 rounded-xl border border-zinc-800 bg-zinc-950/60 hover:border-violet-500/30 hover:bg-violet-500/5 transition-all"
            >
              <ServerIconWireframe className="w-8 h-8 text-violet-400 mx-auto mb-2" />
              <div className="text-sm font-medium text-zinc-200">Remote MCP</div>
              <div className="text-xs text-zinc-500 mt-1">Connect an existing MCP endpoint</div>
            </button>
            <button
              type="button"
              onClick={() => {
                if (!managedMcpSupported) return;
                addPicker.onClose();
                router.push("/sources/new/managed-mcp");
              }}
              disabled={!managedMcpSupported}
              className={`p-4 rounded-xl border border-zinc-800 bg-zinc-950/60 transition-all ${
                managedMcpSupported
                  ? "hover:border-indigo-500/30 hover:bg-indigo-500/5"
                  : "opacity-60 cursor-not-allowed"
              }`}
            >
              <ServerIconStack className="w-8 h-8 text-indigo-400 mx-auto mb-2" />
              <div className="text-sm font-medium text-zinc-200">Managed MCP</div>
              <div className="text-xs text-zinc-500 mt-1">
                {managedMcpReason ?? "Deploy from approved catalog"}
              </div>
            </button>
            <button
              type="button"
              onClick={() => {
                addPicker.onClose();
                router.push("/sources/new/upstream?kind=adapter");
              }}
              className="p-4 rounded-xl border border-zinc-800 bg-zinc-950/60 hover:border-amber-500/30 hover:bg-amber-500/5 transition-all"
            >
              <BoltIcon className="w-8 h-8 text-amber-400 mx-auto mb-2" />
              <div className="text-sm font-medium text-zinc-200">Adapter</div>
              <div className="text-xs text-zinc-500 mt-1">unrelated.ai MCP adapter</div>
            </button>
          </div>
          <ModalActions>
            <Button type="button" variant="ghost" onClick={addPicker.onClose}>
              Cancel
            </Button>
          </ModalActions>
        </Modal>
      )}

      {createKind === "tool_http" && (
        <CreateToolSourceModal
          type="http"
          existingNamesLower={existingNamesLower}
          onClose={() => setCreateKind(null)}
          onCreated={(id) => {
            setCreateKind(null);
            router.push(`/sources/tool-sources/${id}`);
          }}
        />
      )}
      {/* OpenAPI creation uses the full-page wizard now. */}
    </AppShell>
  );
}

const createToolSourceSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, "Name is required")
    .regex(/^[A-Za-z0-9_-]+$/, "Allowed: letters, digits, underscore, dash"),
});

type CreateToolSourceForm = z.infer<typeof createToolSourceSchema>;

function CreateToolSourceModal({
  type,
  existingNamesLower,
  onClose,
  onCreated,
}: {
  type: "http" | "openapi";
  existingNamesLower: ReadonlySet<string>;
  onClose: () => void;
  onCreated: (id: string) => void;
}) {
  const queryClient = useQueryClient();
  const pushToast = useToastStore((s) => s.push);
  const {
    register,
    handleSubmit,
    setError,
    formState: { errors, isSubmitting },
  } = useForm<CreateToolSourceForm>({
    resolver: zodResolver(createToolSourceSchema),
    defaultValues: { name: "" },
  });

  const createMutation = useMutation({
    mutationFn: async (values: CreateToolSourceForm) => {
      const id = values.name.trim();
      const minimal =
        type === "http"
          ? { type: "http", enabled: true, baseUrl: "https://example.com", tools: {} }
          : { type: "openapi", enabled: true, spec: "https://example.com/openapi.json" };
      await tenantApi.putToolSource(id, JSON.stringify(minimal));
      return id;
    },
    onSuccess: async (id) => {
      await queryClient.invalidateQueries({ queryKey: qk.toolSources() });
      pushToast({ variant: "success", message: "Tool source created" });
      onCreated(id);
    },
    onError: (e) => {
      pushToast({
        variant: "error",
        message: e instanceof Error ? e.message : "Failed to create tool source",
      });
    },
  });

  return (
    <Modal
      open
      onClose={onClose}
      title={type === "http" ? "Add HTTP DSL source" : "Add OpenAPI source"}
      description={
        type === "http"
          ? "Create a tenant-owned HTTP DSL tool source (executed locally by the Gateway)."
          : "Create a tenant-owned OpenAPI tool source (executed locally by the Gateway)."
      }
      size="lg"
    >
      <form
        className="space-y-4"
        onSubmit={handleSubmit((v) => {
          const name = v.name.trim();
          if (existingNamesLower.has(name.toLowerCase())) {
            setError("name", {
              type: "validate",
              message: "Name already exists (names are case-insensitive). Choose a different one.",
            });
            return;
          }
          createMutation.mutate({ ...v, name });
        })}
      >
        <Input
          label="Name"
          placeholder={type === "http" ? "http1" : "openapi1"}
          hint="Unique (case-insensitive). Used when attaching to profiles."
          {...register("name")}
          error={errors.name?.message}
          className="font-mono"
        />
        <p className="text-xs text-zinc-500">
          Allowed characters: letters, digits, underscore, dash.
        </p>

        <ModalActions>
          <Button type="button" variant="ghost" onClick={onClose} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button type="submit" loading={createMutation.isPending}>
            Create
          </Button>
        </ModalActions>
      </form>
    </Modal>
  );
}

function TypeBadge({ type }: { type: string }) {
  const tone =
    type === "http"
      ? "bg-blue-500/10 text-blue-400 border border-blue-500/20"
      : type === "openapi"
        ? "bg-green-500/10 text-green-400 border border-green-500/20"
        : "bg-zinc-500/10 text-zinc-400 border border-zinc-500/20";
  return <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${tone}`}>{type}</span>;
}

function SourceTypeIcon({ type }: { type: string }) {
  const bg =
    type === "http" ? "bg-blue-500/10" : type === "openapi" ? "bg-green-500/10" : "bg-zinc-500/10";
  const icon =
    type === "http" ? (
      <GlobeIconSimple className="w-5 h-5 text-blue-400" />
    ) : type === "openapi" ? (
      <DocumentIcon className="w-5 h-5 text-green-400" />
    ) : (
      <DatabaseIcon className="w-5 h-5 text-zinc-400" />
    );
  return (
    <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${bg}`}>{icon}</div>
  );
}

function Badge({
  tone,
  children,
}: {
  tone: "violet" | "emerald" | "zinc";
  children: React.ReactNode;
}) {
  const cls =
    tone === "violet"
      ? "bg-violet-500/10 text-violet-400 border border-violet-500/20"
      : tone === "emerald"
        ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
        : "bg-zinc-500/10 text-zinc-400 border border-zinc-500/20";
  return <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${cls}`}>{children}</span>;
}
