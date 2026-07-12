"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import {
  Badge,
  Button,
  Callout,
  ConfirmModal,
  EmptyState,
  Input,
  Modal,
  ModalActions,
  SectionCard,
  SkeletonRows,
  StatusBadge,
  type Tone,
} from "@/components/ui";
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
  ServerIconWireframe,
  SourcesIcon,
  TrashIcon,
} from "@/components/icons";

type ToolSourceSummary = { id: string; type: string; enabled: boolean };

const EMPTY_UPSTREAMS: tenantApi.Upstream[] = [];
const EMPTY_SOURCES: ToolSourceSummary[] = [];

type CreateKind = "tool_http";

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
  const managedDeploymentsQuery = useQuery({
    queryKey: qk.managedMcpDeployments(),
    queryFn: tenantApi.listManagedMcpDeploymentRequests,
  });
  const managedDeployablesQuery = useQuery({
    queryKey: qk.managedMcpDeployables(),
    queryFn: tenantApi.listManagedMcpDeployables,
  });
  const managedDisplayByUpstreamId = useMemo(() => {
    const deployableById = new Map(
      (managedDeployablesQuery.data?.deployables ?? []).map((deployable) => [
        deployable.id,
        deployable,
      ]),
    );
    const latestByUpstreamId = new Map<string, tenantApi.ManagedMcpDeploymentRequest>();
    for (const request of managedDeploymentsQuery.data?.requests ?? []) {
      const upstreamId = request.upstreamId;
      if (!upstreamId) continue;
      const current = latestByUpstreamId.get(upstreamId);
      if (
        !current ||
        request.updatedAtUnix > current.updatedAtUnix ||
        (request.updatedAtUnix === current.updatedAtUnix &&
          request.createdAtUnix > current.createdAtUnix)
      ) {
        latestByUpstreamId.set(upstreamId, request);
      }
    }
    const result = new Map<
      string,
      {
        displayName: string;
        deployableId: string;
      }
    >();
    for (const [upstreamId, request] of latestByUpstreamId) {
      const deployable = deployableById.get(request.deployableId);
      result.set(upstreamId, {
        displayName: deployable?.displayName ?? request.deployableId,
        deployableId: request.deployableId,
      });
    }
    return result;
  }, [managedDeploymentsQuery.data?.requests, managedDeployablesQuery.data?.deployables]);

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
          <Button onClick={addPicker.onOpen}>
            <PlusIcon className="size-4" />
            Add source
          </Button>
        }
      />

      <PageContent className="space-y-6">
        {/* Upstreams */}
        <SectionCard
          title="Upstreams"
          subtitle="MCP servers registered in Gateway. Profiles attach upstreams by name."
        >
          {upstreamsQuery.isPending && <SkeletonRows rows={2} />}
          {upstreamsQuery.error && (
            <Callout tone="danger" title="Failed to load upstreams" size="md">
              {upstreamsQuery.error instanceof Error
                ? upstreamsQuery.error.message
                : "Unknown error"}
            </Callout>
          )}
          {!upstreamsQuery.isPending && !upstreamsQuery.error && upstreams.length === 0 && (
            <EmptyState
              icon={<ServerIconWireframe className="size-5" />}
              title="No upstreams yet"
              description="Connect a remote MCP server or adapter to attach it to profiles."
              action={{ label: "Add source", onClick: addPicker.onOpen }}
            />
          )}
          {!upstreamsQuery.isPending && !upstreamsQuery.error && upstreams.length > 0 && (
            <div className="space-y-3">
              {upstreams.map((u) => {
                const managedInfo = managedDisplayByUpstreamId.get(u.id);
                return (
                  // Stretched-link card: the title Link covers the card via
                  // ::after; the delete control sits above it — no nested interactives.
                  <div
                    key={`${u.owner}:${u.id}`}
                    className="group relative rounded-lg border border-edge bg-well p-5 transition-colors duration-150 hover:border-edge-strong"
                  >
                    <div className="flex items-center justify-between gap-4">
                      <div className="min-w-0">
                        <div className="flex items-center gap-3">
                          <Link
                            href={`/sources/upstreams/${encodeURIComponent(u.id)}`}
                            className={`text-base font-semibold text-fg after:absolute after:inset-0 after:rounded-lg focus-visible:outline-none focus-visible:after:ring-2 focus-visible:after:ring-accent ${managedInfo ? "" : "font-mono"}`}
                          >
                            {managedInfo?.displayName ?? u.id}
                          </Link>
                          <Badge tone={u.owner === "tenant" ? "accent" : "neutral"}>
                            {u.owner === "tenant" ? "tenant" : "global"}
                          </Badge>
                          <StatusBadge enabled={u.enabled} />
                        </div>
                        {managedInfo ? (
                          <div className="mt-1 text-xs text-faint">
                            Deployable ID:{" "}
                            <span className="font-mono text-muted">{managedInfo.deployableId}</span>{" "}
                            · Upstream ID: <span className="font-mono text-muted">{u.id}</span>
                          </div>
                        ) : null}
                        <div className="mt-2 space-y-1 text-xs text-muted">
                          {u.endpoints.map((ep, idx) => (
                            <div key={ep.id} className="flex items-center gap-2">
                              {u.endpoints.length > 1 ? (
                                <span className="text-faint">Endpoint {idx + 1}</span>
                              ) : (
                                <span className="text-faint">Endpoint</span>
                              )}
                              <span className="truncate font-mono">{ep.url}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      <div className="flex shrink-0 items-center gap-2">
                        {u.owner === "tenant" && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="relative z-10"
                            onClick={() => setDeleteTarget({ kind: "upstream", id: u.id })}
                            disabled={
                              deleteUpstreamMutation.isPending && deletingUpstreamId === u.id
                            }
                          >
                            <TrashIcon className="size-4" />
                            Delete
                          </Button>
                        )}
                        <ChevronRightIcon className="size-5 shrink-0 text-faint transition-colors group-hover:text-muted" />
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </SectionCard>

        {/* Tool sources */}
        <SectionCard
          title="Tool sources"
          subtitle="Gateway-local HTTP/OpenAPI sources. Profiles attach tool sources by name."
        >
          {sourcesQuery.isPending ? (
            <SkeletonRows rows={2} />
          ) : sourcesQuery.error ? (
            <Callout tone="danger" title="Failed to load tool sources" size="md">
              {sourcesQuery.error instanceof Error ? sourcesQuery.error.message : "Unknown error"}
            </Callout>
          ) : sources.length === 0 ? (
            <EmptyState
              icon={<SourcesIcon className="size-5" />}
              title="No tool sources yet"
              description="Add an HTTP DSL or OpenAPI source to generate tools for profiles."
              action={{ label: "Add source", onClick: addPicker.onOpen }}
            />
          ) : (
            <div className="space-y-3">
              {sources.map((source) => (
                <div
                  key={source.id}
                  className="group relative rounded-lg border border-edge bg-well p-5 transition-colors duration-150 hover:border-edge-strong"
                >
                  <div className="flex items-center justify-between gap-4">
                    <div className="flex min-w-0 items-center gap-4">
                      <SourceTypeIcon type={source.type} />
                      <div className="flex items-center gap-3">
                        <Link
                          href={`/sources/tool-sources/${source.id}`}
                          className="font-mono text-base font-semibold text-fg after:absolute after:inset-0 after:rounded-lg focus-visible:outline-none focus-visible:after:ring-2 focus-visible:after:ring-accent"
                        >
                          {source.id}
                        </Link>
                        <Badge tone={toolSourceTone(source.type)}>{source.type}</Badge>
                      </div>
                    </div>

                    <div className="flex shrink-0 items-center gap-2">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="relative z-10"
                        onClick={() => setDeleteTarget({ kind: "toolSource", id: source.id })}
                      >
                        <TrashIcon className="size-4" />
                        Delete
                      </Button>
                      <ChevronRightIcon className="size-5 shrink-0 text-faint transition-colors group-hover:text-muted" />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </SectionCard>
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
              className="rounded-lg border border-edge bg-well p-4 transition-colors duration-150 hover:border-edge-strong hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              <GlobeIconSimple className="mx-auto mb-2 size-8 text-muted" />
              <div className="inline-flex w-full items-center justify-center gap-2 text-sm font-medium text-fg">
                HTTP DSL
                <Badge tone="accent">Beta</Badge>
              </div>
              <div className="mt-1 text-xs text-faint">
                JSON-only editor for now (no validation yet)
              </div>
            </button>
            <button
              type="button"
              onClick={() => {
                addPicker.onClose();
                router.push("/sources/new/openapi");
              }}
              className="rounded-lg border border-edge bg-well p-4 transition-colors duration-150 hover:border-edge-strong hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              <DocumentIcon className="mx-auto mb-2 size-8 text-muted" />
              <div className="text-sm font-medium text-fg">OpenAPI</div>
              <div className="mt-1 text-xs text-faint">Generate tools from spec</div>
            </button>
            <button
              type="button"
              onClick={() => {
                addPicker.onClose();
                router.push("/sources/new/upstream?kind=mcp");
              }}
              className="rounded-lg border border-edge bg-well p-4 transition-colors duration-150 hover:border-edge-strong hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              <ServerIconWireframe className="mx-auto mb-2 size-8 text-muted" />
              <div className="text-sm font-medium text-fg">Remote MCP</div>
              <div className="mt-1 text-xs text-faint">Connect an existing MCP endpoint</div>
            </button>
            <button
              type="button"
              onClick={() => {
                addPicker.onClose();
                router.push("/sources/new/upstream?kind=adapter");
              }}
              className="rounded-lg border border-edge bg-well p-4 transition-colors duration-150 hover:border-edge-strong hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              <BoltIcon className="mx-auto mb-2 size-8 text-muted" />
              <div className="text-sm font-medium text-fg">Adapter</div>
              <div className="mt-1 text-xs text-faint">unrelated.ai MCP adapter</div>
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
        <p className="text-xs text-faint">Allowed characters: letters, digits, underscore, dash.</p>

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

function toolSourceTone(type: string): Tone {
  return type === "http"
    ? "info"
    : type === "openapi"
      ? "ok"
      : type === "managed"
        ? "accent"
        : "neutral";
}

function SourceTypeIcon({ type }: { type: string }) {
  const icon =
    type === "http" ? (
      <GlobeIconSimple className="size-5 text-info" />
    ) : type === "openapi" ? (
      <DocumentIcon className="size-5 text-ok" />
    ) : type === "managed" ? (
      <DatabaseIcon className="size-5 text-accent" />
    ) : (
      <DatabaseIcon className="size-5 text-muted" />
    );
  return (
    <div className="flex size-9 shrink-0 items-center justify-center rounded-md border border-edge bg-raised">
      {icon}
    </div>
  );
}
