"use client";

import { useMemo, useState } from "react";
import { HttpSourceEditor } from "@/components/sources/http-source-editor";
import { useParams, useRouter } from "next/navigation";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import { useIsMutating, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Button,
  Callout,
  ConfirmModal,
  EmptyState,
  Input,
  QueryParamAuthWarning,
  SectionCard,
  Select,
  SkeletonRows,
  Spinner,
  Tabs,
  Textarea,
  Toggle,
  type TabItem,
} from "@/components/ui";
import { qk } from "@/src/lib/queryKeys";
import { useToastStore } from "@/src/lib/toast-store";
import * as tenantApi from "@/src/lib/tenantApi";
import { useForm, useWatch } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  buildJsonSourceUpdate,
  buildOpenApiSourceUpdate,
  type ToolSourceDetail,
} from "@/src/lib/tool-source-updates";

export default function ToolSourceDetailPage() {
  const params = useParams();
  const router = useRouter();
  const sourceId = String(params.sourceId ?? "");
  const queryClient = useQueryClient();
  const pushToast = useToastStore((s) => s.push);
  const [showDelete, setShowDelete] = useState(false);

  const deleteMutation = useMutation({
    mutationFn: async () => {
      await tenantApi.deleteToolSource(sourceId);
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: qk.toolSources() });
      await queryClient.invalidateQueries({ queryKey: qk.profiles() });
      pushToast({ variant: "success", message: "Tool source deleted" });
      router.push("/sources");
    },
    onError: (e) => {
      pushToast({
        variant: "error",
        message: e instanceof Error ? e.message : "Failed to delete tool source",
      });
    },
  });

  return (
    <AppShell>
      <PageHeader
        title={sourceId || "Tool source"}
        description="Tenant-owned tool source (http/openapi)"
        breadcrumb={[{ label: "Sources", href: "/sources" }, { label: sourceId || "…" }]}
        actions={
          sourceId ? (
            <Button variant="danger" onClick={() => setShowDelete(true)}>
              Delete
            </Button>
          ) : null
        }
      />

      <ToolSourceEditor key={sourceId} sourceId={sourceId} />

      <ConfirmModal
        open={showDelete}
        onClose={() => {
          if (!deleteMutation.isPending) setShowDelete(false);
        }}
        onConfirm={() => deleteMutation.mutate()}
        title={`Delete tool source "${sourceId}"?`}
        description="This will remove it from any profiles that reference it (including disabled profiles) and permanently delete it."
        confirmLabel="Delete"
        danger
        loading={deleteMutation.isPending}
        requireText={sourceId}
      />
    </AppShell>
  );
}

function ToolSourceEditor({ sourceId }: { sourceId: string }) {
  const [activeTab, setActiveTab] = useState<"settings" | "tools">("settings");

  const toolSourceQuery = useQuery({
    queryKey: qk.toolSource(sourceId),
    enabled: !!sourceId,
    queryFn: () => tenantApi.getToolSource(sourceId),
  });

  const detail = toolSourceQuery.data;
  const toolsTabEnabled = detail?.type === "openapi";

  const tabItems: TabItem<"settings" | "tools">[] = toolsTabEnabled
    ? [
        { value: "settings", label: "Settings" },
        { value: "tools", label: "Tools" },
      ]
    : [{ value: "settings", label: "Settings" }];

  return (
    <PageContent width="5xl" className="space-y-6">
      <Tabs items={tabItems} value={activeTab} onChange={setActiveTab} />

      {toolSourceQuery.isPending && <SkeletonRows rows={3} />}
      {toolSourceQuery.error && (
        <Callout tone="danger">
          {toolSourceQuery.error instanceof Error
            ? toolSourceQuery.error.message
            : "Failed to load tool source"}
        </Callout>
      )}

      {!toolSourceQuery.isPending && !toolSourceQuery.error && !detail && (
        <EmptyState title="Tool source not found" />
      )}

      {detail ? (
        <SourceDraft
          key={sourceId}
          sourceId={sourceId}
          initial={detail}
          activeTab={activeTab}
          onSaved={() => setActiveTab("tools")}
        />
      ) : null}
    </PageContent>
  );
}

function SourceDraft({
  sourceId,
  initial,
  activeTab,
  onSaved,
}: {
  sourceId: string;
  initial: ToolSourceDetail;
  activeTab: "settings" | "tools";
  onSaved: () => void;
}) {
  const [source, setSource] = useState(initial);
  const [epoch, setEpoch] = useState(0);
  const [showReload, setShowReload] = useState(false);
  const saving = useIsMutating({ mutationKey: ["toolSourceSave", sourceId] }) > 0;
  const queryClient = useQueryClient();
  const toast = useToastStore((s) => s.push);
  const reload = useMutation({
    mutationFn: () => tenantApi.getToolSource(sourceId),
    onSuccess: (latest) => {
      setSource(latest);
      setEpoch((value) => value + 1);
      queryClient.setQueryData(qk.toolSource(sourceId), latest);
      setShowReload(false);
    },
    onError: (error) => toast({ variant: "error", message: error.message }),
  });
  const saved = async () => {
    await reload.mutateAsync();
    if (source.type === "openapi") onSaved();
  };
  return (
    <>
      <div className="flex justify-end">
        <Button
          type="button"
          variant="secondary"
          size="sm"
          disabled={saving || reload.isPending}
          onClick={() => setShowReload(true)}
        >
          Reload source
        </Button>
      </div>
      {initial.revision !== source.revision ? (
        <Callout tone="info">
          This source has changed. Unsaved edits are kept; reload to use the latest configuration.
        </Callout>
      ) : null}
      {source.type === "openapi" && (
        <OpenApiEditor
          key={epoch}
          sourceId={sourceId}
          source={source}
          activeTab={activeTab}
          onSaved={saved}
        />
      )}

      {source.type === "http" && (
        <HttpSourceEditor key={epoch} sourceId={sourceId} source={source} onSaved={saved} />
      )}
      {source.type !== "http" && source.type !== "openapi" && (
        <AdvancedJsonEditor key={epoch} sourceId={sourceId} source={source} onSaved={saved} />
      )}
      <ConfirmModal
        open={showReload}
        onClose={() => setShowReload(false)}
        onConfirm={() => {
          if (!saving) reload.mutate();
        }}
        title="Reload source?"
        description="This replaces the current draft with the latest saved configuration. Unsaved edits will be discarded."
        confirmLabel="Reload"
        loading={reload.isPending || saving}
      />
    </>
  );
}

const openApiSchema = z.object({
  enabled: z.boolean(),
  spec: z.string().url("Must be a valid URL"),
  baseUrl: z.string().optional(),

  authMode: z.enum(["none", "bearer", "header", "basic", "query"]),
  bearerToken: z.string().optional(),
  headerName: z.string().optional(),
  headerValue: z.string().optional(),
  basicUsername: z.string().optional(),
  basicPassword: z.string().optional(),
  queryName: z.string().optional(),
  queryValue: z.string().optional(),

  autoDiscoverEnabled: z.boolean(),
  autoDiscoverInclude: z.string().optional(),
  autoDiscoverExclude: z.string().optional(),

  defaultsTimeoutSecs: z
    .string()
    .optional()
    .refine((v) => !v || (/^\d+$/.test(v.trim()) && Number(v.trim()) > 0), {
      message: "Must be a positive integer",
    }),
  defaultsArrayStyle: z.enum(["form", "spaceDelimited", "pipeDelimited", "deepObject"]).optional(),
  defaultsHeaders: z
    .array(
      z.object({
        key: z.string(),
        value: z.string(),
      }),
    )
    .default([]),
});

type OpenApiFormValues = z.input<typeof openApiSchema>;

function OpenApiEditor({
  sourceId,
  source,
  activeTab,
  onSaved,
}: {
  sourceId: string;
  source: ToolSourceDetail;
  activeTab: "settings" | "tools";
  onSaved: () => Promise<void>;
}) {
  const queryClient = useQueryClient();
  const pushToast = useToastStore((s) => s.push);

  const defaults = useMemo<OpenApiFormValues>(() => {
    const cfg = source.spec;

    const auth = (cfg.auth ?? null) as Record<string, unknown> | null;
    const authType = (auth?.type as string | undefined) ?? "none";

    const autoDiscover = cfg.autoDiscover as unknown;
    const autoDiscoverEnabled =
      typeof autoDiscover === "boolean"
        ? autoDiscover
        : typeof autoDiscover === "object" && autoDiscover !== null;
    const autoDiscoverObj: { include?: unknown; exclude?: unknown } | null =
      typeof autoDiscover === "object" && autoDiscover
        ? (autoDiscover as { include?: unknown; exclude?: unknown })
        : null;
    const include = autoDiscoverObj?.include;
    const exclude = autoDiscoverObj?.exclude;

    const defaultsObj = (cfg.defaults ?? {}) as Record<string, unknown>;
    const headersObj = (defaultsObj.headers ?? {}) as Record<string, unknown>;
    const headers = Object.entries(headersObj)
      .filter(([k, v]) => typeof k === "string" && typeof v === "string")
      .map(([k, v]) => ({ key: k, value: String(v) }));

    return {
      enabled: source.enabled,
      spec: typeof cfg.spec === "string" ? cfg.spec : "",
      baseUrl: typeof cfg.baseUrl === "string" ? cfg.baseUrl : "",

      authMode:
        authType === "bearer" ||
        authType === "header" ||
        authType === "basic" ||
        authType === "query"
          ? (authType as OpenApiFormValues["authMode"])
          : "none",
      bearerToken: typeof auth?.token === "string" ? (auth.token as string) : undefined,
      headerName: typeof auth?.name === "string" ? (auth.name as string) : undefined,
      headerValue: typeof auth?.value === "string" ? (auth.value as string) : undefined,
      basicUsername: typeof auth?.username === "string" ? (auth.username as string) : undefined,
      basicPassword: typeof auth?.password === "string" ? (auth.password as string) : undefined,
      queryName: typeof auth?.name === "string" ? (auth.name as string) : undefined,
      queryValue: typeof auth?.value === "string" ? (auth.value as string) : undefined,

      autoDiscoverEnabled,
      autoDiscoverInclude: Array.isArray(include)
        ? include.filter((x) => typeof x === "string").join("\n")
        : "",
      autoDiscoverExclude: Array.isArray(exclude)
        ? exclude.filter((x) => typeof x === "string").join("\n")
        : "",

      defaultsTimeoutSecs:
        typeof defaultsObj.timeout === "number" ? String(defaultsObj.timeout) : "",
      defaultsArrayStyle:
        typeof defaultsObj.arrayStyle === "string"
          ? (defaultsObj.arrayStyle as OpenApiFormValues["defaultsArrayStyle"])
          : undefined,
      defaultsHeaders: headers,
    };
  }, [source]);

  const form = useForm<OpenApiFormValues>({
    resolver: zodResolver(openApiSchema),
    defaultValues: defaults,
  });

  const authMode = useWatch({ control: form.control, name: "authMode" });
  const enabled = useWatch({ control: form.control, name: "enabled" });
  const autoDiscoverEnabled = useWatch({ control: form.control, name: "autoDiscoverEnabled" });
  const defaultsArrayStyle = useWatch({ control: form.control, name: "defaultsArrayStyle" });
  const defaultsHeaders = useWatch({ control: form.control, name: "defaultsHeaders" });

  const toolsQuery = useQuery({
    queryKey: qk.toolSourceTools(sourceId),
    enabled: activeTab === "tools" && !!sourceId,
    queryFn: () => tenantApi.listToolSourceTools(sourceId),
  });

  const saveMutation = useMutation({
    mutationKey: ["toolSourceSave", sourceId],
    mutationFn: async (values: OpenApiFormValues) => {
      const payload: Record<string, unknown> = {
        type: "openapi",
        enabled: values.enabled,
        spec: values.spec,
        baseUrl: null,
        auth: null,
      };

      const baseUrl = values.baseUrl?.trim();
      if (baseUrl) payload.baseUrl = baseUrl;

      // auth
      if (values.authMode === "bearer") {
        payload.auth = { type: "bearer", token: values.bearerToken ?? "" };
      } else if (values.authMode === "header") {
        payload.auth = {
          type: "header",
          name: values.headerName ?? "",
          value: values.headerValue ?? "",
        };
      } else if (values.authMode === "basic") {
        payload.auth = {
          type: "basic",
          username: values.basicUsername ?? "",
          password: values.basicPassword ?? "",
        };
      } else if (values.authMode === "query") {
        payload.auth = {
          type: "query",
          name: values.queryName ?? "",
          value: values.queryValue ?? "",
        };
      }

      // autoDiscover
      if (values.autoDiscoverEnabled) {
        const include = splitLines(values.autoDiscoverInclude ?? "");
        const exclude = splitLines(values.autoDiscoverExclude ?? "");
        payload.autoDiscover = include.length || exclude.length ? { include, exclude } : true;
      } else {
        payload.autoDiscover = false;
      }

      // defaults
      const headers: Record<string, string> = {};
      for (const row of values.defaultsHeaders ?? []) {
        const k = row.key?.trim();
        if (!k) continue;
        headers[k] = row.value ?? "";
      }
      const timeoutStr = values.defaultsTimeoutSecs?.trim();
      const timeout = timeoutStr ? Number(timeoutStr) : undefined;
      payload.defaults = {
        timeout,
        arrayStyle: values.defaultsArrayStyle,
        headers,
      };
      await tenantApi.putToolSource(
        sourceId,
        JSON.stringify(
          buildOpenApiSourceUpdate(source, {
            ...payload,
            enabled: values.enabled,
            defaults: payload.defaults as Record<string, unknown>,
          }),
        ),
      );
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: qk.toolSources() });
      await queryClient.invalidateQueries({ queryKey: qk.toolSource(sourceId) });
      pushToast({ variant: "success", message: "Source saved" });
      await onSaved();
      await queryClient.invalidateQueries({ queryKey: qk.toolSourceTools(sourceId) });
    },
    onError: (e) => {
      pushToast({
        variant: "error",
        message: e instanceof Error ? e.message : "Failed to save source",
      });
    },
  });

  if (activeTab === "tools") {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-4">
          <div className="text-sm text-muted">
            {toolsQuery.data ? (
              <>
                Discovered tools:{" "}
                <span className="font-mono font-medium text-fg">
                  {toolsQuery.data.tools.length}
                </span>
              </>
            ) : (
              "Discovered tools"
            )}
          </div>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => toolsQuery.refetch()}
            disabled={toolsQuery.isFetching}
            loading={toolsQuery.isFetching}
          >
            Refresh
          </Button>
        </div>

        {toolsQuery.error && (
          <Callout tone="danger">
            {toolsQuery.error instanceof Error
              ? toolsQuery.error.message
              : "Failed to discover tools"}
          </Callout>
        )}

        {toolsQuery.isFetching && !toolsQuery.data && (
          <div className="flex items-center gap-2 text-sm text-muted">
            <Spinner size="sm" />
            Probing…
          </div>
        )}

        {toolsQuery.data && toolsQuery.data.tools.length === 0 && (
          <EmptyState title="No tools discovered" />
        )}

        {toolsQuery.data && toolsQuery.data.tools.length > 0 && (
          <div className="overflow-hidden rounded-lg border border-edge bg-surface">
            <div className="divide-y divide-edge">
              {toolsQuery.data.tools.map((t) => (
                <div key={t.name} className="px-4 py-3">
                  <div className="font-mono text-sm font-medium text-accent">{t.name}</div>
                  {t.description && <div className="mt-1 text-xs text-faint">{t.description}</div>}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  const headerRows = defaultsHeaders ?? [];

  return (
    <form onSubmit={form.handleSubmit((v) => saveMutation.mutate(v))} className="space-y-6">
      <fieldset disabled={saveMutation.isPending} className="space-y-6">
        <Toggle
          label="Source enabled"
          checked={enabled}
          onChange={(checked) => form.setValue("enabled", checked, { shouldDirty: true })}
          description="Disabled sources stay configured but do not expose tools."
        />
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <Input
            label="OpenAPI spec URL"
            placeholder="https://example.com/openapi.json"
            {...form.register("spec")}
            error={form.formState.errors.spec?.message}
          />
          <Input
            label="Base URL (optional)"
            placeholder="https://api.example.com/v1"
            hint="Override the spec's base url (recommended when the spec uses a relative server URL)."
            {...form.register("baseUrl")}
            error={form.formState.errors.baseUrl?.message}
          />
        </div>

        <SectionCard title="Auth" bodyClassName="space-y-4">
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <Select
              label="Auth mode"
              value={authMode}
              onChange={(e) =>
                form.setValue("authMode", e.target.value as OpenApiFormValues["authMode"])
              }
            >
              <option value="none">None</option>
              <option value="bearer">Bearer token</option>
              <option value="header">Custom header</option>
              <option value="basic">Basic auth</option>
              <option value="query">Query parameter</option>
            </Select>
          </div>

          {authMode === "bearer" && (
            <Input label="Bearer token" placeholder="token" {...form.register("bearerToken")} />
          )}
          {authMode === "header" && (
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <Input
                label="Header name"
                placeholder="Authorization"
                {...form.register("headerName")}
              />
              <Input
                label="Header value"
                placeholder="Bearer …"
                {...form.register("headerValue")}
              />
            </div>
          )}
          {authMode === "basic" && (
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <Input label="Username" {...form.register("basicUsername")} />
              <Input label="Password" type="password" {...form.register("basicPassword")} />
            </div>
          )}
          {authMode === "query" && (
            <>
              <QueryParamAuthWarning />
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <Input
                  label="Query param name"
                  placeholder="api_key"
                  {...form.register("queryName")}
                />
                <Input label="Query param value" {...form.register("queryValue")} />
              </div>
            </>
          )}
        </SectionCard>

        <SectionCard title="Discovery" bodyClassName="space-y-4">
          <div className="flex items-center justify-between gap-4">
            <div>
              <div className="text-sm text-fg">Auto-discover tools</div>
              <div className="text-xs text-faint">
                Discover operations from the spec automatically.
              </div>
            </div>
            <Toggle
              checked={autoDiscoverEnabled}
              onChange={(checked) =>
                form.setValue("autoDiscoverEnabled", checked, { shouldDirty: true })
              }
            />
          </div>

          {autoDiscoverEnabled && (
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <Textarea
                label="Include patterns (optional)"
                hint="One per line. Leave empty to include everything."
                rows={6}
                {...form.register("autoDiscoverInclude")}
              />
              <Textarea
                label="Exclude patterns (optional)"
                hint="One per line."
                rows={6}
                {...form.register("autoDiscoverExclude")}
              />
            </div>
          )}
        </SectionCard>

        <SectionCard title="Defaults" bodyClassName="space-y-4">
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <Input
              label="Default timeout (seconds)"
              placeholder="e.g. 30"
              inputMode="numeric"
              {...form.register("defaultsTimeoutSecs")}
              error={form.formState.errors.defaultsTimeoutSecs?.message}
            />
            <Select
              label="Array style"
              value={defaultsArrayStyle ?? ""}
              onChange={(e) =>
                form.setValue(
                  "defaultsArrayStyle",
                  e.target.value
                    ? (e.target.value as NonNullable<OpenApiFormValues["defaultsArrayStyle"]>)
                    : undefined,
                  { shouldDirty: true },
                )
              }
            >
              <option value="">Default</option>
              <option value="form">Comma-separated (form)</option>
              <option value="spaceDelimited">Space-delimited</option>
              <option value="pipeDelimited">Pipe-delimited</option>
              <option value="deepObject">Deep object</option>
            </Select>
          </div>

          <div>
            <div className="mb-2 flex items-center justify-between gap-4">
              <div>
                <div className="text-sm font-medium text-fg">Default headers</div>
                <div className="text-xs text-faint">Applied to every request.</div>
              </div>
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={() =>
                  form.setValue("defaultsHeaders", [...headerRows, { key: "", value: "" }], {
                    shouldDirty: true,
                  })
                }
              >
                Add header
              </Button>
            </div>

            {headerRows.length === 0 ? (
              <div className="text-sm text-faint">No headers.</div>
            ) : (
              <div className="space-y-3">
                {headerRows.map((row, idx) => (
                  <div key={idx} className="grid grid-cols-1 gap-3 md:grid-cols-[1fr_1fr_auto]">
                    <Input
                      aria-label={`Default header ${idx + 1} name`}
                      placeholder="Header name"
                      value={row.key}
                      onChange={(e) => {
                        const next = [...headerRows];
                        next[idx] = { ...next[idx], key: e.target.value };
                        form.setValue("defaultsHeaders", next, { shouldDirty: true });
                      }}
                    />
                    <Input
                      aria-label={`Default header ${idx + 1} value`}
                      placeholder="Header value"
                      value={row.value}
                      onChange={(e) => {
                        const next = [...headerRows];
                        next[idx] = { ...next[idx], value: e.target.value };
                        form.setValue("defaultsHeaders", next, { shouldDirty: true });
                      }}
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        const next = headerRows.filter((_, i) => i !== idx);
                        form.setValue("defaultsHeaders", next, { shouldDirty: true });
                      }}
                    >
                      Remove
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </SectionCard>

        <div className="flex items-center justify-end gap-3 pt-2">
          <Button type="submit" loading={saveMutation.isPending}>
            Save
          </Button>
        </div>
      </fieldset>
    </form>
  );
}

function AdvancedJsonEditor({
  sourceId,
  source,
  onSaved,
}: {
  sourceId: string;
  source: ToolSourceDetail;
  onSaved: () => Promise<void>;
}) {
  const queryClient = useQueryClient();
  const pushToast = useToastStore((s) => s.push);
  const [text, setText] = useState(() =>
    JSON.stringify({ ...source.spec, type: source.type, enabled: source.enabled }, null, 2),
  );
  const [error, setError] = useState<string | null>(null);
  let jsonDraft: Record<string, unknown> | null = null;
  try {
    jsonDraft = buildJsonSourceUpdate(source, text);
  } catch {
    /* Keep invalid JSON editable. */
  }

  const saveMutation = useMutation({
    mutationKey: ["toolSourceSave", sourceId],
    mutationFn: async () => {
      await tenantApi.putToolSource(sourceId, JSON.stringify(buildJsonSourceUpdate(source, text)));
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: qk.toolSources() });
      await queryClient.invalidateQueries({ queryKey: qk.toolSource(sourceId) });
      await onSaved();
      pushToast({ variant: "success", message: "Tool source saved" });
      setError(null);
    },
    onError: (e) => {
      const msg = e instanceof Error ? e.message : "Failed to save tool source";
      setError(msg);
      pushToast({ variant: "error", message: msg });
    },
  });

  return (
    <SectionCard
      title="Advanced JSON"
      subtitle="Edit the source configuration as JSON, then save to apply changes."
      bodyClassName="space-y-4"
    >
      {error && <Callout tone="danger">{error}</Callout>}

      <Toggle
        label="Source enabled"
        description="Save JSON to apply this change."
        checked={jsonDraft?.enabled !== false}
        disabled={!jsonDraft || saveMutation.isPending}
        onChange={(enabled) => {
          if (jsonDraft) {
            setText(JSON.stringify({ ...jsonDraft, enabled }, null, 2));
            setError(null);
          }
        }}
      />
      <Textarea
        aria-label="Source configuration JSON"
        disabled={saveMutation.isPending}
        value={text}
        onChange={(e) => {
          setError(null);
          setText(e.target.value);
        }}
        rows={18}
      />

      <div className="flex items-center justify-end gap-3">
        <Button
          type="button"
          variant="secondary"
          loading={saveMutation.isPending}
          onClick={() => saveMutation.mutate()}
        >
          Save JSON
        </Button>
      </div>
    </SectionCard>
  );
}

function splitLines(text: string): string[] {
  return text
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
}
