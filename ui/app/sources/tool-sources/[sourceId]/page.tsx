"use client";

import { useMemo, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Button,
  ConfirmModal,
  Input,
  QueryParamAuthWarning,
  Textarea,
  Toggle,
} from "@/components/ui";
import { qk } from "@/src/lib/queryKeys";
import { useToastStore } from "@/src/lib/toast-store";
import * as tenantApi from "@/src/lib/tenantApi";
import { useForm, useWatch } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";

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
  const pushToast = useToastStore((s) => s.push);
  const [activeTab, setActiveTab] = useState<"settings" | "tools">("settings");

  const toolSourceQuery = useQuery({
    queryKey: qk.toolSource(sourceId),
    enabled: !!sourceId,
    queryFn: () => tenantApi.getToolSource(sourceId),
  });

  const detail = toolSourceQuery.data;
  const toolsTabEnabled = detail?.type === "openapi";
  const editorKey = detail
    ? `${sourceId}:${detail.type}:${toolSourceQuery.dataUpdatedAt}`
    : sourceId;

  return (
    <PageContent width="5xl">
      <div className="rounded-2xl border border-zinc-800/60 bg-zinc-900/40 overflow-hidden">
        <div className="px-6 py-4 border-b border-zinc-800/60 flex items-center justify-between gap-4">
          <div>
            <div className="text-sm font-semibold text-zinc-100">Source editor</div>
            <div className="mt-1 text-xs text-zinc-500">
              Configure this source and verify discovered tools.
            </div>
          </div>
          <div className="flex items-center gap-2">
            <TabButton active={activeTab === "settings"} onClick={() => setActiveTab("settings")}>
              Settings
            </TabButton>
            {toolsTabEnabled ? (
              <TabButton active={activeTab === "tools"} onClick={() => setActiveTab("tools")}>
                Tools
              </TabButton>
            ) : null}
          </div>
        </div>

        <div className="p-6">
          {toolSourceQuery.isPending && <div className="text-sm text-zinc-400">Loading…</div>}
          {toolSourceQuery.error && (
            <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-200">
              {toolSourceQuery.error instanceof Error
                ? toolSourceQuery.error.message
                : "Failed to load tool source"}
            </div>
          )}

          {!toolSourceQuery.isPending && !toolSourceQuery.error && !detail && (
            <div className="text-sm text-zinc-500">Tool source not found.</div>
          )}

          {detail && detail.type === "openapi" && (
            <OpenApiEditor
              key={editorKey}
              sourceId={sourceId}
              initialSpec={detail.spec ?? {}}
              enabled={detail.enabled}
              activeTab={activeTab}
              onSaved={() => setActiveTab("tools")}
            />
          )}

          {detail && detail.type !== "openapi" && (
            <div className="space-y-4">
              {detail.type === "http" ? (
                <div className="rounded-xl border border-violet-500/20 bg-violet-500/5 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <div className="text-sm font-semibold text-zinc-100">HTTP DSL (Beta)</div>
                    <span className="px-1.5 py-0.5 rounded-md text-[10px] font-semibold bg-violet-500/10 text-violet-300 border border-violet-500/20">
                      Beta
                    </span>
                  </div>
                  <div className="mt-1 text-xs text-zinc-400">
                    For now this source type supports JSON-only editing via the Advanced JSON
                    editor. We don’t validate or help with the schema yet. A full editor is planned.
                  </div>
                </div>
              ) : (
                <div className="rounded-xl border border-zinc-800/60 bg-zinc-950/30 p-4 text-sm text-zinc-400">
                  Dedicated editor for{" "}
                  <span className="font-mono text-zinc-200">{detail.type}</span> is not implemented
                  yet. For now, use the Advanced JSON editor below.
                </div>
              )}
              <AdvancedJsonEditor
                key={editorKey}
                sourceId={sourceId}
                type={detail.type}
                enabled={detail.enabled}
                spec={detail.spec ?? {}}
                onSaved={() => pushToast({ variant: "success", message: "Tool source saved" })}
              />
            </div>
          )}
        </div>
      </div>
    </PageContent>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={[
        "px-3 py-1.5 rounded-lg text-xs font-medium transition-colors",
        active
          ? "bg-violet-500/15 text-violet-200 border border-violet-500/30"
          : "bg-zinc-950/30 text-zinc-400 border border-zinc-800/60 hover:text-zinc-200 hover:border-zinc-700/80",
      ].join(" ")}
    >
      {children}
    </button>
  );
}

const openApiSchema = z.object({
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
  initialSpec,
  enabled,
  activeTab,
  onSaved,
}: {
  sourceId: string;
  initialSpec: Record<string, unknown>;
  enabled: boolean;
  activeTab: "settings" | "tools";
  onSaved: () => void;
}) {
  const queryClient = useQueryClient();
  const pushToast = useToastStore((s) => s.push);

  const defaults = useMemo<OpenApiFormValues>(() => {
    const cfg = (initialSpec ?? {}) as Record<string, unknown>;

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
  }, [initialSpec]);

  const form = useForm<OpenApiFormValues>({
    resolver: zodResolver(openApiSchema),
    defaultValues: defaults,
  });

  const authMode = useWatch({ control: form.control, name: "authMode" });
  const autoDiscoverEnabled = useWatch({ control: form.control, name: "autoDiscoverEnabled" });
  const defaultsArrayStyle = useWatch({ control: form.control, name: "defaultsArrayStyle" });
  const defaultsHeaders = useWatch({ control: form.control, name: "defaultsHeaders" });

  const toolsQuery = useQuery({
    queryKey: qk.toolSourceTools(sourceId),
    enabled: activeTab === "tools" && !!sourceId,
    queryFn: () => tenantApi.listToolSourceTools(sourceId),
  });

  const saveMutation = useMutation({
    mutationFn: async (values: OpenApiFormValues) => {
      const payload: Record<string, unknown> = {
        type: "openapi",
        // UI does not expose "enabled" yet; preserve existing value.
        enabled,
        spec: values.spec,
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
      if (
        timeout !== undefined ||
        values.defaultsArrayStyle !== undefined ||
        Object.keys(headers).length > 0
      ) {
        payload.defaults = {
          timeout,
          arrayStyle: values.defaultsArrayStyle,
          headers,
        };
      }

      await tenantApi.putToolSource(sourceId, JSON.stringify(payload));
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: qk.toolSources() });
      await queryClient.invalidateQueries({ queryKey: qk.toolSource(sourceId) });
      pushToast({ variant: "success", message: "Source saved" });
      onSaved();
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
          <div className="text-sm text-zinc-300">
            {toolsQuery.data ? (
              <>
                Discovered tools:{" "}
                <span className="text-zinc-100 font-semibold">{toolsQuery.data.tools.length}</span>
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
          <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-200">
            {toolsQuery.error instanceof Error
              ? toolsQuery.error.message
              : "Failed to discover tools"}
          </div>
        )}

        {toolsQuery.isFetching && !toolsQuery.data && (
          <div className="text-sm text-zinc-400">Probing…</div>
        )}

        {toolsQuery.data && toolsQuery.data.tools.length === 0 && (
          <div className="rounded-xl border border-zinc-800/60 bg-zinc-950/30 p-4 text-sm text-zinc-500">
            No tools discovered.
          </div>
        )}

        {toolsQuery.data && toolsQuery.data.tools.length > 0 && (
          <div className="rounded-xl border border-zinc-800/60 bg-zinc-950/30 overflow-hidden">
            <div className="divide-y divide-zinc-800/40">
              {toolsQuery.data.tools.map((t) => (
                <div key={t.name} className="px-4 py-3">
                  <div className="text-sm font-semibold text-violet-300 font-mono">{t.name}</div>
                  {t.description && (
                    <div className="mt-1 text-xs text-zinc-500">{t.description}</div>
                  )}
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
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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

      <Section title="Auth">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <SelectField
            label="Auth mode"
            value={authMode}
            onChange={(v) => form.setValue("authMode", v as OpenApiFormValues["authMode"])}
            options={[
              { value: "none", label: "None" },
              { value: "bearer", label: "Bearer token" },
              { value: "header", label: "Custom header" },
              { value: "basic", label: "Basic auth" },
              { value: "query", label: "Query parameter" },
            ]}
          />
        </div>

        {authMode === "bearer" && (
          <Input label="Bearer token" placeholder="token" {...form.register("bearerToken")} />
        )}
        {authMode === "header" && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Input
              label="Header name"
              placeholder="Authorization"
              {...form.register("headerName")}
            />
            <Input label="Header value" placeholder="Bearer …" {...form.register("headerValue")} />
          </div>
        )}
        {authMode === "basic" && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Input label="Username" {...form.register("basicUsername")} />
            <Input label="Password" type="password" {...form.register("basicPassword")} />
          </div>
        )}
        {authMode === "query" && (
          <>
            <QueryParamAuthWarning />
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Input
                label="Query param name"
                placeholder="api_key"
                {...form.register("queryName")}
              />
              <Input label="Query param value" {...form.register("queryValue")} />
            </div>
          </>
        )}
      </Section>

      <Section title="Discovery">
        <div className="flex items-center justify-between gap-4">
          <div>
            <div className="text-sm text-zinc-200">Auto-discover tools</div>
            <div className="text-xs text-zinc-500">
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
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
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
      </Section>

      <Section title="Defaults">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Input
            label="Default timeout (seconds)"
            placeholder="e.g. 30"
            inputMode="numeric"
            {...form.register("defaultsTimeoutSecs")}
            error={form.formState.errors.defaultsTimeoutSecs?.message}
          />
          <SelectField
            label="Array style"
            value={defaultsArrayStyle ?? ""}
            onChange={(v) =>
              form.setValue(
                "defaultsArrayStyle",
                v ? (v as NonNullable<OpenApiFormValues["defaultsArrayStyle"]>) : undefined,
                { shouldDirty: true },
              )
            }
            options={[
              { value: "", label: "Default" },
              { value: "form", label: "Comma-separated (form)" },
              { value: "spaceDelimited", label: "Space-delimited" },
              { value: "pipeDelimited", label: "Pipe-delimited" },
              { value: "deepObject", label: "Deep object" },
            ]}
          />
        </div>

        <div className="mt-4">
          <div className="flex items-center justify-between gap-4 mb-2">
            <div>
              <div className="text-sm font-medium text-zinc-300">Default headers</div>
              <div className="text-xs text-zinc-500">Applied to every request.</div>
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
            <div className="text-sm text-zinc-500">No headers.</div>
          ) : (
            <div className="space-y-3">
              {headerRows.map((row, idx) => (
                <div key={idx} className="grid grid-cols-1 md:grid-cols-[1fr_1fr_auto] gap-3">
                  <Input
                    placeholder="Header name"
                    value={row.key}
                    onChange={(e) => {
                      const next = [...headerRows];
                      next[idx] = { ...next[idx], key: e.target.value };
                      form.setValue("defaultsHeaders", next, { shouldDirty: true });
                    }}
                  />
                  <Input
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
      </Section>

      <div className="flex items-center justify-end gap-3 pt-2">
        <Button type="submit" loading={saveMutation.isPending}>
          Save
        </Button>
      </div>
    </form>
  );
}

function AdvancedJsonEditor({
  sourceId,
  type,
  enabled,
  spec,
  onSaved,
}: {
  sourceId: string;
  type: string;
  enabled: boolean;
  spec: Record<string, unknown>;
  onSaved: () => void;
}) {
  const queryClient = useQueryClient();
  const pushToast = useToastStore((s) => s.push);
  const [text, setText] = useState(() =>
    JSON.stringify({ type, enabled, ...(spec ?? {}) }, null, 2),
  );
  const [error, setError] = useState<string | null>(null);

  const saveMutation = useMutation({
    mutationFn: async () => {
      JSON.parse(text);
      await tenantApi.putToolSource(sourceId, text);
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: qk.toolSources() });
      await queryClient.invalidateQueries({ queryKey: qk.toolSource(sourceId) });
      onSaved();
      setError(null);
    },
    onError: (e) => {
      const msg = e instanceof Error ? e.message : "Failed to save tool source";
      setError(msg);
      pushToast({ variant: "error", message: msg });
    },
  });

  return (
    <div className="rounded-xl border border-zinc-800/60 bg-zinc-950/30 p-5">
      <div className="text-sm font-semibold text-zinc-100">Advanced JSON</div>
      <div className="mt-1 text-xs text-zinc-500">
        Direct payload editor (temporary). UI will replace this with dedicated editors per type.
      </div>

      {error && (
        <div className="mt-4 rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-200">
          {error}
        </div>
      )}

      <div className="mt-4">
        <textarea
          value={text}
          onChange={(e) => {
            setError(null);
            setText(e.target.value);
          }}
          rows={18}
          className="w-full rounded-lg bg-zinc-950/80 border border-zinc-800 px-3 py-2 text-xs text-zinc-200 font-mono focus:outline-none focus:ring-2 focus:ring-violet-500/50"
        />
      </div>

      <div className="mt-4 flex items-center justify-end gap-3">
        <Button
          type="button"
          variant="secondary"
          loading={saveMutation.isPending}
          onClick={() => saveMutation.mutate()}
        >
          Save JSON
        </Button>
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-zinc-800/60 bg-zinc-950/30 p-5">
      <div className="text-sm font-semibold text-zinc-100">{title}</div>
      <div className="mt-4 space-y-4">{children}</div>
    </div>
  );
}

function SelectField({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <div className="space-y-1.5">
      <label className="block text-sm font-medium text-zinc-300">{label}</label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={[
          "w-full rounded-lg border border-zinc-700/80 bg-zinc-900/50",
          "text-zinc-100 placeholder:text-zinc-500",
          "transition-all duration-150",
          "focus:outline-none focus:ring-2 focus:ring-violet-500/50 focus:border-violet-500/50",
          "hover:border-zinc-600/80",
          "px-3 py-2 text-sm",
        ].join(" ")}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </div>
  );
}

function splitLines(text: string): string[] {
  return text
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
}
