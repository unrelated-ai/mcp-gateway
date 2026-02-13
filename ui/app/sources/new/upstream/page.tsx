"use client";

import { Suspense, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useMutation, useQuery } from "@tanstack/react-query";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import { Button, Input, QueryParamAuthWarning } from "@/components/ui";
import * as tenantApi from "@/src/lib/tenantApi";
import { useToastStore } from "@/src/lib/toast-store";

type WizardKind = "mcp" | "adapter";

function kindLabel(kind: WizardKind) {
  return kind === "adapter" ? "Adapter" : "MCP Server";
}

function sanitizeIdBase(s: string): string {
  const cleaned = s
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/\/+$/, "")
    .replace(/[^A-Za-z0-9_-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^[-_]+|[-_]+$/g, "");
  return cleaned || "upstream";
}

function ensureUnique(base: string, existingLower: ReadonlySet<string>): string {
  const b = base.trim();
  if (!existingLower.has(b.toLowerCase())) return b;
  for (let i = 2; i < 1000; i++) {
    const candidate = `${b}_${i}`;
    if (!existingLower.has(candidate.toLowerCase())) return candidate;
  }
  return `${b}_${Date.now()}`;
}

function parseHttpUrl(s: string): URL | null {
  try {
    const u = new URL(s.trim());
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return u;
  } catch {
    return null;
  }
}

type AuthDraft =
  | { type: "none" }
  | { type: "bearer"; token: string }
  | { type: "basic"; username: string; password: string }
  | { type: "header"; name: string; value: string }
  | { type: "query"; name: string; value: string };

export default function NewUpstreamWizardPage() {
  return (
    <Suspense
      fallback={
        <AppShell>
          <PageHeader
            title="Add upstream"
            description="Connect a remote MCP endpoint (Streamable HTTP)."
            breadcrumb={[{ label: "Sources", href: "/sources" }, { label: "New upstream" }]}
          />
          <PageContent>
            <div className="mx-auto max-w-3xl">
              <div className="rounded-2xl border border-zinc-800/60 bg-zinc-950/30 p-6 sm:p-8 text-sm text-zinc-400">
                Loading…
              </div>
            </div>
          </PageContent>
        </AppShell>
      }
    >
      <NewUpstreamWizardInner />
    </Suspense>
  );
}

function NewUpstreamWizardInner() {
  const router = useRouter();
  const search = useSearchParams();
  const pushToast = useToastStore((s) => s.push);

  const kind = (search.get("kind") === "adapter" ? "adapter" : "mcp") satisfies WizardKind;

  const [step, setStep] = useState<1 | 2>(1);
  const [error, setError] = useState<string | null>(null);

  const [endpointUrl, setEndpointUrl] = useState("");
  const [upstreamId, setUpstreamId] = useState("");

  const [authType, setAuthType] = useState<AuthDraft["type"]>("none");
  const [bearerToken, setBearerToken] = useState("");
  const [basicUsername, setBasicUsername] = useState("");
  const [basicPassword, setBasicPassword] = useState("");
  const [headerName, setHeaderName] = useState("");
  const [headerValue, setHeaderValue] = useState("");
  const [queryName, setQueryName] = useState("");
  const [queryValue, setQueryValue] = useState("");

  const upstreamsQuery = useQuery({
    queryKey: ["wizardUpstreams"],
    queryFn: tenantApi.listUpstreams,
  });
  const toolSourcesQuery = useQuery({
    queryKey: ["wizardToolSources"],
    queryFn: tenantApi.listToolSources,
  });

  const existingNamesLower = useMemo(() => {
    const upstreams = upstreamsQuery.data?.upstreams ?? [];
    const sources = toolSourcesQuery.data?.sources ?? [];
    return new Set<string>(
      [...upstreams.map((u) => u.id), ...sources.map((s) => s.id)].map((s) =>
        String(s).toLowerCase(),
      ),
    );
  }, [upstreamsQuery.data, toolSourcesQuery.data]);

  const createMutation = useMutation({
    mutationFn: async () => {
      const url = endpointUrl.trim();
      const parsed = parseHttpUrl(url);
      if (!parsed) throw new Error("Endpoint URL must be a valid http(s) URL.");

      const id = upstreamId.trim();
      if (!id) throw new Error("Upstream name is required.");
      if (!/^[A-Za-z0-9_-]+$/.test(id)) {
        throw new Error("Upstream name may only contain letters, digits, underscore, dash.");
      }
      if (existingNamesLower.has(id.toLowerCase())) {
        throw new Error(
          "Name already exists (names are case-insensitive). Choose a different one.",
        );
      }

      const auth: tenantApi.AuthConfig | undefined =
        authType === "none"
          ? undefined
          : authType === "bearer"
            ? { type: "bearer", token: bearerToken }
            : authType === "basic"
              ? { type: "basic", username: basicUsername, password: basicPassword }
              : authType === "header"
                ? { type: "header", name: headerName, value: headerValue }
                : { type: "query", name: queryName, value: queryValue };

      await tenantApi.putUpstream(id, {
        enabled: true,
        endpoints: [auth ? { id: "e1", url, auth } : { id: "e1", url }],
      });
      return id;
    },
    onSuccess: (id) => {
      pushToast({ variant: "success", message: "Upstream created" });
      // Replace wizard entry to avoid "Back" returning to the wizard after creation.
      router.replace(`/sources/upstreams/${encodeURIComponent(id)}`);
    },
    onError: (e) => {
      setError(e instanceof Error ? e.message : "Failed to create upstream");
    },
  });

  const title = `${kindLabel(kind)} upstream`;
  const abort = () => router.push("/sources");

  return (
    <AppShell>
      <PageHeader
        title="Add upstream"
        description="Connect a remote MCP endpoint (Streamable HTTP)."
        breadcrumb={[{ label: "Sources", href: "/sources" }, { label: "New upstream" }]}
      />

      <PageContent>
        <div className="mx-auto max-w-3xl">
          <div className="rounded-2xl border border-zinc-800/60 bg-zinc-950/30 overflow-hidden">
            <div className="p-6 sm:p-8">
              <div className="text-xs text-zinc-500">
                Step {step} of 2 · {kindLabel(kind)}
              </div>
              <h1 className="mt-2 text-xl sm:text-2xl font-semibold text-zinc-100">{title}</h1>
              <p className="mt-3 text-base text-zinc-400">
                We’ll create a tenant-owned upstream. You can probe and edit endpoints later on the
                upstream page.
              </p>

              {error ? (
                <div className="mt-5 rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-200">
                  {error}
                </div>
              ) : null}

              {step === 1 ? (
                <div className="mt-6 space-y-5">
                  <Input
                    label="Endpoint URL"
                    placeholder={
                      kind === "adapter" ? "http://adapter:8080/mcp" : "https://example.com/mcp"
                    }
                    value={endpointUrl}
                    onChange={(e) => setEndpointUrl(e.target.value)}
                    className="font-mono"
                    hint="Must be a Streamable HTTP MCP endpoint (http(s) only)."
                  />
                </div>
              ) : (
                <div className="mt-6 space-y-6">
                  <div className="rounded-xl border border-zinc-800/60 bg-zinc-900/30 p-4">
                    <div className="text-xs text-zinc-500">Endpoint</div>
                    <div className="mt-1 font-mono text-sm text-zinc-200 break-all">
                      {endpointUrl.trim()}
                    </div>
                  </div>

                  <Input
                    label="Upstream name"
                    value={upstreamId}
                    onChange={(e) => setUpstreamId(e.target.value)}
                    className="font-mono"
                    hint="Unique (case-insensitive). Used when attaching to profiles."
                  />
                  <p className="text-xs text-zinc-500">
                    Allowed characters: letters, digits, underscore, dash.
                  </p>

                  <div className="space-y-2">
                    <label className="block text-sm font-medium text-zinc-300">Upstream auth</label>
                    <select
                      value={authType}
                      onChange={(e) => setAuthType(e.target.value as AuthDraft["type"])}
                      className="w-full h-10 rounded-xl bg-zinc-900 border border-zinc-800 px-3 text-sm text-zinc-200"
                    >
                      <option value="none">None</option>
                      <option value="bearer">Bearer token (Authorization)</option>
                      <option value="header">Custom header (e.g. x-api-key)</option>
                      <option value="basic">Basic auth (Authorization)</option>
                      <option value="query">Query parameter</option>
                    </select>
                    <div className="text-xs text-zinc-500">
                      Optional. Used only for Gateway → upstream connections; client auth is never
                      forwarded.
                    </div>
                    {authType === "query" ? <QueryParamAuthWarning /> : null}
                  </div>

                  {authType === "bearer" ? (
                    <Input
                      label="Bearer token"
                      type="password"
                      value={bearerToken}
                      onChange={(e) => setBearerToken(e.target.value)}
                      className="font-mono"
                    />
                  ) : null}

                  {authType === "basic" ? (
                    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                      <Input
                        label="Username"
                        value={basicUsername}
                        onChange={(e) => setBasicUsername(e.target.value)}
                        className="font-mono"
                      />
                      <Input
                        label="Password"
                        type="password"
                        value={basicPassword}
                        onChange={(e) => setBasicPassword(e.target.value)}
                        className="font-mono"
                      />
                    </div>
                  ) : null}

                  {authType === "header" ? (
                    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                      <Input
                        label="Header name"
                        value={headerName}
                        onChange={(e) => setHeaderName(e.target.value)}
                        className="font-mono"
                      />
                      <Input
                        label="Header value"
                        type="password"
                        value={headerValue}
                        onChange={(e) => setHeaderValue(e.target.value)}
                        className="font-mono"
                      />
                    </div>
                  ) : null}

                  {authType === "query" ? (
                    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                      <Input
                        label="Query name"
                        value={queryName}
                        onChange={(e) => setQueryName(e.target.value)}
                        className="font-mono"
                      />
                      <Input
                        label="Query value"
                        type="password"
                        value={queryValue}
                        onChange={(e) => setQueryValue(e.target.value)}
                        className="font-mono"
                      />
                    </div>
                  ) : null}
                </div>
              )}
            </div>

            <div className="border-t border-zinc-800/60 bg-zinc-900/30 p-6 flex items-center justify-between gap-3">
              <Button
                type="button"
                variant="ghost"
                onClick={abort}
                disabled={createMutation.isPending}
              >
                Abort
              </Button>

              <div className="flex items-center gap-2">
                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => setStep(1)}
                  disabled={createMutation.isPending || step === 1}
                >
                  Back
                </Button>

                {step === 1 ? (
                  <Button
                    type="button"
                    onClick={() => {
                      setError(null);
                      const u = parseHttpUrl(endpointUrl);
                      if (!u) {
                        setError("Endpoint URL must be a valid http(s) URL.");
                        return;
                      }
                      const base = sanitizeIdBase(u.host + u.pathname);
                      const prefixed = kind === "adapter" ? `adapter-${base}` : `mcp-${base}`;
                      const suggested = ensureUnique(prefixed, existingNamesLower);
                      setUpstreamId(suggested);
                      setStep(2);
                    }}
                    disabled={createMutation.isPending}
                  >
                    Next
                  </Button>
                ) : (
                  <Button
                    type="button"
                    loading={createMutation.isPending}
                    onClick={() => {
                      setError(null);
                      createMutation.mutate();
                    }}
                  >
                    Create
                  </Button>
                )}
              </div>
            </div>
          </div>
        </div>
      </PageContent>
    </AppShell>
  );
}
