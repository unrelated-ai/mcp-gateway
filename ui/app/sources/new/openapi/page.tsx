"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import { Button, Callout, Input } from "@/components/ui";
import * as tenantApi from "@/src/lib/tenantApi";

type Step = 1 | 2 | 3 | 4;

function nextStepLabel(step: Step) {
  return `Step ${step} of 4`;
}

function normalizeSuggestedId(raw: string): string {
  const s = raw.trim().toLowerCase();
  let out = "";
  let prevUnderscore = false;
  for (const ch of s) {
    const ok = /[a-z0-9_-]/.test(ch);
    const c = ok ? ch : "_";
    if (c === "_") {
      if (prevUnderscore) continue;
      prevUnderscore = true;
      out += "_";
    } else {
      prevUnderscore = false;
      out += c;
    }
  }
  out = out.replace(/^_+|_+$/g, "");
  return out || "openapi";
}

function withCollisionSuffix(base: string, existingLower: Set<string>): string {
  if (!existingLower.has(base.toLowerCase())) return base;
  let i = 2;
  while (i < 9999) {
    const cand = `${base}_${i}`;
    if (!existingLower.has(cand.toLowerCase())) return cand;
    i += 1;
  }
  return `${base}_${Date.now()}`;
}

export default function NewOpenApiSourceWizardPage() {
  const router = useRouter();

  const [step, setStep] = useState<Step>(1);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [specUrl, setSpecUrl] = useState("");
  const [inspect, setInspect] = useState<tenantApi.OpenApiInspectResponse | null>(null);
  const [sourceId, setSourceId] = useState("");

  const existingSourcesQuery = tenantApi.listToolSources;
  const [existingNamesLower, setExistingNamesLower] = useState<Set<string>>(new Set());

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await existingSourcesQuery();
        if (cancelled) return;
        setExistingNamesLower(new Set((data.sources ?? []).map((s) => s.id.toLowerCase())));
      } catch {
        // Best-effort only; collisions are still checked server-side.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [existingSourcesQuery]);

  const title = useMemo(() => {
    switch (step) {
      case 1:
        return "OpenAPI spec";
      case 2:
        return "Name";
      case 3:
        return "Tools";
      case 4:
        return "Create";
      default:
        return "OpenAPI";
    }
  }, [step]);

  const abort = () => router.push("/sources");

  const runInspect = async () => {
    setBusy(true);
    setError(null);
    try {
      const url = specUrl.trim();
      if (!url) throw new Error("OpenAPI spec URL is required");
      const resp = await tenantApi.openapiInspect(url);
      setInspect(resp);

      const base = normalizeSuggestedId(resp.suggestedId ?? "openapi");
      const unique = withCollisionSuffix(base, existingNamesLower);
      setSourceId(unique);
      setStep(2);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to inspect spec");
    } finally {
      setBusy(false);
    }
  };

  const validateIdAndContinue = async () => {
    setBusy(true);
    setError(null);
    try {
      const id = sourceId.trim();
      if (!id) throw new Error("Name is required");
      const res = await tenantApi.validateSourceId(id);
      if (!res.ok) throw new Error(res.error || "Invalid name");
      setStep(3);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to validate name");
    } finally {
      setBusy(false);
    }
  };

  const goToConfirm = () => setStep(4);

  const create = async () => {
    if (!inspect) return;
    setBusy(true);
    setError(null);
    try {
      const id = sourceId.trim();
      const payload = {
        type: "openapi",
        enabled: true,
        spec: specUrl.trim(),
        baseUrl: inspect.inferredBaseUrl,
      };
      await tenantApi.putToolSource(id, JSON.stringify(payload));
      // Replace wizard entry to avoid "Back" returning to the wizard after creation.
      router.replace(`/sources/tool-sources/${encodeURIComponent(id)}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create source");
    } finally {
      setBusy(false);
    }
  };

  return (
    <AppShell>
      <PageHeader
        title="Add OpenAPI source"
        description="Step-by-step setup. You can tune advanced settings after creation."
        breadcrumb={[{ label: "Sources", href: "/sources" }, { label: "New OpenAPI source" }]}
      />
      <PageContent>
        <div className="mx-auto max-w-2xl">
          <div className="overflow-hidden rounded-lg border border-edge bg-surface">
            <div className="p-6">
              <div className="eyebrow">{nextStepLabel(step)}</div>

              <h2 className="mt-2 text-lg font-semibold text-fg">{title}</h2>

              {error && (
                <Callout tone="danger" size="md" title="Could not continue" className="mt-5">
                  <span className="whitespace-pre-wrap break-words">{error}</span>
                </Callout>
              )}

              {step === 1 && (
                <>
                  <p className="mt-2 text-sm text-muted">
                    Paste the URL to an OpenAPI spec. The Gateway supports JSON or YAML over
                    http(s).
                  </p>
                  <div className="mt-6">
                    <Input
                      label="OpenAPI spec URL"
                      value={specUrl}
                      onChange={(e) => setSpecUrl(e.target.value)}
                      placeholder="https://example.com/openapi.yaml"
                      className="font-mono"
                      hint="File paths are not supported in the UI."
                    />
                  </div>
                </>
              )}

              {step === 2 && inspect && (
                <>
                  <p className="mt-2 text-sm text-muted">
                    We fetched and parsed your spec. Choose a source name.
                  </p>

                  <div className="mt-6 space-y-4">
                    <Input
                      label="Source name"
                      value={sourceId}
                      onChange={(e) => setSourceId(e.target.value)}
                      placeholder="my_openapi_source"
                      className="font-mono"
                    />

                    <div className="rounded-lg border border-edge bg-well p-4">
                      <div className="eyebrow">Inferred base URL</div>
                      <div className="mt-2 break-all font-mono text-xs text-fg">
                        {inspect.inferredBaseUrl}
                      </div>
                      <div className="mt-2 text-xs text-faint">
                        This is used for tool calls. You can adjust it after creation.
                      </div>
                    </div>
                  </div>
                </>
              )}

              {step === 3 && inspect && (
                <>
                  <p className="mt-2 text-sm text-muted">Tools discovered from your spec.</p>
                  <div className="mt-6 overflow-hidden rounded-lg border border-edge bg-well">
                    <div className="flex items-center justify-between border-b border-edge px-4 py-3">
                      <div className="eyebrow">{inspect.tools.length} tools</div>
                    </div>
                    <div className="max-h-[420px] divide-y divide-edge overflow-y-auto">
                      {inspect.tools.slice(0, 200).map((t) => (
                        <div key={t.name} className="px-4 py-3">
                          <div className="font-mono text-sm font-medium text-accent">{t.name}</div>
                          {t.description ? (
                            <div className="mt-1 text-xs text-faint">{t.description}</div>
                          ) : null}
                        </div>
                      ))}
                      {inspect.tools.length > 200 ? (
                        <div className="px-4 py-3 text-xs text-faint">Showing first 200 tools.</div>
                      ) : null}
                    </div>
                  </div>
                </>
              )}

              {step === 4 && inspect && (
                <>
                  <p className="mt-2 text-sm text-muted">Ready to create the source.</p>
                  <div className="mt-6 grid gap-3">
                    <div className="rounded-lg border border-edge bg-well p-4">
                      <div className="eyebrow">Source name</div>
                      <div className="mt-1 break-all font-mono text-sm font-semibold text-fg">
                        {sourceId.trim()}
                      </div>
                    </div>
                    <div className="rounded-lg border border-edge bg-well p-4">
                      <div className="eyebrow">Spec URL</div>
                      <div className="mt-1 break-all font-mono text-xs text-fg">
                        {specUrl.trim()}
                      </div>
                    </div>
                    <div className="rounded-lg border border-edge bg-well p-4">
                      <div className="eyebrow">Inferred base URL</div>
                      <div className="mt-1 break-all font-mono text-xs text-fg">
                        {inspect.inferredBaseUrl}
                      </div>
                    </div>
                    <div className="rounded-lg border border-edge bg-well p-4">
                      <div className="eyebrow">Tools discovered</div>
                      <div className="mt-1 font-mono text-sm font-semibold text-fg">
                        {inspect.tools.length}
                      </div>
                      <div className="mt-2 text-xs text-faint">
                        After creation, you can tune discovery/auth and other settings in the
                        editor.
                      </div>
                    </div>
                  </div>
                </>
              )}
            </div>

            <div className="flex items-center justify-between gap-3 border-t border-edge px-6 py-4">
              <Button type="button" variant="ghost" onClick={abort} disabled={busy}>
                Abort
              </Button>

              <div className="flex items-center gap-2">
                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => setStep((s) => (s > 1 ? ((s - 1) as Step) : s))}
                  disabled={busy || step === 1}
                >
                  Back
                </Button>

                {step === 1 ? (
                  <Button type="button" onClick={runInspect} loading={busy}>
                    Next
                  </Button>
                ) : step === 2 ? (
                  <Button type="button" onClick={validateIdAndContinue} loading={busy}>
                    Next
                  </Button>
                ) : step === 3 ? (
                  <Button type="button" onClick={goToConfirm} disabled={busy}>
                    Next
                  </Button>
                ) : (
                  <Button type="button" onClick={create} loading={busy} disabled={!inspect}>
                    Create source
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
