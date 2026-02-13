"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import { Badge, Button, Toggle } from "@/components/ui";
import { qk } from "@/src/lib/queryKeys";
import * as tenantApi from "@/src/lib/tenantApi";
import { useToastStore } from "@/src/lib/toast-store";

type StepKey = "details" | "upstreams" | "sources";

type Draft = {
  name: string;
  description: string;
  allowPartialUpstreams: boolean;
  upstreams: string[];
  sources: string[];
};

function normalizeIdList(list: string[]) {
  return [...new Set(list)].sort((a, b) => a.localeCompare(b));
}

export default function NewProfileWizardPage() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const pushToast = useToastStore((s) => s.push);

  const [draft, setDraft] = useState<Draft>({
    name: "",
    description: "",
    allowPartialUpstreams: true,
    upstreams: [],
    sources: [],
  });
  const [activeStep, setActiveStep] = useState<StepKey>("details");
  const [error, setError] = useState<string | null>(null);

  const upstreamsQuery = useQuery({
    queryKey: qk.upstreams(),
    queryFn: tenantApi.listUpstreams,
  });
  const toolSourcesQuery = useQuery({
    queryKey: qk.toolSources(),
    queryFn: tenantApi.listToolSources,
  });

  const upstreams = upstreamsQuery.data?.upstreams ?? [];
  const toolSources = toolSourcesQuery.data?.sources ?? [];

  const steps = useMemo(() => {
    const out: StepKey[] = ["details"];
    if (upstreams.length > 0) out.push("upstreams");
    if (toolSources.length > 0) out.push("sources");
    return out;
  }, [upstreams.length, toolSources.length]);

  const stepIndex = steps.indexOf(activeStep);
  const stepNumber = stepIndex >= 0 ? stepIndex + 1 : 1;
  const stepTotal = steps.length;

  const canAdvanceFromDetails =
    !!draft.name.trim() && !upstreamsQuery.isPending && !toolSourcesQuery.isPending;

  const createMutation = useMutation({
    mutationFn: async () => {
      const name = draft.name.trim();
      if (!name) throw new Error("Name is required.");
      const description = draft.description.trim();

      const resp = await tenantApi.createProfile({
        name,
        description: description ? description : undefined,
        enabled: true,
        allowPartialUpstreams: draft.allowPartialUpstreams,
        dataPlaneAuth: { mode: "apiKeyEveryRequest", acceptXApiKey: false },
        upstreams: normalizeIdList(draft.upstreams),
        sources: normalizeIdList(draft.sources),
      });
      return resp.id;
    },
    onSuccess: async (id) => {
      await queryClient.invalidateQueries({ queryKey: qk.profiles() });
      pushToast({ variant: "success", message: "Profile created" });
      // Replace so browser-back doesn't land inside the wizard.
      router.replace(`/profiles/${encodeURIComponent(id)}`);
    },
    onError: (e) => {
      setError(e instanceof Error ? e.message : "Failed to create profile");
    },
  });

  const abort = () => router.push("/profiles");

  const goBack = () => {
    const idx = steps.indexOf(activeStep);
    if (idx <= 0) return;
    setError(null);
    setActiveStep(steps[idx - 1] ?? "details");
  };

  const goNext = () => {
    const idx = steps.indexOf(activeStep);
    if (idx < 0) return;
    const next = steps[idx + 1];
    if (!next) return;
    setError(null);
    setActiveStep(next);
  };

  const nextLabel = activeStep === steps[steps.length - 1] ? "Create" : "Next";

  const primaryDisabled =
    createMutation.isPending || (activeStep === "details" ? !canAdvanceFromDetails : false);

  const primaryAction = () => {
    setError(null);
    if (activeStep === steps[steps.length - 1]) {
      createMutation.mutate();
      return;
    }
    goNext();
  };

  const title =
    activeStep === "details" ? "Basics" : activeStep === "upstreams" ? "Upstreams" : "Tool sources";

  return (
    <AppShell>
      <PageHeader
        title="Create profile"
        description="Step-by-step setup. You can adjust advanced settings after creation."
        breadcrumb={[{ label: "Profiles", href: "/profiles" }, { label: "New profile" }]}
      />

      <PageContent>
        <div className="min-h-[70vh] flex items-start justify-center pt-6">
          <div className="w-full max-w-2xl">
            <div className="rounded-2xl border border-zinc-800/80 bg-zinc-900/60 backdrop-blur-sm overflow-hidden">
              <div className="p-8">
                <div className="flex items-center justify-between gap-4">
                  <div className="text-sm text-zinc-400">
                    Step {stepNumber} of {stepTotal}
                  </div>
                </div>

                <h1 className="mt-4 text-xl sm:text-2xl font-semibold text-white tracking-tight">
                  {title}
                </h1>

                {error ? (
                  <div className="mt-5 rounded-xl bg-red-500/5 border border-red-500/20 p-4 text-sm text-red-300">
                    <div className="font-medium">Could not continue</div>
                    <div className="mt-1 text-xs text-red-300/80 break-words whitespace-pre-wrap">
                      {error}
                    </div>
                  </div>
                ) : null}

                {activeStep === "details" ? (
                  <>
                    <p className="mt-3 text-base text-zinc-400 max-w-2xl">
                      Give the profile a name and choose whether it should tolerate missing
                      upstreams.
                    </p>

                    {!upstreamsQuery.isPending &&
                    !toolSourcesQuery.isPending &&
                    !upstreamsQuery.error &&
                    !toolSourcesQuery.error &&
                    upstreams.length === 0 &&
                    toolSources.length === 0 ? (
                      <div className="mt-5 rounded-xl border border-zinc-800/80 bg-zinc-950/30 p-4">
                        <div className="text-sm font-medium text-zinc-200">No sources yet</div>
                        <div className="mt-1 text-xs text-zinc-500">
                          This profile will be created with no upstreams or tool sources attached,
                          so it won’t expose any tools until you add at least one source.
                        </div>
                        <div className="mt-3 flex flex-wrap items-center gap-2">
                          <Button
                            type="button"
                            variant="secondary"
                            onClick={() => router.push("/sources")}
                          >
                            Go to Sources
                          </Button>
                          <Button
                            type="button"
                            variant="ghost"
                            onClick={() => router.push("/sources/new/openapi")}
                          >
                            Add OpenAPI source
                          </Button>
                          <Button
                            type="button"
                            variant="ghost"
                            onClick={() => router.push("/sources/new/upstream?kind=mcp")}
                          >
                            Add upstream
                          </Button>
                        </div>
                      </div>
                    ) : null}

                    <div className="mt-6 space-y-4">
                      <div>
                        <label className="block text-xs font-medium text-zinc-400 mb-2">Name</label>
                        <input
                          value={draft.name}
                          onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))}
                          placeholder="e.g., Telegram bot"
                          className="w-full h-10 rounded-xl bg-zinc-900 border border-zinc-800 px-3 text-sm text-zinc-200"
                        />
                      </div>

                      <div>
                        <label className="block text-xs font-medium text-zinc-400 mb-2">
                          Description (optional)
                        </label>
                        <input
                          value={draft.description}
                          onChange={(e) => setDraft((d) => ({ ...d, description: e.target.value }))}
                          placeholder="Short note for humans"
                          className="w-full h-10 rounded-xl bg-zinc-900 border border-zinc-800 px-3 text-sm text-zinc-200"
                        />
                      </div>

                      <div className="rounded-xl border border-zinc-800/60 bg-zinc-950/30 p-4">
                        <div className="flex items-center justify-between gap-4">
                          <div>
                            <div className="text-sm font-semibold text-zinc-100">
                              Allow partial upstreams
                            </div>
                            <div className="mt-1 text-xs text-zinc-500">
                              If some upstream endpoints are down, still serve what’s available.
                            </div>
                          </div>
                          <Toggle
                            checked={draft.allowPartialUpstreams}
                            onChange={(checked) =>
                              setDraft((d) => ({ ...d, allowPartialUpstreams: checked }))
                            }
                          />
                        </div>
                      </div>

                      {(upstreamsQuery.isPending || toolSourcesQuery.isPending) && (
                        <div className="text-xs text-zinc-500">
                          Loading upstreams and tool sources…
                        </div>
                      )}
                    </div>
                  </>
                ) : activeStep === "upstreams" ? (
                  <>
                    <p className="mt-3 text-base text-zinc-400 max-w-2xl">
                      Select upstreams to attach to this profile. You can leave this empty and add
                      upstreams later.
                    </p>

                    <div className="mt-6 space-y-3">
                      {upstreams.map((u) => {
                        const selected = draft.upstreams.includes(u.id);
                        return (
                          <div
                            key={`${u.owner}:${u.id}`}
                            onClick={() =>
                              setDraft((d) => ({
                                ...d,
                                upstreams: selected
                                  ? d.upstreams.filter((x) => x !== u.id)
                                  : [...d.upstreams, u.id],
                              }))
                            }
                            className={`w-full text-left rounded-xl border p-4 transition-colors ${
                              selected
                                ? "border-violet-500/30 bg-violet-500/5"
                                : "border-zinc-800/80 bg-zinc-950/30 hover:border-zinc-700/80"
                            }`}
                          >
                            <div className="flex items-start justify-between gap-4">
                              <div className="min-w-0">
                                <div className="font-mono text-sm text-zinc-100 break-all">
                                  {u.id}
                                </div>
                                <div className="mt-1 text-xs text-zinc-500">
                                  owner: {u.owner} • status: {u.enabled ? "enabled" : "disabled"}
                                </div>
                              </div>
                              <div className="flex items-center gap-2 shrink-0">
                                <div className="hidden sm:flex items-center gap-2">
                                  <Badge variant={u.owner === "tenant" ? "violet" : "default"}>
                                    {u.owner === "tenant" ? "tenant" : "global"}
                                  </Badge>
                                </div>
                                <div
                                  onClick={(e) => e.stopPropagation()}
                                  className="flex items-center gap-2"
                                >
                                  <span className="hidden sm:inline text-xs text-zinc-500">
                                    Attach
                                  </span>
                                  <Toggle
                                    checked={selected}
                                    onChange={() =>
                                      setDraft((d) => ({
                                        ...d,
                                        upstreams: selected
                                          ? d.upstreams.filter((x) => x !== u.id)
                                          : [...d.upstreams, u.id],
                                      }))
                                    }
                                  />
                                </div>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                      {upstreams.length === 0 ? (
                        <div className="rounded-xl border border-zinc-800/80 bg-zinc-950/30 p-4 text-sm text-zinc-500">
                          No upstreams exist yet.
                        </div>
                      ) : null}
                    </div>
                  </>
                ) : (
                  <>
                    <p className="mt-3 text-base text-zinc-400 max-w-2xl">
                      Select local tool sources to attach to this profile. You can leave this empty
                      and add sources later.
                    </p>

                    <div className="mt-6 space-y-3">
                      {toolSources.map((s) => {
                        const selected = draft.sources.includes(s.id);
                        return (
                          <div
                            key={s.id}
                            onClick={() =>
                              setDraft((d) => ({
                                ...d,
                                sources: selected
                                  ? d.sources.filter((x) => x !== s.id)
                                  : [...d.sources, s.id],
                              }))
                            }
                            className={`w-full text-left rounded-xl border p-4 transition-colors ${
                              selected
                                ? "border-emerald-500/30 bg-emerald-500/5"
                                : "border-zinc-800/80 bg-zinc-950/30 hover:border-zinc-700/80"
                            }`}
                          >
                            <div className="flex items-start justify-between gap-4">
                              <div className="min-w-0">
                                <div className="font-mono text-sm text-zinc-100 break-all">
                                  {s.id}
                                </div>
                                <div className="mt-1 text-xs text-zinc-500">
                                  type: {s.type} • status: {s.enabled ? "enabled" : "disabled"}
                                </div>
                              </div>
                              <div className="flex items-center gap-2 shrink-0">
                                <div className="hidden sm:flex items-center gap-2">
                                  <Badge variant={s.type === "openapi" ? "success" : "info"}>
                                    {s.type}
                                  </Badge>
                                </div>
                                <div
                                  onClick={(e) => e.stopPropagation()}
                                  className="flex items-center gap-2"
                                >
                                  <span className="hidden sm:inline text-xs text-zinc-500">
                                    Attach
                                  </span>
                                  <Toggle
                                    checked={selected}
                                    onChange={() =>
                                      setDraft((d) => ({
                                        ...d,
                                        sources: selected
                                          ? d.sources.filter((x) => x !== s.id)
                                          : [...d.sources, s.id],
                                      }))
                                    }
                                  />
                                </div>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                      {toolSources.length === 0 ? (
                        <div className="rounded-xl border border-zinc-800/80 bg-zinc-950/30 p-4 text-sm text-zinc-500">
                          No tool sources exist yet.
                        </div>
                      ) : null}
                    </div>
                  </>
                )}
              </div>

              <div className="border-t border-zinc-800/80 bg-zinc-900/40 p-6 flex items-center justify-between gap-3">
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
                    onClick={goBack}
                    disabled={createMutation.isPending || activeStep === "details"}
                  >
                    Back
                  </Button>
                  <Button
                    type="button"
                    onClick={primaryAction}
                    loading={createMutation.isPending && activeStep === steps[steps.length - 1]}
                    disabled={primaryDisabled}
                  >
                    {nextLabel}
                  </Button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </PageContent>
    </AppShell>
  );
}
