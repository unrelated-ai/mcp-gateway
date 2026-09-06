"use client";

import { useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { ProfileSurface } from "@/src/lib/tenantApi";
import type { Profile, ToolPolicy } from "@/src/lib/types";
import * as tenantApi from "@/src/lib/tenantApi";
import { qk } from "@/src/lib/queryKeys";
import { useAutosave } from "@/src/lib/useAutosave";
import { SaveStatus } from "@/components/ui/save-status";
import { ToolTimeoutCard } from "./tool-timeout-card";
import { Badge, Button, Card, Input, Modal, ModalActions, Tabs, Toggle } from "@/components/ui";
import { ToolPolicyEditor } from "./tool-policy-editor";
import {
  ToolTransformEditor,
  normalizePipeline,
  type TransformPipeline,
} from "./tool-transform-editor";

function stablePolicies(ps: ToolPolicy[]): ToolPolicy[] {
  return [...ps].sort((a, b) => a.tool.localeCompare(b.tool));
}

function ToolName({
  name,
  originalName,
  isRenamed,
  enabled,
}: {
  name: string;
  originalName: string;
  isRenamed: boolean;
  enabled: boolean;
}) {
  const title = isRenamed ? `${name} (original: ${originalName})` : name;
  return (
    <div className="min-w-0 flex items-center gap-2">
      {!enabled ? (
        <span aria-hidden="true" className="size-1.5 shrink-0 rounded-[1px] bg-faint/60" />
      ) : null}
      <code
        title={title}
        className={`min-w-0 truncate text-sm font-semibold ${
          enabled ? "text-accent" : "text-muted"
        }`}
      >
        {name}
        {isRenamed ? (
          <span className="text-xs font-medium text-faint"> ({originalName})</span>
        ) : null}
      </code>
    </div>
  );
}

function ToolRow({
  tool,
  selected,
  onClick,
  onToggleEnabled,
  togglingDisabled,
}: {
  tool: ProfileSurface["allTools"][number];
  selected: boolean;
  onClick: () => void;
  onToggleEnabled: (enabled: boolean) => void;
  togglingDisabled: boolean;
}) {
  const isRenamed = tool.baseName !== tool.originalName;
  return (
    <div
      onClick={onClick}
      role="button"
      tabIndex={0}
      title={`${tool.sourceId}:${tool.originalName}`}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") onClick();
      }}
      className={`w-full cursor-pointer border-b border-edge px-4 py-3 text-left transition-colors duration-150 hover:bg-raised/50 ${
        selected ? "bg-raised" : ""
      }`}
    >
      <div
        className={`flex items-center justify-between gap-4 ${tool.enabled ? "" : "opacity-70"}`}
      >
        <div className="min-w-0">
          <ToolName
            name={tool.name}
            originalName={tool.originalName}
            isRenamed={isRenamed}
            enabled={tool.enabled}
          />
        </div>

        <div className="shrink-0" onClick={(e) => e.stopPropagation()}>
          <Toggle
            checked={tool.enabled}
            disabled={togglingDisabled}
            onChange={(checked) => onToggleEnabled(checked)}
          />
        </div>
      </div>
    </div>
  );
}

export function ToolsNewTab({
  profile,
  surface,
  surfaceError,
  probePending,
  onProbe,
  toolsPending,
  onSetToolEnabled,
}: {
  profile: Profile | null;
  surface: ProfileSurface | null;
  surfaceError: string | null;
  probePending: boolean;
  onProbe: () => void;
  toolsPending: boolean;
  onSetToolEnabled: (toolRef: string, enabled: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const [rightTab, setRightTab] = useState<"transforms" | "policies">("transforms");
  const [search, setSearch] = useState("");
  const [showDisabledTools, setShowDisabledTools] = useState(true);
  const [showPoliciesHelp, setShowPoliciesHelp] = useState(false);

  const allTools = useMemo(() => surface?.allTools ?? [], [surface]);
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    const base = showDisabledTools ? allTools : allTools.filter((t) => t.enabled);
    if (!q) return base;
    return base.filter(
      (t) =>
        t.name.toLowerCase().includes(q) ||
        t.sourceId.toLowerCase().includes(q) ||
        t.originalName.toLowerCase().includes(q) ||
        t.baseName.toLowerCase().includes(q),
    );
  }, [allTools, search, showDisabledTools]);

  const [selectedKey, setSelectedKey] = useState<string>(() => {
    const first = allTools[0];
    return first ? `${first.sourceId}:${first.originalName}` : "";
  });

  // Derive initial selection from the probed surface (no setState-in-effect).
  const firstKey = useMemo(() => {
    const first = allTools[0];
    return first ? `${first.sourceId}:${first.originalName}` : "";
  }, [allTools]);

  const effectiveSelectedKey = selectedKey || firstKey;

  const selected = useMemo(() => {
    return allTools.find((t) => `${t.sourceId}:${t.originalName}` === effectiveSelectedKey) ?? null;
  }, [allTools, effectiveSelectedKey]);

  // ---------------------------
  // Transforms pipeline (local) + autosave
  // ---------------------------
  const pipelineFromProfile = useMemo(
    () => normalizePipeline(profile?.transforms ?? {}),
    [profile],
  );
  const [pipeline, setPipeline] = useState<TransformPipeline>(() => pipelineFromProfile);

  const pipelineAutosave = useAutosave<TransformPipeline>(async (nextTransforms) => {
    if (!profile) throw new Error("Profile not loaded");
    await tenantApi.updateProfile(profile.id, { transforms: nextTransforms });
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: qk.profile(profile.id) }),
      queryClient.invalidateQueries({ queryKey: qk.profiles() }),
    ]);
  });

  // ---------------------------
  // Tool policies (local) + autosave
  // ---------------------------
  const policiesFromProfile = useMemo(() => profile?.toolPolicies ?? [], [profile]);
  const [policies, setPolicies] = useState<ToolPolicy[]>(() => policiesFromProfile);
  const policiesByToolRef = useMemo(() => {
    return new Map<string, ToolPolicy>(stablePolicies(policies).map((p) => [p.tool, p]));
  }, [policies]);
  const [toolPoliciesError, setToolPoliciesError] = useState<string | null>(null);

  const knownToolRefs = useMemo(() => {
    return new Set(allTools.map((t) => `${t.sourceId}:${t.originalName}`));
  }, [allTools]);
  const unknownPolicies = useMemo(() => {
    return stablePolicies(policies).filter((p) => !knownToolRefs.has(p.tool));
  }, [knownToolRefs, policies]);

  const savePoliciesMutation = useMutation({
    mutationFn: async (nextPolicies: ToolPolicy[]) => {
      const stable = stablePolicies(nextPolicies);
      const seen = new Set<string>();
      for (const p of stable) {
        if (seen.has(p.tool)) throw new Error(`Duplicate tool policy for '${p.tool}'.`);
        seen.add(p.tool);
      }
      if (!profile) throw new Error("Profile not loaded");
      await tenantApi.updateProfile(profile.id, { toolPolicies: stable });
      return stable;
    },
    onSuccess: async (toolPolicies) => {
      if (!profile) return;
      await queryClient.invalidateQueries({ queryKey: qk.profile(profile.id) });
      await queryClient.invalidateQueries({ queryKey: qk.profiles() });
      queryClient.setQueryData(qk.profile(profile.id), (old: Profile | undefined) => {
        if (!old) return old;
        return { ...old, toolPolicies };
      });
      setToolPoliciesError(null);
    },
    onError: (e) => {
      const msg = e instanceof Error ? e.message : "Failed to save tool policies";
      setToolPoliciesError(
        msg.includes("502") || msg.toLowerCase().includes("bad gateway")
          ? "Gateway is temporarily unavailable (502). Try again in a moment."
          : msg,
      );
    },
  });

  const savePolicy = (p: ToolPolicy) => {
    const prev = policies;
    const next = stablePolicies([...prev.filter((x) => x.tool !== p.tool), p]);
    setPolicies(next);
    savePoliciesMutation.mutate(next, { onError: () => setPolicies(prev) });
  };

  const clearPolicy = (stableToolRef: string) => {
    const prev = policies;
    const next = stablePolicies(prev.filter((p) => p.tool !== stableToolRef));
    setPolicies(next);
    savePoliciesMutation.mutate(next, { onError: () => setPolicies(prev) });
  };

  const removeUnknownPolicy = (toolRef: string) => {
    clearPolicy(toolRef);
  };

  return (
    <div className="space-y-6">
      {profile ? <ToolTimeoutCard key={profile.id} profile={profile} /> : null}
      <SaveStatus {...pipelineAutosave} onRetry={pipelineAutosave.retry} label="Tool transforms" />

      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-start justify-between gap-3 border-b border-edge px-5 py-3.5">
          <div className="min-w-0">
            <div className="eyebrow">Tool list</div>
            <div className="mt-1 text-sm text-muted">
              Probe once, then configure transforms and call policies per tool.
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Toggle
              checked={showDisabledTools}
              onChange={setShowDisabledTools}
              label={showDisabledTools ? "All tools" : "Enabled only"}
              description={showDisabledTools ? "Shows enabled + disabled" : "Hides disabled tools"}
              switchSide="right"
            />
            <Button variant="secondary" onClick={onProbe} loading={probePending}>
              {probePending ? "Probing…" : "Probe surface"}
            </Button>
          </div>
        </div>

        {surfaceError ? (
          <div className="border-b border-edge bg-danger/5 px-5 py-4 text-sm text-danger">
            {surfaceError}
          </div>
        ) : null}

        {!surface ? (
          <div className="p-5 text-sm text-muted">
            Run a probe to discover tools before configuring this page.
          </div>
        ) : allTools.length === 0 ? (
          <div className="p-5 text-sm text-muted">No tools discovered.</div>
        ) : (
          <div className="grid xl:grid-cols-[300px_minmax(0,1fr)]">
            <div className="border-r border-edge">
              <div className="border-b border-edge px-4 py-3 text-xs text-faint">
                Tools: <span className="font-mono text-fg">{surface.tools.length}</span>
                <span className="font-mono text-faint"> / {surface.allTools.length}</span>
              </div>
              <div className="border-b border-edge p-4">
                <Input
                  aria-label="Search tools"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search tools…"
                />
              </div>
              <div className="max-h-[620px] overflow-y-auto">
                {filtered.map((t) => {
                  const key = `${t.sourceId}:${t.originalName}`;
                  const isSelected = key === effectiveSelectedKey;
                  const stableRef = key;
                  return (
                    <ToolRow
                      key={key}
                      tool={t}
                      selected={isSelected}
                      togglingDisabled={toolsPending}
                      onClick={() => setSelectedKey(key)}
                      onToggleEnabled={(enabled) => onSetToolEnabled(stableRef, enabled)}
                    />
                  );
                })}
              </div>
            </div>

            <div className="p-5 space-y-4">
              {selected ? (
                <div className="rounded-lg border border-edge bg-well p-4">
                  <div className="eyebrow">Selected tool</div>
                  <div className="mt-2 flex items-center gap-2 min-w-0">
                    <code className="min-w-0 truncate text-sm font-semibold text-fg">
                      {selected.name}
                    </code>
                    <Badge className="normal-case">{selected.sourceId}</Badge>
                  </div>
                  {selected.baseName !== selected.originalName ? (
                    <div className="mt-2 text-xs text-faint">
                      original:{" "}
                      <span className="font-mono text-muted">{selected.originalName}</span>
                    </div>
                  ) : null}
                </div>
              ) : null}

              <div className="relative">
                <Tabs
                  items={[
                    {
                      value: "transforms" as const,
                      label: (
                        <span className="inline-flex items-center gap-2">
                          Transforms
                          <Badge tone="accent">Beta</Badge>
                        </span>
                      ),
                    },
                    { value: "policies" as const, label: "Policies" },
                  ]}
                  value={rightTab}
                  onChange={setRightTab}
                />
                {rightTab === "policies" ? (
                  <div className="absolute right-0 top-1/2 -translate-y-1/2">
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => setShowPoliciesHelp(true)}
                      aria-label="Tool call policies help"
                    >
                      Help
                    </Button>
                  </div>
                ) : null}
              </div>

              {!selected ? (
                <div className="text-sm text-muted">Select a tool to configure it.</div>
              ) : rightTab === "transforms" ? (
                <ToolTransformEditor
                  key={`${selected.sourceId}:${selected.originalName}`}
                  tool={selected}
                  pipeline={pipeline}
                  onCommitPipeline={(next) => {
                    setPipeline(next);
                    pipelineAutosave.commit(next);
                  }}
                  onDirty={pipelineAutosave.edit}
                  toolsPending={toolsPending}
                  enabled={selected.enabled}
                />
              ) : (
                <ToolPolicyEditor
                  key={`${selected.sourceId}:${selected.originalName}`}
                  tool={selected}
                  policiesByToolRef={policiesByToolRef}
                  saveError={toolPoliciesError}
                  clearSaveError={() => setToolPoliciesError(null)}
                  onSave={savePolicy}
                />
              )}
            </div>
          </div>
        )}
      </Card>

      {surface && unknownPolicies.length > 0 ? (
        <Card className="overflow-hidden">
          <div className="border-b border-edge px-5 py-3.5">
            <div className="eyebrow">Policies not in current surface</div>
            <div className="mt-1 text-sm text-muted">
              These policies don’t match any currently discovered tool. They won’t apply until the
              surface matches again.
            </div>
          </div>
          <div className="divide-y divide-edge">
            {unknownPolicies.map((p) => (
              <div key={p.tool} className="p-5 flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="font-mono text-sm text-fg break-all">{p.tool}</div>
                  <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-faint">
                    <span>
                      timeout:{" "}
                      <span className="text-muted">
                        {typeof p.timeoutSecs === "number" ? `${p.timeoutSecs}s` : "default"}
                      </span>
                    </span>
                    <span aria-hidden="true" className="size-1 rounded-full bg-edge-strong" />
                    <span>
                      retry:{" "}
                      <span className="text-muted">
                        {p.retry ? `${p.retry.maximumAttempts} attempts` : "off"}
                      </span>
                    </span>
                  </div>
                </div>
                <Button
                  type="button"
                  variant="danger"
                  size="sm"
                  onClick={() => removeUnknownPolicy(p.tool)}
                >
                  Remove
                </Button>
              </div>
            ))}
          </div>
        </Card>
      ) : null}

      <Modal
        open={showPoliciesHelp}
        onClose={() => setShowPoliciesHelp(false)}
        title="Tool call policies"
        size="lg"
      >
        <div className="space-y-4 text-sm text-muted">
          <p>
            Tool call policies control how the Gateway executes{" "}
            <span className="font-mono">tools/call</span> for this profile.
          </p>
          <ul className="list-disc pl-5 space-y-1">
            <li>
              <span className="font-semibold text-fg">Default timeout</span>: applies when a tool
              has no per-tool override.
            </li>
            <li>
              <span className="font-semibold text-fg">Per-tool timeout</span>: overrides the default
              for a single tool.
            </li>
            <li>
              <span className="font-semibold text-fg">Retry policy</span>: Gateway-side retries for
              transient failures. Use conservative values to avoid duplicate side effects.
            </li>
            <li>
              <span className="font-semibold text-fg">Stable tool identity</span>: policies are
              keyed by{" "}
              <span className="font-mono">&lt;source_id&gt;:&lt;original_tool_name&gt;</span> so
              transforms/renames won’t break your settings.
            </li>
            <li>
              <span className="font-semibold text-fg">Timeout cap</span>: the Gateway enforces a
              maximum timeout. Admins can raise it via{" "}
              <span className="font-mono">UNRELATED_TOOL_CALL_TIMEOUT_MAX_SECS</span>.
            </li>
          </ul>
        </div>
        <ModalActions>
          <Button type="button" onClick={() => setShowPoliciesHelp(false)}>
            Close
          </Button>
        </ModalActions>
      </Modal>
    </div>
  );
}
