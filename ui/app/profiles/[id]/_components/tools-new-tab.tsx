"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { ProfileSurface } from "@/src/lib/tenantApi";
import type { Profile, ToolPolicy } from "@/src/lib/types";
import * as tenantApi from "@/src/lib/tenantApi";
import { qk } from "@/src/lib/queryKeys";
import { buildPutProfileBody } from "@/src/lib/profilePut";
import { useQueuedAutosave } from "@/src/lib/useQueuedAutosave";
import { Button, Input, Modal, ModalActions, Toggle } from "@/components/ui";
import { ToolPolicyEditor } from "./tool-policy-editor";
import {
  ToolTransformEditor,
  normalizePipeline,
  stableStringifyPipeline,
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
        <span className="inline-block w-2 h-2 rounded-full bg-zinc-600 shrink-0" />
      ) : null}
      <code
        title={title}
        className={`min-w-0 truncate text-sm font-semibold ${
          enabled ? "text-violet-400" : "text-zinc-400"
        }`}
      >
        {name}
        {isRenamed ? (
          <span className="text-xs font-medium text-zinc-500"> ({originalName})</span>
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
      className={`w-full text-left px-4 py-3 border-b border-zinc-800/40 hover:bg-zinc-800/20 transition-colors cursor-pointer ${
        selected ? "bg-zinc-800/25" : ""
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
  const autosaveCooldownUntilRef = useRef<number>(0);
  const shouldSkipAutosave = () => Date.now() < autosaveCooldownUntilRef.current;
  const applyAutosaveCooldownFromError = (msg: string) => {
    if (msg.includes("502") || msg.toLowerCase().includes("bad gateway")) {
      autosaveCooldownUntilRef.current = Date.now() + 3000;
    }
  };

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

  // ---------------------------
  // Default tool call timeout
  // ---------------------------
  const initialTimeout = profile?.toolCallTimeoutSecs ?? null;
  const [timeoutSecsText, setTimeoutSecsText] = useState(() =>
    initialTimeout != null ? String(initialTimeout) : "",
  );
  const [timeoutError, setTimeoutError] = useState<string | null>(null);

  const saveTimeoutMutation = useMutation({
    mutationFn: async (toolCallTimeoutSecs: number | null) => {
      if (!profile) throw new Error("Profile not loaded");
      await tenantApi.putProfile(
        profile.id,
        buildPutProfileBody(profile, { transforms: pipeline, toolCallTimeoutSecs }),
      );
      return toolCallTimeoutSecs;
    },
    onSuccess: async (toolCallTimeoutSecs) => {
      if (!profile) return;
      await queryClient.invalidateQueries({ queryKey: qk.profile(profile.id) });
      await queryClient.invalidateQueries({ queryKey: qk.profiles() });
      queryClient.setQueryData(qk.profile(profile.id), (old: Profile | undefined) => {
        if (!old) return old;
        return { ...old, toolCallTimeoutSecs };
      });
      setTimeoutError(null);
    },
    onError: (e) => {
      const msg = e instanceof Error ? e.message : "Failed to save default timeout";
      const m = msg.match(/toolCallTimeoutSecs must be <= (\\d+)/);
      if (m && m[1]) {
        setTimeoutError(
          `Too large: max is ${m[1]}s (Gateway cap). Ask your admin to raise UNRELATED_TOOL_CALL_TIMEOUT_MAX_SECS if you need longer calls.`,
        );
      } else if (msg.includes("502") || msg.toLowerCase().includes("bad gateway")) {
        setTimeoutError("Gateway is temporarily unavailable (502). Try again in a moment.");
      } else {
        setTimeoutError("Could not save timeout. Please try again.");
      }
      applyAutosaveCooldownFromError(msg);
    },
  });

  const commitTimeout = () => {
    if (shouldSkipAutosave()) return;
    const raw = timeoutSecsText.trim();
    if (!raw) {
      saveTimeoutMutation.mutate(null);
      return;
    }
    const n = Number(raw);
    if (!Number.isFinite(n) || n <= 0 || !Number.isInteger(n)) {
      setTimeoutError("Timeout must be a positive integer");
      return;
    }
    saveTimeoutMutation.mutate(n);
  };

  const saveTransformsMutation = useMutation({
    mutationFn: async (nextTransforms: unknown) => {
      if (!profile) throw new Error("Profile not loaded");
      await tenantApi.putProfile(
        profile.id,
        buildPutProfileBody(profile, { transforms: nextTransforms }),
      );
      return nextTransforms;
    },
    onSuccess: async (nextTransforms) => {
      if (!profile) return;
      await queryClient.invalidateQueries({ queryKey: qk.profile(profile.id) });
      await queryClient.invalidateQueries({ queryKey: qk.profiles() });
      queryClient.setQueryData(qk.profile(profile.id), (old: Profile | undefined) => {
        if (!old) return old;
        return { ...old, transforms: nextTransforms };
      });
    },
    onError: (e) => {
      const msg = e instanceof Error ? e.message : "Failed to save transforms";
      applyAutosaveCooldownFromError(msg);
    },
  });

  const pipelineKey = useCallback((p: TransformPipeline) => stableStringifyPipeline(p), []);
  const pipelineAutosave = useQueuedAutosave<TransformPipeline>({
    isPending: saveTransformsMutation.isPending,
    mutate: (p) => saveTransformsMutation.mutate(p),
    computeKey: pipelineKey,
  });

  useEffect(() => {
    // Keep the server fingerprint updated; avoid setState-in-effect.
    pipelineAutosave.setLastSavedKey(stableStringifyPipeline(pipelineFromProfile));
  }, [pipelineAutosave, pipelineFromProfile]);

  const commitPipeline = useCallback(
    (next: TransformPipeline) => {
      if (!profile) return;
      if (shouldSkipAutosave()) return;
      pipelineAutosave.commit(next);
    },
    [pipelineAutosave, profile],
  );

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

  useEffect(() => {
    // Mirror server updates into the local state without using setState-in-effect lint.
    // This component is keyed by profile id in the parent, so this is mostly a safety net.
  }, [policiesFromProfile]);

  const savePoliciesMutation = useMutation({
    mutationFn: async (nextPolicies: ToolPolicy[]) => {
      const stable = stablePolicies(nextPolicies);
      const seen = new Set<string>();
      for (const p of stable) {
        if (seen.has(p.tool)) throw new Error(`Duplicate tool policy for '${p.tool}'.`);
        seen.add(p.tool);
      }
      if (!profile) throw new Error("Profile not loaded");
      await tenantApi.putProfile(
        profile.id,
        buildPutProfileBody(profile, { transforms: pipeline, toolPolicies: stable }),
      );
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
      applyAutosaveCooldownFromError(msg);
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
      <div className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 p-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="text-sm font-semibold text-zinc-100">Default tool call timeout</div>
            <div className="mt-1 text-xs text-zinc-500">
              Applies to <span className="font-mono">tools/call</span> when a tool policy does not
              override timeout. Leave empty to use the Gateway default.
            </div>
          </div>
        </div>

        <div className="mt-4 space-y-2">
          <Input
            label="Timeout (seconds)"
            inputMode="numeric"
            placeholder={initialTimeout != null ? String(initialTimeout) : "e.g. 30"}
            value={timeoutSecsText}
            onChange={(e) => {
              setTimeoutError(null);
              setTimeoutSecsText(e.target.value);
            }}
            onBlur={commitTimeout}
            onKeyDown={(e) => {
              if (e.key === "Enter") (e.target as HTMLInputElement).blur();
            }}
            error={timeoutError ?? undefined}
            hint={
              timeoutError
                ? undefined
                : "Clearing this field removes the override (reverting to the Gateway default)."
            }
          />
        </div>
      </div>

      <div className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 overflow-hidden">
        <div className="px-5 py-3 border-b border-zinc-800/60 flex items-center justify-between gap-3">
          <div>
            <div className="text-sm font-medium text-zinc-300">Tool list</div>
            <div className="mt-1 text-xs text-zinc-500">
              Probe once, then configure transforms and call policies per tool.
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Toggle
              checked={showDisabledTools}
              onChange={setShowDisabledTools}
              label={showDisabledTools ? "All tools" : "Enabled only"}
              description={showDisabledTools ? "Shows enabled + disabled" : "Hides disabled tools"}
              switchSide="right"
            />
            <button
              onClick={onProbe}
              disabled={probePending}
              className="px-4 py-2 rounded-lg bg-zinc-800 text-zinc-200 text-sm font-medium hover:bg-zinc-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {probePending ? "Probing…" : "Probe surface"}
            </button>
          </div>
        </div>

        {surfaceError ? (
          <div className="px-5 py-4 text-sm text-red-200 border-b border-zinc-800/60 bg-red-500/5">
            {surfaceError}
          </div>
        ) : null}

        {!surface ? (
          <div className="p-5 text-sm text-zinc-500">
            Run a probe to discover tools before configuring this page.
          </div>
        ) : allTools.length === 0 ? (
          <div className="p-5 text-sm text-zinc-500">No tools discovered.</div>
        ) : (
          <div className="grid md:grid-cols-[340px_1fr]">
            <div className="border-r border-zinc-800/60">
              <div className="px-4 py-3 border-b border-zinc-800/60 text-xs text-zinc-500">
                Tools: <span className="text-zinc-200">{surface.tools.length}</span>
                <span className="text-zinc-500"> / {surface.allTools.length}</span>
              </div>
              <div className="p-4 border-b border-zinc-800/60">
                <Input
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
                <div className="rounded-xl border border-zinc-800/60 bg-zinc-950/30 p-4">
                  <div className="text-xs text-zinc-500">Selected tool</div>
                  <div className="mt-2 flex items-center gap-2 min-w-0">
                    <code className="min-w-0 truncate text-sm font-semibold text-zinc-100">
                      {selected.name}
                    </code>
                    <span className="shrink-0 px-2 py-0.5 rounded-full text-[11px] font-medium bg-zinc-800/60 text-zinc-300 border border-zinc-700/40">
                      <span className="font-mono">{selected.sourceId}</span>
                    </span>
                  </div>
                  {selected.baseName !== selected.originalName ? (
                    <div className="mt-2 text-xs text-zinc-500">
                      original:{" "}
                      <span className="font-mono text-zinc-300">{selected.originalName}</span>
                    </div>
                  ) : null}
                </div>
              ) : null}

              <div className="flex items-center gap-1 border-b border-zinc-800/60">
                <button
                  type="button"
                  onClick={() => setRightTab("transforms")}
                  className={`px-3 py-2 text-sm font-medium transition-colors relative ${
                    rightTab === "transforms" ? "text-white" : "text-zinc-500 hover:text-zinc-300"
                  }`}
                >
                  <span className="inline-flex items-center gap-2">
                    Transforms
                    <span className="px-1.5 py-0.5 rounded-md text-[10px] font-semibold bg-violet-500/10 text-violet-300 border border-violet-500/20">
                      Beta
                    </span>
                  </span>
                  {rightTab === "transforms" && (
                    <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-violet-500 rounded-full" />
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => setRightTab("policies")}
                  className={`px-3 py-2 text-sm font-medium transition-colors relative ${
                    rightTab === "policies" ? "text-white" : "text-zinc-500 hover:text-zinc-300"
                  }`}
                >
                  Policies
                  {rightTab === "policies" && (
                    <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-violet-500 rounded-full" />
                  )}
                </button>
                <div className="flex-1" />
                {rightTab === "policies" ? (
                  <button
                    type="button"
                    onClick={() => setShowPoliciesHelp(true)}
                    className="inline-flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60 transition-colors"
                    aria-label="Tool call policies help"
                  >
                    Help
                  </button>
                ) : null}
              </div>

              {!selected ? (
                <div className="text-sm text-zinc-500">Select a tool to configure it.</div>
              ) : rightTab === "transforms" ? (
                <ToolTransformEditor
                  key={`${selected.sourceId}:${selected.originalName}`}
                  tool={selected}
                  pipeline={pipeline}
                  onCommitPipeline={(next) => {
                    setPipeline(next);
                    commitPipeline(next);
                  }}
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
      </div>

      {surface && unknownPolicies.length > 0 ? (
        <div className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 overflow-hidden">
          <div className="px-5 py-3 border-b border-zinc-800/60">
            <div className="text-sm font-medium text-zinc-300">Policies not in current surface</div>
            <div className="mt-1 text-xs text-zinc-500">
              These policies don’t match any currently discovered tool. They won’t apply until the
              surface matches again.
            </div>
          </div>
          <div className="divide-y divide-zinc-800/40">
            {unknownPolicies.map((p) => (
              <div key={p.tool} className="p-5 flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="font-mono text-sm text-zinc-100 break-all">{p.tool}</div>
                  <div className="mt-2 text-xs text-zinc-500 flex flex-wrap items-center gap-2">
                    <span>
                      timeout:{" "}
                      <span className="text-zinc-200">
                        {typeof p.timeoutSecs === "number" ? `${p.timeoutSecs}s` : "default"}
                      </span>
                    </span>
                    <span className="w-1 h-1 rounded-full bg-zinc-700" />
                    <span>
                      retry:{" "}
                      <span className="text-zinc-200">
                        {p.retry ? `${p.retry.maximumAttempts} attempts` : "off"}
                      </span>
                    </span>
                  </div>
                </div>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => removeUnknownPolicy(p.tool)}
                  className="text-red-400 hover:text-red-300"
                >
                  Remove
                </Button>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      <Modal
        open={showPoliciesHelp}
        onClose={() => setShowPoliciesHelp(false)}
        title="Tool call policies"
        size="lg"
      >
        <div className="space-y-4 text-sm text-zinc-300">
          <p>
            Tool call policies control how the Gateway executes{" "}
            <span className="font-mono">tools/call</span> for this profile.
          </p>
          <ul className="list-disc pl-5 space-y-1">
            <li>
              <span className="font-semibold">Default timeout</span>: applies when a tool has no
              per-tool override.
            </li>
            <li>
              <span className="font-semibold">Per-tool timeout</span>: overrides the default for a
              single tool.
            </li>
            <li>
              <span className="font-semibold">Retry policy</span>: Gateway-side retries for
              transient failures. Use conservative values to avoid duplicate side effects.
            </li>
            <li>
              <span className="font-semibold">Stable tool identity</span>: policies are keyed by{" "}
              <span className="font-mono">&lt;source_id&gt;:&lt;original_tool_name&gt;</span> so
              transforms/renames won’t break your settings.
            </li>
            <li>
              <span className="font-semibold">Timeout cap</span>: the Gateway enforces a maximum
              timeout. Admins can raise it via{" "}
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
