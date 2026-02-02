"use client";

import { useState, type ReactNode } from "react";
import type { ProfileSurface } from "@/src/lib/tenantApi";
import type { RetryPolicy, ToolPolicy } from "@/src/lib/types";
import { Checkbox, Input, Toggle } from "@/components/ui";

const KNOWN_NON_RETRYABLE_ERROR_TYPES = [
  "timeout",
  "transport",
  "upstream_5xx",
  "deserialize",
] as const;

type KnownNonRetryableErrorType = (typeof KNOWN_NON_RETRYABLE_ERROR_TYPES)[number];

function uniqSorted(xs: string[]): string[] {
  return [...new Set(xs.map((s) => s.trim()).filter(Boolean))].sort((a, b) => a.localeCompare(b));
}

function normalizeToolRef(raw: string): string {
  return raw.trim();
}

function isValidToolRef(tool: string): boolean {
  const t = tool.trim();
  if (!t) return false;
  const i = t.indexOf(":");
  if (i <= 0) return false;
  if (i === t.length - 1) return false;
  return true;
}

function parsePositiveInt(text: string): number | null {
  const t = text.trim();
  if (!t) return null;
  if (!/^[0-9]+$/.test(t)) throw new Error("Must be a positive integer");
  const n = Number(t);
  if (!Number.isFinite(n) || n <= 0) throw new Error("Must be > 0");
  return n;
}

function parsePositiveNumber(text: string): number | null {
  const t = text.trim();
  if (!t) return null;
  const n = Number(t);
  if (!Number.isFinite(n)) throw new Error("Must be a number");
  return n;
}

function stablePolicy(p: ToolPolicy): ToolPolicy {
  const tool = normalizeToolRef(p.tool);
  const timeoutSecs = typeof p.timeoutSecs === "number" ? p.timeoutSecs : null;
  const retry: RetryPolicy | null =
    p.retry && typeof p.retry === "object"
      ? {
          maximumAttempts: p.retry.maximumAttempts,
          initialIntervalMs: p.retry.initialIntervalMs,
          backoffCoefficient: p.retry.backoffCoefficient,
          maximumIntervalMs: p.retry.maximumIntervalMs ?? null,
          nonRetryableErrorTypes: uniqSorted(p.retry.nonRetryableErrorTypes ?? []),
        }
      : null;

  return {
    tool,
    timeoutSecs: timeoutSecs ?? undefined,
    retry: retry ?? undefined,
  };
}

type ToolPolicyDraft = {
  tool: string;
  timeoutSecs: string;
  retryEnabled: boolean;
  maximumAttempts: string;
  initialIntervalMs: string;
  backoffCoefficient: string;
  maximumIntervalMs: string;
  nonRetryable: Record<KnownNonRetryableErrorType, boolean>;
  extraNonRetryableCsv: string;
};

function draftFromPolicy(p: ToolPolicy): ToolPolicyDraft {
  const retry = p.retry ?? null;
  const nonRetryableList = new Set((retry?.nonRetryableErrorTypes ?? []).map((s) => s.trim()));

  const nonRetryable: Record<KnownNonRetryableErrorType, boolean> = {
    timeout: nonRetryableList.has("timeout"),
    transport: nonRetryableList.has("transport"),
    upstream_5xx: nonRetryableList.has("upstream_5xx"),
    deserialize: nonRetryableList.has("deserialize"),
  };

  const extraNonRetryableCsv = uniqSorted(
    (retry?.nonRetryableErrorTypes ?? []).filter(
      (s) =>
        !KNOWN_NON_RETRYABLE_ERROR_TYPES.includes(s.trim() as KnownNonRetryableErrorType) &&
        s.trim().length > 0,
    ),
  ).join(", ");

  return {
    tool: p.tool,
    timeoutSecs: typeof p.timeoutSecs === "number" ? String(p.timeoutSecs) : "",
    retryEnabled: !!retry,
    maximumAttempts: retry ? String(retry.maximumAttempts) : "2",
    initialIntervalMs: retry ? String(retry.initialIntervalMs) : "500",
    backoffCoefficient: retry ? String(retry.backoffCoefficient) : "2",
    maximumIntervalMs: retry?.maximumIntervalMs ? String(retry.maximumIntervalMs) : "",
    nonRetryable,
    extraNonRetryableCsv,
  };
}

function policyFromDraft(d: ToolPolicyDraft): ToolPolicy {
  const tool = normalizeToolRef(d.tool);
  if (!isValidToolRef(tool)) {
    throw new Error('Tool must be in the form "<source_id>:<original_tool_name>".');
  }

  const timeoutSecs = parsePositiveInt(d.timeoutSecs);
  const out: ToolPolicy = { tool };
  if (timeoutSecs != null) out.timeoutSecs = timeoutSecs;

  if (!d.retryEnabled) return out;

  const maximumAttempts = parsePositiveInt(d.maximumAttempts);
  const initialIntervalMs = parsePositiveInt(d.initialIntervalMs);
  const backoffCoefficient = parsePositiveNumber(d.backoffCoefficient);

  if (maximumAttempts == null) throw new Error("Retry maximumAttempts is required");
  if (initialIntervalMs == null) throw new Error("Retry initialIntervalMs is required");
  if (backoffCoefficient == null) throw new Error("Retry backoffCoefficient is required");
  if (!(backoffCoefficient >= 1.0)) throw new Error("Retry backoffCoefficient must be >= 1.0");

  const maximumIntervalMs = parsePositiveInt(d.maximumIntervalMs);

  const selectedKnown = Object.entries(d.nonRetryable)
    .filter(([, v]) => v)
    .map(([k]) => k);
  const extra = d.extraNonRetryableCsv
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  const nonRetryableErrorTypes = uniqSorted([...selectedKnown, ...extra]);

  out.retry = {
    maximumAttempts,
    initialIntervalMs,
    backoffCoefficient,
    maximumIntervalMs: maximumIntervalMs ?? undefined,
    nonRetryableErrorTypes,
  };

  return out;
}

function policySummary(p: ToolPolicy | null): ReactNode {
  if (!p) return null;
  const timeout = typeof p.timeoutSecs === "number" ? `${p.timeoutSecs}s` : "default";
  const retry = p.retry ? `${p.retry.maximumAttempts} attempts` : "off";
  return (
    <span>
      override timeout <span className="text-zinc-200">{timeout}</span>{" "}
      <span className="text-zinc-600">·</span> retry <span className="text-zinc-200">{retry}</span>
    </span>
  );
}

export function ToolPolicyEditor({
  tool,
  policiesByToolRef,
  saveError,
  clearSaveError,
  onSave,
}: {
  tool: ProfileSurface["allTools"][number];
  policiesByToolRef: Map<string, ToolPolicy>;
  saveError: string | null;
  clearSaveError: () => void;
  onSave: (p: ToolPolicy) => void;
}) {
  // Stable identifier: original tool name (independent of transforms).
  const stableRef = `${tool.sourceId}:${tool.originalName}`;
  const current = policiesByToolRef.get(stableRef) ?? null;

  const [draft, setDraft] = useState<ToolPolicyDraft>(() => {
    if (current) return draftFromPolicy({ ...current, tool: stableRef });
    return draftFromPolicy({ tool: stableRef, timeoutSecs: null, retry: null });
  });

  const [error, setError] = useState<string | null>(null);

  const commit = () => {
    setError(null);
    try {
      const next = policyFromDraft({ ...draft, tool: stableRef });
      const nextNorm = JSON.stringify(stablePolicy(next));
      const currNorm = JSON.stringify(
        stablePolicy(current ?? { tool: stableRef, retry: null, timeoutSecs: null }),
      );
      if (nextNorm === currNorm) return;
      clearSaveError();
      onSave(next);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Invalid policy");
    }
  };

  return (
    <div className="space-y-4">
      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-200">
          {error}
        </div>
      )}
      {saveError && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-200">
          {saveError}
        </div>
      )}

      <Input
        label="Timeout override (seconds, optional)"
        inputMode="numeric"
        value={draft.timeoutSecs}
        onChange={(e) => {
          clearSaveError();
          setDraft((p) => ({ ...p, timeoutSecs: e.target.value }));
        }}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            (e.target as HTMLInputElement).blur();
          }
        }}
        placeholder="e.g. 30"
      />

      <div className="rounded-xl border border-zinc-800/60 bg-zinc-950/30 p-4 space-y-4">
        <Toggle
          checked={draft.retryEnabled}
          onChange={(checked) => {
            clearSaveError();
            setDraft((p) => ({ ...p, retryEnabled: checked }));
            // Discrete change: save immediately.
            setTimeout(commit, 0);
          }}
          label="Enable retry policy"
          description="Retries are Gateway-side; use conservative settings."
        />

        {draft.retryEnabled ? (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Input
                label="Maximum attempts"
                inputMode="numeric"
                value={draft.maximumAttempts}
                onChange={(e) => {
                  clearSaveError();
                  setDraft((p) => ({ ...p, maximumAttempts: e.target.value }));
                }}
                onBlur={commit}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    (e.target as HTMLInputElement).blur();
                  }
                }}
                placeholder="e.g. 2"
              />
              <Input
                label="Initial interval (ms)"
                inputMode="numeric"
                value={draft.initialIntervalMs}
                onChange={(e) => {
                  clearSaveError();
                  setDraft((p) => ({ ...p, initialIntervalMs: e.target.value }));
                }}
                onBlur={commit}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    (e.target as HTMLInputElement).blur();
                  }
                }}
                placeholder="e.g. 500"
              />
              <Input
                label="Backoff coefficient"
                inputMode="decimal"
                value={draft.backoffCoefficient}
                onChange={(e) => {
                  clearSaveError();
                  setDraft((p) => ({ ...p, backoffCoefficient: e.target.value }));
                }}
                onBlur={commit}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    (e.target as HTMLInputElement).blur();
                  }
                }}
                placeholder="e.g. 2"
              />
              <Input
                label="Maximum interval (ms, optional)"
                inputMode="numeric"
                value={draft.maximumIntervalMs}
                onChange={(e) => {
                  clearSaveError();
                  setDraft((p) => ({ ...p, maximumIntervalMs: e.target.value }));
                }}
                onBlur={commit}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    (e.target as HTMLInputElement).blur();
                  }
                }}
                placeholder="e.g. 5000"
              />
            </div>

            <div className="space-y-2">
              <div className="text-sm font-medium text-zinc-300">Non-retryable errors</div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {KNOWN_NON_RETRYABLE_ERROR_TYPES.map((t) => (
                  <Checkbox
                    key={t}
                    checked={!!draft.nonRetryable[t]}
                    onChange={(checked) => {
                      clearSaveError();
                      setDraft((p) => ({
                        ...p,
                        nonRetryable: { ...p.nonRetryable, [t]: checked },
                      }));
                      setTimeout(commit, 0);
                    }}
                    label={<span className="font-mono text-sm">{t}</span>}
                    description={null}
                  />
                ))}
              </div>
              <Input
                label="Extra non-retryable errors (CSV, optional)"
                value={draft.extraNonRetryableCsv}
                onChange={(e) => {
                  clearSaveError();
                  setDraft((p) => ({ ...p, extraNonRetryableCsv: e.target.value }));
                }}
                onBlur={commit}
                placeholder="e.g. invalid_request, quota_exceeded"
              />
            </div>
          </div>
        ) : null}
      </div>

      <div className="flex items-center justify-between">
        <div className="text-xs text-zinc-500">{policySummary(current)}</div>
      </div>
    </div>
  );
}
