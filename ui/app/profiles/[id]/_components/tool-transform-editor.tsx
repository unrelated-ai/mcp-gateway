"use client";

import { useState } from "react";
import type { ProfileSurface } from "@/src/lib/tenantApi";
import { Button, Callout, Input, SectionCard, Textarea, Toggle } from "@/components/ui";

// NOTE: `ui/src/lib/types.ts` defines `Profile.transforms` as `unknown`. We keep the
// editor typed, but accept/emit `unknown`-compatible shapes.
export type ParamOverride = {
  rename?: string;
  default?: unknown;
  visible?: boolean;
  treatNullAsMissing?: boolean;
};

export type ToolOverride = {
  rename?: string;
  description?: string;
  params?: Record<string, ParamOverride>;
};

export type TransformPipeline = {
  toolOverrides: Record<string, ToolOverride>;
};

export function normalizePipeline(input: unknown): TransformPipeline {
  const obj = typeof input === "object" && input !== null ? (input as Record<string, unknown>) : {};
  const toolOverrides =
    (typeof obj.toolOverrides === "object" && obj.toolOverrides !== null
      ? (obj.toolOverrides as Record<string, ToolOverride>)
      : {}) ?? {};

  return { toolOverrides: { ...toolOverrides } };
}

export function ToolTransformEditor({
  tool,
  pipeline,
  onCommitPipeline,
  onDirty,
  toolsPending,
  enabled,
}: {
  tool: ProfileSurface["allTools"][number];
  pipeline: TransformPipeline;
  onCommitPipeline: (next: TransformPipeline) => void;
  onDirty: () => void;
  toolsPending: boolean;
  enabled: boolean;
}) {
  const currentOverride: ToolOverride = pipeline.toolOverrides[tool.originalName] ?? {};
  const originalDescription = tool.originalDescription ?? tool.description ?? "";
  const hasExistingDescriptionOverride = typeof currentOverride.description === "string";

  const [renameTool, setRenameTool] = useState<string>(() => currentOverride.rename ?? "");
  const [descriptionText, setDescriptionText] = useState<string>(() => {
    return hasExistingDescriptionOverride
      ? (currentOverride.description as string)
      : originalDescription;
  });
  const [descriptionTouched, setDescriptionTouched] = useState(false);
  const [clearDescriptionOverride, setClearDescriptionOverride] = useState(false);
  const [paramRows, setParamRows] = useState<
    Array<{
      name: string;
      rename: string;
      defaultText: string;
      visible: boolean;
      treatNullAsMissing: boolean;
    }>
  >(() => {
    const m = currentOverride.params ?? {};
    const names = tool.originalParams.slice();
    for (const k of Object.keys(m)) {
      if (!names.includes(k)) names.push(k);
    }
    return names.map((name) => {
      const v = m[name] ?? {};
      const rename = typeof v.rename === "string" ? v.rename : "";
      const defaultText =
        v && "default" in v && typeof v.default !== "undefined"
          ? JSON.stringify(v.default, null, 2)
          : "";
      const visible = v.visible !== false;
      const treatNullAsMissing = v.treatNullAsMissing !== false;
      return { name, rename, defaultText, visible, treatNullAsMissing };
    });
  });
  const [error, setError] = useState<string | null>(null);

  const computeCandidate = (opts?: {
    renameTool?: string;
    descriptionText?: string;
    paramRows?: typeof paramRows;
  }) => {
    const rt = (opts?.renameTool ?? renameTool).trim();
    const desc = (opts?.descriptionText ?? descriptionText).trim();
    const rows = opts?.paramRows ?? paramRows;

    const params: Record<
      string,
      { rename?: string; default?: unknown; visible?: boolean; treatNullAsMissing?: boolean }
    > = {};

    for (const row of rows) {
      const name = row.name.trim();
      if (!name) continue;

      const rename = row.rename.trim();
      let parsedDefault: unknown | undefined = undefined;
      const defaultText = row.defaultText.trim();
      if (defaultText) {
        try {
          parsedDefault = JSON.parse(defaultText);
        } catch {
          return { ok: false as const, error: `Invalid JSON default for argument '${name}'.` };
        }
      }

      const entry: ParamOverride = {};
      if (rename) entry.rename = rename;
      if (defaultText) entry.default = parsedDefault;
      if (!row.visible) entry.visible = false;
      if (!row.treatNullAsMissing) entry.treatNullAsMissing = false;
      if (Object.keys(entry).length > 0) params[name] = entry;
    }

    return { ok: true as const, rt, params, desc };
  };

  const commitWith = (opts?: {
    renameTool?: string;
    descriptionText?: string;
    clearDescriptionOverride?: boolean;
    descriptionTouched?: boolean;
    paramRows?: typeof paramRows;
  }) => {
    setError(null);

    const candidate = computeCandidate(opts);
    if (!candidate.ok) {
      setError(candidate.error);
      return;
    }

    const next: TransformPipeline = { toolOverrides: { ...pipeline.toolOverrides } };
    const curr: ToolOverride = { ...(next.toolOverrides[tool.originalName] ?? {}) };

    // Tool rename
    if (candidate.rt) curr.rename = candidate.rt;
    else delete curr.rename;

    // Description override
    const original = originalDescription.trim();
    const clearDesc = opts?.clearDescriptionOverride ?? clearDescriptionOverride;
    const touched = opts?.descriptionTouched ?? descriptionTouched;
    if (clearDesc) {
      delete curr.description;
    } else if (hasExistingDescriptionOverride || touched) {
      const trimmed = candidate.desc;
      if (trimmed === "") {
        delete curr.description;
      } else if (!hasExistingDescriptionOverride && trimmed === original) {
        // No-op: don't persist an override if it matches the original.
        delete curr.description;
      } else {
        curr.description = trimmed;
      }
    }

    // Params (rename/default)
    if (Object.keys(candidate.params).length > 0) curr.params = candidate.params;
    else delete curr.params;

    const isEmpty =
      !curr.rename && !curr.description && (!curr.params || Object.keys(curr.params).length === 0);
    if (isEmpty) {
      delete next.toolOverrides[tool.originalName];
    } else {
      next.toolOverrides[tool.originalName] = curr;
    }

    onCommitPipeline(next);
    setClearDescriptionOverride(false);
    setDescriptionTouched(false);
  };

  const commit = () => commitWith();

  return (
    <div className="space-y-5">
      {!enabled ? (
        <Callout tone="neutral">This tool is currently disabled for this profile.</Callout>
      ) : null}

      {error && <Callout tone="danger">{error}</Callout>}

      <SectionCard title="Tool rename" bodyClassName="space-y-3">
        <Input
          value={renameTool}
          onChange={(e) => {
            setError(null);
            setRenameTool(e.target.value);
            onDirty();
          }}
          onBlur={commit}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              (e.target as HTMLInputElement).blur();
            }
          }}
          placeholder="(optional) New exposed tool name"
        />
        <div className="text-xs text-faint">
          Original name: <span className="font-mono text-fg">{tool.originalName}</span>
        </div>
      </SectionCard>

      <SectionCard title="Description override" bodyClassName="space-y-3">
        <Textarea
          value={descriptionText}
          onChange={(e) => {
            setError(null);
            setDescriptionText(e.target.value);
            onDirty();
            setDescriptionTouched(true);
            setClearDescriptionOverride(false);
          }}
          onBlur={commit}
          placeholder="(optional) Replace tool description shown to clients"
          rows={3}
        />
        <div className="flex items-center justify-between gap-3">
          <div className="text-xs text-faint">
            {hasExistingDescriptionOverride ? "Editing override." : ""}
          </div>
          {hasExistingDescriptionOverride && (
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={() => {
                setError(null);
                setDescriptionText(originalDescription);
                setClearDescriptionOverride(true);
                setDescriptionTouched(true);
                commitWith({
                  descriptionText: originalDescription,
                  clearDescriptionOverride: true,
                  descriptionTouched: true,
                });
              }}
            >
              Reset to original
            </Button>
          )}
        </div>
      </SectionCard>

      <SectionCard title="Arguments" subtitle="Rename, defaults, visibility, and null handling.">
        <div className="space-y-3">
          {paramRows.map((row) => (
            <div key={row.name} className="rounded-lg border border-edge bg-well p-3 space-y-3">
              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="eyebrow">Argument</div>
                  <div className="text-sm font-semibold text-fg font-mono break-all">
                    {row.name}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Toggle
                    checked={row.visible}
                    disabled={toolsPending}
                    onChange={(checked) => {
                      setError(null);
                      const nextRows = paramRows.map((r) =>
                        r.name === row.name ? { ...r, visible: checked } : r,
                      );
                      setParamRows(nextRows);
                      commitWith({ paramRows: nextRows });
                    }}
                    label={row.visible ? "Exposed" : "Hidden"}
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <Input
                  label="Rename (exposed name)"
                  value={row.rename}
                  onChange={(e) => {
                    setError(null);
                    onDirty();
                    setParamRows((rows) =>
                      rows.map((r) => (r.name === row.name ? { ...r, rename: e.target.value } : r)),
                    );
                  }}
                  onBlur={commit}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      (e.target as HTMLInputElement).blur();
                    }
                  }}
                  placeholder="(optional) New exposed argument name"
                />
                <div className="flex items-end">
                  <Toggle
                    checked={row.treatNullAsMissing}
                    disabled={toolsPending}
                    onChange={(checked) => {
                      setError(null);
                      const nextRows = paramRows.map((r) =>
                        r.name === row.name ? { ...r, treatNullAsMissing: checked } : r,
                      );
                      setParamRows(nextRows);
                      commitWith({ paramRows: nextRows });
                    }}
                    label="Default on null"
                    description="When enabled, null is treated like missing."
                  />
                </div>
              </div>

              <Textarea
                value={row.defaultText}
                onChange={(e) => {
                  setError(null);
                  onDirty();
                  setParamRows((rows) =>
                    rows.map((r) =>
                      r.name === row.name ? { ...r, defaultText: e.target.value } : r,
                    ),
                  );
                }}
                onBlur={commit}
                placeholder='(optional) Default JSON, e.g. "hello" or {"k": 1}'
                rows={3}
              />
            </div>
          ))}
        </div>
      </SectionCard>
    </div>
  );
}
