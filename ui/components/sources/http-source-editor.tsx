"use client";

import { useRef, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button, Callout, SectionCard, Tabs, Textarea, Toggle } from "@/components/ui";
import { HttpMethodOptions, HttpSourceForm } from "./http-source-form";
import {
  buildHttpSourceConfig,
  readHttpSourceDraft,
  type HttpSourceDraft,
} from "@/src/lib/http-source";
import type { ToolSourceDetail } from "@/src/lib/tool-source-updates";
import { buildJsonSourceUpdate } from "@/src/lib/tool-source-updates";
import { putToolSource, validateSourceId } from "@/src/lib/tenantApi";
import { useToastStore } from "@/src/lib/toast-store";
import { qk } from "@/src/lib/queryKeys";

function initialDraft(value: unknown) {
  try {
    return { draft: readHttpSourceDraft(value), error: null };
  } catch (error) {
    return {
      draft: null,
      error: error instanceof Error ? error.message : "Unsupported source configuration",
    };
  }
}

export function HttpSourceEditor({
  sourceId,
  source,
  onSaved,
}: {
  sourceId: string;
  source?: ToolSourceDetail;
  onSaved: () => Promise<void>;
}) {
  const [initial] = useState(() => {
    const config = source
      ? { ...source.spec, type: "http", enabled: source.enabled }
      : { type: "http", enabled: true, baseUrl: "", tools: {} };
    return { config, ...initialDraft(config) };
  });
  const [draft, setDraft] = useState<HttpSourceDraft | null>(initial.draft);
  const [mode, setMode] = useState<"form" | "json">(initial.draft ? "form" : "json");
  const [text, setText] = useState(() => JSON.stringify(initial.config, null, 2));
  const [dirty, setDirty] = useState(false);
  const [formChanged, setFormChanged] = useState(false);
  const [error, setError] = useState<string | null>(initial.error);
  const alertRef = useRef<HTMLDivElement>(null);
  const queryClient = useQueryClient();
  const toast = useToastStore((state) => state.push);
  const showError = (message: string) => {
    setError(message);
    requestAnimationFrame(() =>
      alertRef.current?.scrollIntoView({ block: "nearest", behavior: "smooth" }),
    );
  };
  const changeMode = (next: "form" | "json") => {
    if (next === mode) return;
    try {
      if (next === "json" && draft && formChanged)
        setText(JSON.stringify(buildHttpSourceConfig(draft), null, 2));
      if (next === "form") {
        const nextDraft = readHttpSourceDraft(JSON.parse(text));
        setDraft(nextDraft);
        setFormChanged(false);
      }
      setError(null);
      setMode(next);
    } catch (cause) {
      showError(cause instanceof Error ? cause.message : "Could not switch editor");
    }
  };
  const save = useMutation({
    mutationKey: ["toolSourceSave", sourceId],
    mutationFn: async () => {
      const config =
        mode === "form" && draft ? buildHttpSourceConfig(draft) : (JSON.parse(text) as unknown);
      // Both editors validate the supported fields; raw JSON keeps its exact optional-field choices.
      buildHttpSourceConfig(readHttpSourceDraft(config));
      const detail = source ?? { type: "http", enabled: true, revision: 0, spec: {} };
      const body = buildJsonSourceUpdate(detail, JSON.stringify(config));
      const id = sourceId.trim();
      if (!source) {
        if (!/^[A-Za-z0-9_-]+$/.test(id))
          throw new Error("Source name: use letters, digits, underscores, or dashes.");
        const result = await validateSourceId(id);
        if (!result.ok) throw new Error(result.error || "This source name is unavailable.");
      }
      await putToolSource(id, JSON.stringify(body));
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: qk.toolSources() }),
        queryClient.invalidateQueries({ queryKey: qk.toolSource(sourceId) }),
        queryClient.invalidateQueries({ queryKey: qk.toolSourceTools(sourceId) }),
        queryClient.invalidateQueries({ queryKey: qk.profiles() }),
      ]);
      await onSaved();
      toast({ variant: "success", message: "HTTP source saved" });
      setDirty(false);
    },
    onError: (cause) => showError(cause.message),
  });
  const edit = () => {
    setDirty(true);
    setError(null);
    save.reset();
  };
  let jsonEnabled: boolean | null = null;
  try {
    const value = JSON.parse(text);
    if (value && typeof value === "object" && !Array.isArray(value))
      jsonEnabled = value.enabled !== false;
  } catch {
    /* Preserve incomplete JSON. */
  }

  return (
    <div className="space-y-6">
      <HttpMethodOptions />
      <Tabs
        items={[
          { value: "form", label: "Guided editor", disabled: save.isPending },
          { value: "json", label: "Advanced JSON", disabled: save.isPending },
        ]}
        value={mode}
        onChange={changeMode}
      />
      <div
        ref={alertRef}
        role={error ? "alert" : undefined}
        aria-label={error ? "HTTP source error" : undefined}
        className="scroll-mt-32"
      >
        {error && <Callout tone="danger">{error}</Callout>}
      </div>
      {mode === "form" && draft ? (
        <HttpSourceForm
          disabled={save.isPending}
          draft={draft}
          onChange={(next) => {
            setDraft(next);
            setFormChanged(true);
            edit();
          }}
        />
      ) : (
        <SectionCard
          title="Advanced JSON"
          subtitle="Edit the same draft as JSON. Switching editors keeps unsaved changes."
          bodyClassName="space-y-4"
        >
          <Toggle
            label="Source enabled"
            checked={jsonEnabled ?? true}
            disabled={jsonEnabled === null || save.isPending}
            onChange={(enabled) => {
              setText(JSON.stringify({ ...JSON.parse(text), enabled }, null, 2));
              edit();
            }}
          />
          <Textarea
            aria-label="Source configuration JSON"
            value={text}
            disabled={save.isPending}
            rows={22}
            onChange={(event) => {
              setText(event.target.value);
              edit();
            }}
          />
        </SectionCard>
      )}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p role="status" aria-label="HTTP source save status" className="text-sm text-muted">
          {save.isPending ? "Saving…" : dirty ? "Unsaved changes" : save.isSuccess ? "Saved" : ""}
        </p>
        <Button
          type="button"
          loading={save.isPending}
          onClick={() => {
            setError(null);
            save.mutate();
          }}
        >
          {!source ? "Create HTTP source" : mode === "json" ? "Save JSON" : "Save HTTP source"}
        </Button>
      </div>
    </div>
  );
}
