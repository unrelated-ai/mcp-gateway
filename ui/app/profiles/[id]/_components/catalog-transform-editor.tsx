"use client";

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Button,
  Callout,
  ConfirmModal,
  Input,
  Select,
  Tabs,
  Textarea,
  Toggle,
} from "@/components/ui";
import { getProfile, updateProfile, type ProfileSurface } from "@/src/lib/tenantApi";
import type { Profile } from "@/src/lib/types";
import { qk } from "@/src/lib/queryKeys";
import {
  buildCatalogOverride,
  catalogDraft,
  catalogIdentity,
  replaceCatalogOverride,
  type CatalogDraft,
  type CatalogEntry,
  type CatalogKind,
} from "@/src/lib/surface-transforms";

const sections = [
  { value: "resourceOverrides", label: "Resources" },
  { value: "resourceTemplateOverrides", label: "Resource templates" },
  { value: "promptOverrides", label: "Prompts" },
] as const;

export function CatalogTransformEditor({
  profile,
  surface,
  onSaved,
}: {
  profile: Profile;
  surface: ProfileSurface;
  onSaved: () => void;
}) {
  const [kind, setKind] = useState<CatalogKind>("resourceOverrides");
  const [selection, setSelection] = useState("");
  const [locked, setLocked] = useState(false);
  const entries =
    (kind === "resourceOverrides"
      ? surface.allResources
      : kind === "resourceTemplateOverrides"
        ? surface.allResourceTemplates
        : surface.allPrompts) ?? [];
  const key = (entry: CatalogEntry) =>
    JSON.stringify([entry.sourceId, catalogIdentity(entry.original)]);
  const selected = entries.find((entry) => key(entry) === selection) ?? entries[0];
  return (
    <div className="space-y-4 border-t border-edge pt-5">
      <div>
        <h3 className="text-sm font-semibold text-fg">Resource and prompt settings</h3>
        <p className="mt-1 text-sm text-muted">
          Choose what this profile exposes and how it appears to clients.
        </p>
      </div>
      <Tabs
        items={sections.map((section) => ({ ...section, disabled: locked }))}
        value={kind}
        onChange={(value) => {
          setKind(value);
          setSelection("");
        }}
      />
      {selected ? (
        <>
          <Select
            label="Catalog entry"
            value={key(selected)}
            disabled={locked}
            onChange={(event) => setSelection(event.target.value)}
          >
            {entries.map((entry) => (
              <option key={key(entry)} value={key(entry)}>
                {entry.original.name} · {catalogIdentity(entry.original)}
                {entry.enabled ? "" : " (disabled)"} · {entry.sourceId}
              </option>
            ))}
          </Select>
          <EntryEditor
            key={kind + key(selected)}
            profile={profile}
            entry={selected}
            kind={kind}
            onLock={setLocked}
            onSaved={onSaved}
          />
        </>
      ) : (
        <p className="text-sm text-muted">
          No entries discovered in this category. Run a probe after attaching an upstream.
        </p>
      )}
    </div>
  );
}

function EntryEditor({
  profile,
  entry,
  kind,
  onLock,
  onSaved,
}: {
  profile: Profile;
  entry: CatalogEntry;
  kind: CatalogKind;
  onLock: (locked: boolean) => void;
  onSaved: () => void;
}) {
  const [snapshot, setSnapshot] = useState(profile);
  const [draft, setDraft] = useState(() => catalogDraft(kind, entry, profile.transforms));
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showReload, setShowReload] = useState(false);
  const client = useQueryClient();
  const prompt = kind === "promptOverrides";
  const identity = catalogIdentity(entry.original);
  const patch = (changes: Partial<CatalogDraft>) => {
    setDraft((current) => ({ ...current, ...changes }));
    setDirty(true);
    setError(null);
    onLock(true);
  };
  const invalidate = async () => {
    await Promise.all([
      client.invalidateQueries({ queryKey: qk.profile(profile.id) }),
      client.invalidateQueries({ queryKey: qk.profiles() }),
    ]);
  };
  const save = useMutation({
    mutationFn: async () => {
      const rule = buildCatalogOverride(kind, draft);
      await updateProfile(snapshot, (current) => ({
        transforms: replaceCatalogOverride(
          current.transforms,
          kind,
          entry.sourceId,
          identity,
          rule,
        ),
      }));
    },
    onSuccess: async () => {
      // Keep the loaded revision: the shared queue tracks successful local writes, but still rejects external edits.
      setSnapshot((current) => ({
        ...current,
        transforms: replaceCatalogOverride(
          current.transforms,
          kind,
          entry.sourceId,
          identity,
          buildCatalogOverride(kind, draft),
        ),
      }));
      setDirty(false);
      onLock(false);
      await invalidate();
      onSaved();
    },
    onError: (cause) => setError(cause.message),
  });
  const reload = useMutation({
    mutationFn: () => getProfile(profile.id),
    onSuccess: async (latest) => {
      setSnapshot(latest);
      setDraft(catalogDraft(kind, entry, latest.transforms));
      setDirty(false);
      setError(null);
      setShowReload(false);
      onLock(false);
      save.reset();
      await invalidate();
      onSaved();
    },
    onError: (cause) => setError(cause.message),
  });
  const pending = save.isPending || reload.isPending;
  let validation: string | null = null;
  try {
    buildCatalogOverride(kind, draft);
  } catch (cause) {
    validation = cause instanceof Error ? cause.message : "Invalid settings";
  }
  const displayName =
    !dirty && prompt ? entry.exposed.name : draft.name.trim() || entry.original.name;
  const hidden = !draft.enabled || (!dirty && !entry.enabled) || (!prompt && !!entry.error);
  return (
    <div className="space-y-4">
      {entry.error && <Callout tone="warn">{entry.error}</Callout>}
      {error && (
        <div role="alert" aria-label="Catalog settings error">
          <Callout tone="danger">{error}</Callout>
        </div>
      )}
      <fieldset
        disabled={pending}
        className="min-w-0 grid gap-5 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]"
      >
        <div className="min-w-0 space-y-4">
          <Toggle
            label="Available to clients"
            checked={draft.enabled}
            onChange={(enabled) => patch({ enabled })}
            description="Disabled entries are hidden and cannot be accessed directly."
          />
          <Input
            label={prompt ? "Prompt alias" : "Display name"}
            value={draft.name}
            placeholder={entry.original.name}
            onChange={(event) => patch({ name: event.target.value })}
            hint="Leave blank to inherit the upstream name."
          />
          {!prompt && (
            <Input
              label="Display title"
              value={draft.title}
              placeholder={entry.original.title ?? "Optional display title"}
              onChange={(event) => patch({ title: event.target.value })}
              hint="Leave blank to inherit the upstream title."
            />
          )}
          <Toggle
            label="Override description"
            checked={draft.overrideDescription}
            onChange={(overrideDescription) => patch({ overrideDescription })}
          />
          {draft.overrideDescription && (
            <Textarea
              label="Description override"
              value={draft.description}
              rows={3}
              onChange={(event) => patch({ description: event.target.value })}
            />
          )}
          {prompt &&
            draft.params.map((param, index) => (
              <fieldset
                key={param.original}
                aria-label={`Prompt argument ${param.original}`}
                className="min-w-0 rounded-md border border-edge bg-well p-4 space-y-3"
              >
                <p className="break-all font-mono text-sm text-accent">{param.original}</p>
                <Input
                  label="Argument alias"
                  value={param.rename}
                  placeholder={param.original}
                  onChange={(event) =>
                    patch({
                      params: draft.params.map((row, i) =>
                        i === index ? { ...row, rename: event.target.value } : row,
                      ),
                    })
                  }
                />
                <Toggle
                  label="Supply a default"
                  checked={param.useDefault}
                  onChange={(useDefault) =>
                    patch({
                      params: draft.params.map((row, i) =>
                        i === index ? { ...row, useDefault } : row,
                      ),
                    })
                  }
                />
                {param.useDefault && (
                  <Input
                    label="Default argument value"
                    value={param.defaultValue}
                    onChange={(event) =>
                      patch({
                        params: draft.params.map((row, i) =>
                          i === index ? { ...row, defaultValue: event.target.value } : row,
                        ),
                      })
                    }
                    hint="Used when the client omits this argument. Empty text is a valid default."
                  />
                )}
              </fieldset>
            ))}
        </div>
        <div
          className="min-w-0 self-start rounded-lg border border-edge bg-well p-4 space-y-3"
          aria-label="Client preview"
          role="region"
        >
          <h4 className="text-sm font-semibold text-fg">Client preview</h4>
          <p className="text-xs text-muted">{dirty ? "Unsaved draft" : "Current settings"}</p>
          {hidden ? (
            <p className="text-sm text-muted">Hidden from clients. Direct access is blocked.</p>
          ) : (
            <>
              <p className="break-all font-mono text-sm text-accent">{displayName}</p>
              {!prompt && (
                <p className="break-all font-mono text-xs text-muted">
                  {entry.exposed.uri ?? entry.exposed.uriTemplate}
                </p>
              )}
              {!prompt && (draft.title.trim() || entry.original.title) && (
                <p className="text-sm text-fg">{draft.title.trim() || entry.original.title}</p>
              )}
              <p className="whitespace-pre-wrap break-words text-sm text-muted">
                {draft.overrideDescription
                  ? draft.description
                  : entry.original.description || "No description"}
              </p>
              {prompt && draft.params.length > 0 && (
                <ul className="space-y-2 text-sm">
                  {draft.params.map((param) => (
                    <li key={param.original} className="break-all">
                      <span className="font-mono text-fg">
                        {param.rename.trim() || param.original}
                      </span>
                      <span className="text-muted">
                        {param.useDefault
                          ? ` · default: ${JSON.stringify(param.defaultValue)}`
                          : entry.original.arguments?.find((arg) => arg.name === param.original)
                                ?.required
                            ? " · required"
                            : " · optional"}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
              {prompt && (
                <p className="text-xs text-faint">
                  The Gateway adds a source prefix if another upstream exposes the same prompt name.
                </p>
              )}
            </>
          )}
          {validation && <Callout tone="danger">{validation}</Callout>}
        </div>
      </fieldset>
      {kind === "resourceTemplateOverrides" && (
        <p className="text-xs text-muted">
          Disabling a template blocks its URI family, including overlapping templates and listed
          resources. Template variables are treated as wildcards for this restriction.
        </p>
      )}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-muted" role="status" aria-label="Catalog settings save status">
          {pending
            ? "Saving…"
            : dirty
              ? "Unsaved changes — save or discard before selecting another entry."
              : save.isSuccess
                ? "Saved"
                : ""}
        </p>
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" disabled={pending} onClick={() => setShowReload(true)}>
            Reload saved settings
          </Button>
          {dirty && (
            <Button
              variant="ghost"
              disabled={pending}
              onClick={() => {
                setDraft(catalogDraft(kind, entry, snapshot.transforms));
                setDirty(false);
                setError(null);
                onLock(false);
                save.reset();
              }}
            >
              Discard changes
            </Button>
          )}
          <Button
            loading={save.isPending}
            disabled={pending || !dirty || !!validation}
            onClick={() => {
              setError(null);
              onLock(true);
              save.mutate();
            }}
          >
            Save catalog settings
          </Button>
        </div>
      </div>
      <ConfirmModal
        open={showReload}
        onClose={() => {
          if (!reload.isPending) setShowReload(false);
        }}
        onConfirm={() => reload.mutate()}
        title="Reload catalog settings?"
        description="Unsaved changes to this entry will be discarded."
        confirmLabel="Reload"
        loading={reload.isPending}
      />
    </div>
  );
}
