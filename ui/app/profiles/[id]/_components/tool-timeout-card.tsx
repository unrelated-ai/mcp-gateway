"use client";

import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Input, SectionCard } from "@/components/ui";
import { SaveStatus } from "@/components/ui/save-status";
import { useAutosave } from "@/src/lib/useAutosave";
import { updateProfile } from "@/src/lib/tenantApi";
import { invalidateProfile, invalidateProfiles } from "@/src/lib/queries/profileQueries";
import type { Profile } from "@/src/lib/types";

export function ToolTimeoutCard({ profile }: { profile: Profile }) {
  const client = useQueryClient();
  const [draft, setDraft] = useState<string | null>(null);
  const text = draft ?? String(profile.toolCallTimeoutSecs ?? "");
  const [validationError, setValidationError] = useState<string | null>(null);
  const autosave = useAutosave<number | null>(async (toolCallTimeoutSecs) => {
    await updateProfile(profile.id, { toolCallTimeoutSecs });
    await Promise.all([invalidateProfile(client, profile.id), invalidateProfiles(client)]);
  });

  const commit = () => {
    const value = text.trim() === "" ? null : Number(text);
    if (value !== null && (!Number.isSafeInteger(value) || value <= 0)) {
      setValidationError("Timeout must be a positive integer");
      return;
    }
    autosave.commit(value);
  };

  return (
    <SectionCard
      title="Default tool call timeout"
      subtitle="Applies when a tool policy does not override the timeout. Leave empty to use the Gateway default."
    >
      <div className="max-w-md space-y-3">
        <Input
          label="Timeout (seconds)"
          inputMode="numeric"
          placeholder="Gateway default"
          value={text}
          onChange={(e) => {
            setDraft(e.target.value);
            setValidationError(null);
            autosave.edit();
          }}
          onBlur={commit}
          onKeyDown={(e) => {
            if (e.key === "Enter") e.currentTarget.blur();
          }}
          error={validationError ?? undefined}
          hint="Changes save when you leave this field or press Enter."
        />
        <SaveStatus {...autosave} onRetry={autosave.retry} label="Timeout" />
      </div>
    </SectionCard>
  );
}
