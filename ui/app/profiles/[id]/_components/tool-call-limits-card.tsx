"use client";

import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button, Input, SectionCard, Toggle } from "@/components/ui";
import { SaveStatus } from "@/components/ui/save-status";
import { qk } from "@/src/lib/queryKeys";
import { updateProfile } from "@/src/lib/tenantApi";
import type { Profile } from "@/src/lib/types";
import { useAutosave } from "@/src/lib/useAutosave";

export function ToolCallLimitsCard({ profile }: { profile: Profile }) {
  const queryClient = useQueryClient();
  const [rateEnabled, setRateEnabled] = useState(profile.dataPlaneLimits.rateLimitEnabled);
  const [quotaEnabled, setQuotaEnabled] = useState(profile.dataPlaneLimits.quotaEnabled);
  const [rate, setRate] = useState(
    String(profile.dataPlaneLimits.rateLimitToolCallsPerMinute ?? ""),
  );
  const [quota, setQuota] = useState(String(profile.dataPlaneLimits.quotaToolCalls ?? ""));
  const autosave = useAutosave<Profile["dataPlaneLimits"]>(async (dataPlaneLimits) => {
    await updateProfile(profile, () => ({ dataPlaneLimits }));
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: qk.profile(profile.id) }),
      queryClient.invalidateQueries({ queryKey: qk.profiles() }),
    ]);
  });
  const hasApiKeys = profile.dataPlaneAuth.mode === "apiKey";
  const valid = (value: string) => Number.isSafeInteger(Number(value)) && Number(value) > 0;
  const rateError = rateEnabled && !valid(rate) ? "Enter a positive whole number." : undefined;
  const quotaError = quotaEnabled && !valid(quota) ? "Enter a positive whole number." : undefined;

  return (
    <SectionCard
      title="Tool-call limits"
      subtitle="Limits apply separately to each API key on this profile."
      bodyClassName="space-y-4"
    >
      <SaveStatus {...autosave} onRetry={autosave.retry} label="Tool-call limits" />
      {!hasApiKeys && (
        <p className="text-sm text-muted">
          These limits require API key authentication. They do not apply to OAuth or unauthenticated
          requests.
        </p>
      )}
      <form
        onSubmit={(event) => {
          event.preventDefault();
          if (rateError || quotaError) return;
          autosave.commit({
            rateLimitEnabled: rateEnabled,
            rateLimitToolCallsPerMinute: valid(rate) ? Number(rate) : null,
            quotaEnabled,
            quotaToolCalls: valid(quota) ? Number(quota) : null,
          });
        }}
      >
        <fieldset disabled={autosave.status === "saving"} className="space-y-4">
          <Toggle
            label="Limit calls per minute"
            checked={rateEnabled}
            disabled={!hasApiKeys && !rateEnabled}
            onChange={(value) => {
              setRateEnabled(value);
              autosave.edit();
            }}
          />
          {rateEnabled && (
            <Input
              label="Calls per minute"
              inputMode="numeric"
              value={rate}
              error={rateError}
              onChange={(event) => {
                setRate(event.target.value);
                autosave.edit();
              }}
              hint="Fixed one-minute windows. Rejected calls can be retried after the window resets."
            />
          )}
          <Toggle
            label="Limit total calls"
            checked={quotaEnabled}
            disabled={!hasApiKeys && !quotaEnabled}
            onChange={(value) => {
              setQuotaEnabled(value);
              autosave.edit();
            }}
          />
          {quotaEnabled && (
            <Input
              label="Initial call quota"
              inputMode="numeric"
              value={quota}
              error={quotaError}
              onChange={(event) => {
                setQuota(event.target.value);
                autosave.edit();
              }}
              hint="Starting budget for each key when it first uses this profile. Changing this value does not refill an existing budget; disabling and re-enabling preserves its balance. Attempts, including rate-limited calls, consume quota."
            />
          )}
          <Button
            type="submit"
            disabled={
              !!rateError ||
              !!quotaError ||
              autosave.status === "idle" ||
              autosave.status === "saved"
            }
            loading={autosave.status === "saving"}
          >
            Save tool-call limits
          </Button>
        </fieldset>
      </form>
    </SectionCard>
  );
}
