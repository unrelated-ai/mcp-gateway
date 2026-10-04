"use client";

import Link from "next/link";
import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Callout, SectionCard, Select } from "@/components/ui";
import { SaveStatus } from "@/components/ui/save-status";
import { AUDIT_LEVELS, auditLevelLabel, previewProfileAuditLevel } from "@/src/lib/auditSettings";
import { qk } from "@/src/lib/queryKeys";
import { getProfileAuditSettings, updateProfileAuditSettings } from "@/src/lib/tenantApi";
import type { AuditLevel, Profile } from "@/src/lib/types";
import { useAutosave } from "@/src/lib/useAutosave";

type Draft = { level: AuditLevel | null; revision: number };

export function ProfileAuditCard({ profile }: { profile: Profile }) {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: qk.profileAuditSettings(profile.id),
    queryFn: () => getProfileAuditSettings(profile.id),
  });
  const [draft, setDraft] = useState<Draft | null>(null);
  const save = useAutosave<Draft>(async (next) => {
    await updateProfileAuditSettings(
      { id: profile.id, revision: next.revision },
      { level: next.level },
    );
    await queryClient.invalidateQueries({ queryKey: qk.profile(profile.id) });
  });
  const settings = query.data;
  const selected = draft ? draft.level : (settings?.auditSettings.level ?? null);
  const preview = settings ? previewProfileAuditLevel(settings.tenantSettings, selected) : null;

  return (
    <SectionCard
      title="Profile audit"
      subtitle="Logging for this profile’s MCP activity."
      bodyClassName="space-y-4"
    >
      <SaveStatus {...save} onRetry={save.retry} label="Profile audit" />
      {query.isPending && (
        <p role="status" className="text-sm text-muted">
          Loading audit settings…
        </p>
      )}
      {query.isError && (
        <Callout tone="danger">
          Could not load audit settings. {query.error.message}{" "}
          <Button size="sm" disabled={query.isFetching} onClick={() => void query.refetch()}>
            Retry audit settings
          </Button>
        </Callout>
      )}
      {settings && (
        <>
          {settings.hasUnrecognizedSettings && (
            <Callout tone="info">
              The saved settings use an unsupported format. Tenant defaults apply until a supported
              setting is saved.
            </Callout>
          )}
          <dl className="grid gap-4 sm:grid-cols-3 text-sm">
            <div>
              <dt className="text-muted">Tenant default</dt>
              <dd className="mt-1 font-medium text-fg">
                {auditLevelLabel(settings.tenantSettings.defaultLevel)}
              </dd>
            </div>
            <div>
              <dt className="text-muted">Current effective level</dt>
              <dd aria-label="Effective audit level" className="mt-1 font-medium text-fg">
                {auditLevelLabel(settings.effectiveLevel)}
              </dd>
            </div>
            <div>
              <dt className="text-muted">Retention</dt>
              <dd className="mt-1 font-medium text-fg">
                {settings.tenantSettings.retentionDays} days · tenant-wide
              </dd>
            </div>
          </dl>
          {(!settings.tenantSettings.enabled || settings.tenantSettings.defaultLevel === "off") && (
            <Callout tone="info">
              Audit logging is off for the tenant. Profile overrides take effect when tenant logging
              is enabled with a non-off default level.
            </Callout>
          )}
          <Select
            label="Profile audit detail"
            value={selected ?? "inherit"}
            disabled={save.status === "saving"}
            onChange={(event) => {
              const level =
                event.target.value === "inherit" ? null : (event.target.value as AuditLevel);
              setDraft({ level, revision: draft?.revision ?? settings.revision });
              save.edit();
            }}
          >
            <option value="inherit">Inherit tenant default</option>
            {AUDIT_LEVELS.map((level) => (
              <option key={level.value} value={level.value}>
                {level.label}
              </option>
            ))}
          </Select>
          <p className="text-xs text-faint">
            {selected === null
              ? "Follows future changes to the tenant default."
              : AUDIT_LEVELS.find((level) => level.value === selected)?.description}
          </p>
          {preview !== settings.effectiveLevel && (
            <p role="status" className="text-sm text-muted">
              After saving: {auditLevelLabel(preview!)}
            </p>
          )}
          <Button
            disabled={
              query.isError ||
              (!settings.hasUnrecognizedSettings &&
                (save.status === "idle" || save.status === "saved"))
            }
            loading={save.status === "saving"}
            onClick={() => {
              const next = draft ?? { level: selected, revision: settings.revision };
              setDraft(next);
              save.commit(next);
            }}
          >
            Save profile audit
          </Button>
          <p className="text-xs text-faint">
            Configuration changes follow tenant audit settings. Retention and the master switch are
            managed in{" "}
            <Link href="/settings" className="text-accent underline">
              Settings → Audit
            </Link>
            .
          </p>
        </>
      )}
    </SectionCard>
  );
}
