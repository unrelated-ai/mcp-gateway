import type { AuditLevel, ProfileAuditSettingsResponse } from "./types";

export const AUDIT_LEVELS: { value: AuditLevel; label: string; description: string }[] = [
  { value: "off", label: "Off", description: "No new activity events are stored." },
  {
    value: "summary",
    label: "Summary",
    description:
      "Event identity, tool, caller, outcome, and timing. Additional metadata and error messages are omitted.",
  },
  {
    value: "metadata",
    label: "Metadata",
    description: "Summary fields plus event metadata and error details, without payload samples.",
  },
  {
    value: "payload",
    label: "Payload samples",
    description:
      "Metadata plus bounded samples when a transport limit is exceeded. Full tool request and response bodies are not recorded.",
  },
];

export function auditLevelLabel(value: AuditLevel): string {
  return AUDIT_LEVELS.find((level) => level.value === value)!.label;
}

export function previewProfileAuditLevel(
  tenant: ProfileAuditSettingsResponse["tenantSettings"],
  override: AuditLevel | null,
): AuditLevel {
  return !tenant.enabled || tenant.defaultLevel === "off"
    ? "off"
    : (override ?? tenant.defaultLevel);
}
