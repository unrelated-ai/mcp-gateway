"use client";

import { type ReactNode } from "react";

export type Tone = "neutral" | "accent" | "ok" | "warn" | "danger" | "info";

interface BadgeProps {
  children: ReactNode;
  tone?: Tone;
  /** Square status LED in front of the text. Steady, never animated. */
  dot?: boolean;
  className?: string;
}

const toneStyles: Record<Tone, string> = {
  neutral: "bg-raised text-muted border-edge",
  accent: "bg-accent/10 text-accent border-accent/25",
  ok: "bg-ok/10 text-ok border-ok/25",
  warn: "bg-warn/10 text-warn border-warn/25",
  danger: "bg-danger/10 text-danger border-danger/25",
  info: "bg-info/10 text-info border-info/25",
};

export function Badge({ children, tone = "neutral", dot = false, className = "" }: BadgeProps) {
  return (
    <span
      className={`
        inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 border
        font-mono text-[11px] font-medium uppercase tracking-wide whitespace-nowrap
        ${toneStyles[tone]}
        ${className}
      `}
    >
      {dot && <span aria-hidden="true" className="size-1.5 rounded-[1px] bg-current" />}
      {children}
    </span>
  );
}

interface StatusBadgeProps {
  enabled: boolean;
  className?: string;
}

export function StatusBadge({ enabled, className = "" }: StatusBadgeProps) {
  return (
    <Badge tone={enabled ? "ok" : "neutral"} dot className={className}>
      {enabled ? "Enabled" : "Disabled"}
    </Badge>
  );
}

interface AuthModeBadgeProps {
  mode: "disabled" | "apiKey" | "oauth";
  className?: string;
}

const authModeLabels: Record<AuthModeBadgeProps["mode"], { label: string; tone: Tone }> = {
  disabled: { label: "No auth", tone: "warn" },
  apiKey: { label: "API key", tone: "info" },
  oauth: { label: "OAuth", tone: "accent" },
};

export function AuthModeBadge({ mode, className = "" }: AuthModeBadgeProps) {
  const { label, tone } = authModeLabels[mode];
  return (
    <Badge tone={tone} className={className}>
      {label}
    </Badge>
  );
}
