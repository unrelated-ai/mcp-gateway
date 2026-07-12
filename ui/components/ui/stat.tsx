"use client";

import type { ReactNode } from "react";
import type { Tone } from "./badge";

const toneText: Record<Tone, string> = {
  neutral: "text-fg",
  accent: "text-accent",
  ok: "text-ok",
  warn: "text-warn",
  danger: "text-danger",
  info: "text-info",
};

/** Instrument-style stat readout: silkscreen label above a mono value. */
export function Stat({
  label,
  value,
  tone = "neutral",
  hint,
  className = "",
}: {
  label: string;
  value: ReactNode;
  tone?: Tone;
  hint?: string;
  className?: string;
}) {
  return (
    <div className={`rounded-lg border border-edge bg-surface px-4 py-3 ${className}`}>
      <div className="eyebrow">{label}</div>
      <div className={`mt-1 font-mono text-2xl font-medium ${toneText[tone]}`}>{value}</div>
      {hint && <div className="mt-0.5 text-xs text-faint">{hint}</div>}
    </div>
  );
}
