"use client";

import { type ReactNode } from "react";
import type { Tone } from "./badge";

type CalloutSize = "sm" | "md";

const toneStyles: Record<Tone, { border: string; bg: string; title: string; body: string }> = {
  neutral: {
    border: "border-edge",
    bg: "bg-raised/50",
    title: "text-fg",
    body: "text-muted",
  },
  accent: {
    border: "border-accent/25",
    bg: "bg-accent/5",
    title: "text-accent",
    body: "text-muted",
  },
  info: {
    border: "border-info/25",
    bg: "bg-info/5",
    title: "text-info",
    body: "text-muted",
  },
  ok: {
    border: "border-ok/25",
    bg: "bg-ok/5",
    title: "text-ok",
    body: "text-muted",
  },
  warn: {
    border: "border-warn/25",
    bg: "bg-warn/5",
    title: "text-warn",
    body: "text-muted",
  },
  danger: {
    border: "border-danger/25",
    bg: "bg-danger/5",
    title: "text-danger",
    body: "text-muted",
  },
};

const sizeStyles: Record<CalloutSize, string> = {
  sm: "p-3 text-xs",
  md: "p-4 text-sm",
};

export function Callout({
  tone = "neutral",
  size = "sm",
  title,
  children,
  className = "",
}: {
  tone?: Tone;
  size?: CalloutSize;
  title?: string;
  children: ReactNode;
  className?: string;
}) {
  const s = toneStyles[tone];
  return (
    <div className={`rounded-lg border ${s.border} ${s.bg} ${sizeStyles[size]} ${className}`}>
      {title ? <div className={`font-semibold ${s.title}`}>{title}</div> : null}
      <div className={`${title ? "mt-1 " : ""}${s.body}`}>{children}</div>
    </div>
  );
}

export function QueryParamAuthWarning({ className = "" }: { className?: string }) {
  return (
    <Callout tone="warn" title="Not recommended" className={className}>
      Query-parameter auth puts secrets in URLs, which can leak via logs, proxies, caches, or
      referrers. Prefer header-based auth (Bearer / custom header) whenever possible.
    </Callout>
  );
}
