"use client";

import { type ReactNode } from "react";

type CalloutTone = "neutral" | "info" | "success" | "warning" | "danger";
type CalloutSize = "sm" | "md";

const toneStyles: Record<CalloutTone, { border: string; bg: string; title: string; body: string }> =
  {
    neutral: {
      border: "border-zinc-800/60",
      bg: "bg-zinc-950/30",
      title: "text-zinc-200",
      body: "text-zinc-400",
    },
    info: {
      border: "border-sky-500/20",
      bg: "bg-sky-500/5",
      title: "text-sky-200",
      body: "text-sky-200/80",
    },
    success: {
      border: "border-emerald-500/20",
      bg: "bg-emerald-500/5",
      title: "text-emerald-200",
      body: "text-emerald-200/80",
    },
    warning: {
      border: "border-amber-500/20",
      bg: "bg-amber-500/5",
      title: "text-amber-200",
      body: "text-amber-200/80",
    },
    danger: {
      border: "border-red-500/20",
      bg: "bg-red-500/5",
      title: "text-red-200",
      body: "text-red-200/80",
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
  tone?: CalloutTone;
  size?: CalloutSize;
  title?: string;
  children: ReactNode;
  className?: string;
}) {
  const s = toneStyles[tone];
  return (
    <div className={`rounded-xl border ${s.border} ${s.bg} ${sizeStyles[size]} ${className}`}>
      {title ? <div className={`font-semibold ${s.title}`}>{title}</div> : null}
      <div className={`${title ? "mt-1 " : ""}${s.body}`}>{children}</div>
    </div>
  );
}

export function QueryParamAuthWarning({ className = "" }: { className?: string }) {
  return (
    <Callout tone="warning" title="Not recommended" className={className}>
      Query-parameter auth puts secrets in URLs, which can leak via logs, proxies, caches, or
      referrers. Prefer header-based auth (Bearer / custom header) whenever possible.
    </Callout>
  );
}
