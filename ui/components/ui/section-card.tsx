"use client";

import type { ReactNode } from "react";

/**
 * Labeled panel: the standard section container on detail/settings pages.
 * The title renders as a mono "silkscreen" eyebrow label.
 */
export function SectionCard({
  title,
  subtitle,
  right,
  children,
  className,
  headerClassName,
  bodyClassName,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
  headerClassName?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={`rounded-lg border border-edge bg-surface ${className ?? ""}`.trim()}>
      {(title || subtitle || right) && (
        <div
          className={`flex flex-col items-start justify-between gap-4 sm:flex-row border-b border-edge px-5 py-3.5 ${
            headerClassName ?? ""
          }`.trim()}
        >
          <div className="min-w-0">
            {title ? <div className="eyebrow">{title}</div> : null}
            {subtitle ? <div className="mt-1 text-sm text-muted">{subtitle}</div> : null}
          </div>
          {right ? <div className="shrink-0">{right}</div> : null}
        </div>
      )}
      <div className={`p-5 ${bodyClassName ?? ""}`.trim()}>{children}</div>
    </section>
  );
}
