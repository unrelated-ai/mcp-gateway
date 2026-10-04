"use client";

import { useId, type ReactNode } from "react";

export interface TabItem<T extends string = string> {
  value: T;
  label: ReactNode;
  /** Small mono counter or badge rendered after the label. */
  count?: number;
  disabled?: boolean;
}

interface TabsProps<T extends string> {
  items: readonly TabItem<T>[];
  value: T;
  onChange: (value: T) => void;
  className?: string;
}

/**
 * Horizontal tab bar. Renders only the tablist — callers render the active
 * panel themselves (pass `id`/`aria-labelledby` via panelProps if needed).
 */
export function Tabs<T extends string>({ items, value, onChange, className = "" }: TabsProps<T>) {
  const baseId = useId();

  const moveFocus = (from: number, delta: number) => {
    const enabled = items.filter((t) => !t.disabled);
    if (enabled.length === 0) return;
    const currentEnabledIdx = enabled.findIndex((t) => t.value === items[from].value);
    const next = enabled[(currentEnabledIdx + delta + enabled.length) % enabled.length];
    onChange(next.value);
    document.getElementById(`${baseId}-tab-${next.value}`)?.focus();
  };

  return (
    <div
      role="tablist"
      className={`flex max-w-full items-center gap-1 overflow-x-auto border-b border-edge ${className}`}
    >
      {items.map((item, i) => {
        const active = item.value === value;
        return (
          <button
            key={item.value}
            id={`${baseId}-tab-${item.value}`}
            role="tab"
            type="button"
            aria-selected={active}
            tabIndex={active ? 0 : -1}
            disabled={item.disabled}
            onClick={() => onChange(item.value)}
            onKeyDown={(e) => {
              if (e.key === "ArrowRight") moveFocus(i, 1);
              if (e.key === "ArrowLeft") moveFocus(i, -1);
            }}
            className={`
              relative -mb-px inline-flex shrink-0 items-center gap-2 whitespace-nowrap px-3 py-2.5 text-sm font-medium
              border-b-2 transition-colors duration-150
              focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-inset
              disabled:opacity-40 disabled:cursor-not-allowed
              ${
                active
                  ? "border-accent text-fg"
                  : "border-transparent text-muted hover:text-fg hover:border-edge-strong"
              }
            `}
          >
            {item.label}
            {item.count != null && (
              <span className={`font-mono text-[11px] ${active ? "text-accent" : "text-faint"}`}>
                {item.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}
