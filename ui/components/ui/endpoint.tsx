"use client";

import { useCopyToClipboard } from "@/src/lib/useCopyToClipboard";
import { CheckIcon, CopyIcon } from "@/components/icons";

interface EndpointWellProps {
  url: string;
  /** Drives the status LED: true = routing traffic, false = disabled. */
  live?: boolean;
  className?: string;
  /** Hide the LED for endpoints without an enabled/disabled state. */
  showLed?: boolean;
}

/**
 * The signature "patch panel" treatment for MCP endpoint URLs: a mono
 * connection string in an inset well with a square status LED and an
 * always-available copy control.
 */
export function EndpointWell({
  url,
  live = true,
  className = "",
  showLed = true,
}: EndpointWellProps) {
  const { copied, copy } = useCopyToClipboard(url);

  return (
    <div
      className={`
        flex items-center gap-2.5 rounded-md border border-edge bg-well px-3 py-2
        ${className}
      `}
    >
      {showLed && (
        <span
          aria-hidden="true"
          title={live ? "Live" : "Disabled"}
          className={`size-1.5 shrink-0 rounded-[1px] ${live ? "bg-ok" : "bg-faint/60"}`}
        />
      )}
      <code
        className={`min-w-0 flex-1 truncate font-mono text-[13px] ${live ? "text-fg" : "text-muted"}`}
      >
        {url}
      </code>
      <button
        type="button"
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          void copy();
        }}
        aria-label={copied ? "Copied" : "Copy endpoint URL"}
        className={`
          shrink-0 rounded p-1 transition-colors duration-150
          focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent
          ${copied ? "text-ok" : "text-faint hover:text-fg"}
        `}
      >
        {copied ? <CheckIcon className="size-4" /> : <CopyIcon className="size-4" />}
      </button>
    </div>
  );
}
