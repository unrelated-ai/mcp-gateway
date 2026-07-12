"use client";

import { useCopyToClipboard } from "@/src/lib/useCopyToClipboard";
import { CheckIcon, CopyIcon } from "@/components/icons";
import { IconButton } from "./button";

export function CopyButton({
  value,
  className = "",
  copiedLabel = "Copied",
  label = "Copy",
  size = "sm",
  variant = "button",
}: {
  value: string;
  className?: string;
  label?: string;
  copiedLabel?: string;
  size?: "sm" | "md";
  variant?: "button" | "icon";
}) {
  const { copied, copy } = useCopyToClipboard(value);

  if (variant === "icon") {
    return (
      <IconButton
        label={copied ? copiedLabel : label}
        size={size === "md" ? "md" : "sm"}
        onClick={() => void copy()}
        className={className}
      >
        {copied ? <CheckIcon className="size-4 text-ok" /> : <CopyIcon className="size-4" />}
      </IconButton>
    );
  }

  return (
    <button
      onClick={() => void copy()}
      type="button"
      className={`
        inline-flex items-center gap-1.5 rounded-md border border-edge-strong bg-raised
        px-2.5 text-xs font-medium text-muted
        transition-colors duration-150 hover:bg-overlay hover:text-fg
        focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-bg
        ${size === "md" ? "h-9" : "h-8"}
        ${className}
      `.trim()}
    >
      {copied ? (
        <>
          <CheckIcon className="size-3.5 text-ok" />
          {copiedLabel}
        </>
      ) : (
        <>
          <CopyIcon className="size-3.5" />
          {label}
        </>
      )}
    </button>
  );
}
