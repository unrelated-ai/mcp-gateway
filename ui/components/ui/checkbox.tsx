"use client";

import { type ReactNode } from "react";

type CheckboxSize = "sm" | "md";

export function Checkbox({
  checked,
  onChange,
  label,
  description,
  disabled = false,
  size = "md",
  className = "",
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label?: ReactNode;
  description?: ReactNode;
  disabled?: boolean;
  size?: CheckboxSize;
  className?: string;
}) {
  const boxSize = size === "sm" ? "size-4" : "size-5";
  const iconSize = size === "sm" ? "size-3" : "size-3.5";

  return (
    <label
      className={`flex items-start gap-3 ${disabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer"} ${className}`}
    >
      <input
        type="checkbox"
        className="sr-only peer"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span
        className={`
          ${boxSize} shrink-0 rounded flex items-center justify-center border
          transition-colors duration-150
          border-edge-strong bg-well
          peer-checked:border-accent/60 peer-checked:bg-accent/15
          peer-focus-visible:ring-2 peer-focus-visible:ring-accent peer-focus-visible:ring-offset-2 peer-focus-visible:ring-offset-bg
        `}
      >
        <CheckIcon
          className={`${iconSize} ${checked ? "opacity-100" : "opacity-0"} text-accent transition-opacity duration-150`}
        />
      </span>

      {(label || description) && (
        <div className="flex min-w-0 flex-col">
          {label ? <span className="text-sm font-medium text-fg">{label}</span> : null}
          {description ? <span className="text-xs text-faint">{description}</span> : null}
        </div>
      )}
    </label>
  );
}

function CheckIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <path
        fillRule="evenodd"
        d="M16.704 5.29a1 1 0 010 1.42l-7.25 7.25a1 1 0 01-1.42 0l-3.25-3.25a1 1 0 011.42-1.42l2.54 2.54 6.54-6.54a1 1 0 011.42 0z"
        clipRule="evenodd"
      />
    </svg>
  );
}
