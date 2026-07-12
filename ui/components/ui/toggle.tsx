"use client";

interface ToggleProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label?: string;
  description?: string;
  disabled?: boolean;
  switchSide?: "left" | "right";
}

export function Toggle({
  checked,
  onChange,
  label,
  description,
  disabled = false,
  switchSide = "left",
}: ToggleProps) {
  const hasText = Boolean(label || description);
  const isSingleLine = Boolean(label) && !description;
  const textAlign = switchSide === "right" ? "text-right items-end" : "text-left items-start";

  const Switch = (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => !disabled && onChange(!checked)}
      className={`
        relative inline-flex h-5 w-9 shrink-0 items-center rounded-full
        transition-colors duration-150
        focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-bg
        ${checked ? "bg-accent-strong" : "bg-edge-strong"}
        ${disabled ? "pointer-events-none" : ""}
      `}
    >
      <span
        className={`
          inline-block size-3.5 transform rounded-full bg-white
          transition-transform duration-150
          ${checked ? "translate-x-[18px]" : "translate-x-[3px]"}
        `}
      />
    </button>
  );

  const Text = hasText ? (
    <div className={`flex flex-col ${textAlign}`.trim()}>
      {label && <span className="text-sm font-medium text-fg">{label}</span>}
      {description && <span className="text-xs text-faint">{description}</span>}
    </div>
  ) : null;

  return (
    <label
      className={`flex ${isSingleLine ? "items-center" : "items-start"} gap-3 ${disabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}`}
    >
      {switchSide === "right" ? (
        <>
          {Text}
          {Switch}
        </>
      ) : (
        <>
          {Switch}
          {Text}
        </>
      )}
    </label>
  );
}
