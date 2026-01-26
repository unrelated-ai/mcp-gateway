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
  const textAlign = switchSide === "right" ? "text-right items-end" : "text-left items-start";

  const Switch = (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => !disabled && onChange(!checked)}
      className={`
        relative inline-flex h-6 w-11 shrink-0 items-center rounded-full
        transition-colors duration-200 ease-in-out
        focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-violet-500 focus-visible:ring-offset-2 focus-visible:ring-offset-zinc-900
        ${checked ? "bg-violet-600" : "bg-zinc-700"}
        ${disabled ? "pointer-events-none" : ""}
      `}
    >
      <span
        className={`
          inline-block h-4 w-4 transform rounded-full bg-white shadow-lg
          transition-transform duration-200 ease-in-out
          ${checked ? "translate-x-6" : "translate-x-1"}
        `}
      />
    </button>
  );

  const Text =
    hasText ? (
      <div className={`flex flex-col ${textAlign}`.trim()}>
        {label && <span className="text-sm font-medium text-zinc-200">{label}</span>}
        {description && <span className="text-xs text-zinc-500">{description}</span>}
      </div>
    ) : null;

  return (
    <label
      className={`flex items-start gap-3 ${disabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}`}
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
