"use client";

const sizeStyles = {
  sm: "size-3.5",
  md: "size-4",
  lg: "size-6",
} as const;

export function Spinner({
  size = "md",
  className = "",
}: {
  size?: keyof typeof sizeStyles;
  className?: string;
}) {
  return (
    <svg
      className={`animate-spin ${sizeStyles[size]} ${className}`.trim()}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V1C5.925 1 1 5.925 1 12h3z"
      />
    </svg>
  );
}
