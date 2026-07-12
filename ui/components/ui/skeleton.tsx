"use client";

/** Loading placeholder block. Size with className (h-*, w-*). */
export function Skeleton({ className = "" }: { className?: string }) {
  return (
    <div
      aria-hidden="true"
      className={`animate-pulse rounded-md bg-raised motion-reduce:animate-none ${className}`}
    />
  );
}

/** Standard list-page loading state: a few stacked row placeholders. */
export function SkeletonRows({ rows = 3 }: { rows?: number }) {
  return (
    <div className="space-y-3" role="status" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-20 w-full" />
      ))}
    </div>
  );
}
