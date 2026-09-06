"use client";

import type { SaveStatus as Status } from "@/src/lib/useAutosave";
import { Button } from "./button";

export function SaveStatus({
  status,
  error,
  onRetry,
  label = "Changes",
}: {
  status: Status;
  error: string | null;
  onRetry: () => void;
  label?: string;
}) {
  return (
    <div role="status" aria-label={`${label} save status`} className="text-xs text-muted">
      {status === "unsaved" ? "Unsaved changes" : null}
      {status === "saving" ? "Saving…" : null}
      {status === "saved" ? "Saved" : null}
      {status === "error" ? (
        <div className="flex flex-wrap items-center gap-2 text-danger">
          <span>Not saved. {error}</span>
          <Button variant="secondary" size="sm" onClick={onRetry}>
            Retry save
          </Button>
        </div>
      ) : null}
    </div>
  );
}
