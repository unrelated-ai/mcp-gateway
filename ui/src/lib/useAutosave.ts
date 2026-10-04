"use client";

import { useRef, useState } from "react";

export type SaveStatus = "idle" | "unsaved" | "saving" | "saved" | "error";

/** Profile writes are serialized by updateProfile. Keep the latest draft's UI
 * independent of older completions, and retry only when the user requests it.
 */
export function useAutosave<T>(save: (value: T) => Promise<unknown>) {
  const revision = useRef(0);
  const lastSubmitted = useRef<{ value: T } | null>(null);
  const [status, setStatus] = useState<SaveStatus>("idle");
  const [error, setError] = useState<string | null>(null);

  const edit = () => {
    revision.current += 1;
    setStatus("unsaved");
    setError(null);
  };

  const commit = (value: T) => {
    const current = ++revision.current;
    lastSubmitted.current = { value };
    setStatus("saving");
    setError(null);
    void save(value).then(
      () => {
        if (current === revision.current) setStatus("saved");
      },
      (cause: unknown) => {
        if (current !== revision.current) return;
        setError(cause instanceof Error ? cause.message : "Could not save changes");
        setStatus("error");
      },
    );
  };

  return {
    status,
    error,
    edit,
    commit,
    retry: () => {
      if (lastSubmitted.current) commit(lastSubmitted.current.value);
    },
  };
}
