"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export function useCopyToClipboard(
  value: string,
  opts?: {
    resetAfterMs?: number;
  },
) {
  const resetAfterMs = opts?.resetAfterMs ?? 2000;
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (timerRef.current != null) window.clearTimeout(timerRef.current);
    };
  }, []);

  const copy = useCallback(async (): Promise<boolean> => {
    setError(null);
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
    } catch {
      try {
        // Fallback for older browsers
        const textarea = document.createElement("textarea");
        textarea.value = value;
        textarea.style.position = "fixed";
        textarea.style.left = "-10000px";
        textarea.style.top = "-10000px";
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
        setCopied(true);
      } catch {
        setError("Failed to copy");
        setCopied(false);
        return false;
      }
    }

    if (resetAfterMs > 0) {
      if (timerRef.current != null) window.clearTimeout(timerRef.current);
      timerRef.current = window.setTimeout(() => setCopied(false), resetAfterMs);
    }
    return true;
  }, [resetAfterMs, value]);

  return { copied, copy, error };
}
