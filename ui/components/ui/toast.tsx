"use client";

import { useToastStore } from "@/src/lib/toast-store";
import { XIcon } from "@/components/icons";

const toneBar = {
  success: "before:bg-ok",
  error: "before:bg-danger",
  info: "before:bg-info",
} as const;

export function ToastViewport() {
  const toasts = useToastStore((s) => s.toasts);
  const dismiss = useToastStore((s) => s.dismiss);

  return (
    <div
      aria-live="polite"
      className="fixed bottom-4 right-4 z-[1100] w-[360px] max-w-[calc(100vw-2rem)] space-y-2"
    >
      {toasts.map((t) => (
        <div
          key={t.id}
          role="status"
          className={`
            relative overflow-hidden rounded-lg border border-edge-strong bg-overlay
            shadow-lg shadow-black/40 animate-rise
            before:absolute before:inset-y-0 before:left-0 before:w-0.5
            ${toneBar[t.variant] ?? toneBar.info}
          `}
        >
          <div className="flex items-start gap-3 p-4">
            <div className="min-w-0 flex-1">
              {t.title && <div className="text-sm font-semibold text-fg">{t.title}</div>}
              <div className="break-words text-sm text-muted">{t.message}</div>
            </div>
            <button
              onClick={() => dismiss(t.id)}
              className="shrink-0 rounded-md p-1.5 text-faint transition-colors hover:bg-raised hover:text-fg"
              aria-label="Dismiss"
            >
              <XIcon className="size-4" />
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}
