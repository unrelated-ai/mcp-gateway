"use client";

import { type ReactNode, useCallback, useEffect, useId, useRef } from "react";
import { createPortal } from "react-dom";
import { XIcon } from "@/components/icons";
import { IconButton } from "./button";

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

interface DrawerProps {
  open: boolean;
  onClose: () => void;
  children: ReactNode;
  title?: ReactNode;
  description?: ReactNode;
  /** Panel width; defaults to a detail-inspector width. */
  widthClassName?: string;
}

/** Right-side inspector panel for record details (audit events, etc.). */
export function Drawer({
  open,
  onClose,
  children,
  title,
  description,
  widthClassName = "max-w-xl",
}: DrawerProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const titleId = useId();

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
        return;
      }
      if (e.key !== "Tab" || !panelRef.current) return;

      const focusables = panelRef.current.querySelectorAll<HTMLElement>(FOCUSABLE);
      if (focusables.length === 0) {
        e.preventDefault();
        panelRef.current.focus();
        return;
      }

      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      const active = document.activeElement;
      const focusOutsidePanel = active instanceof Node && !panelRef.current.contains(active);

      if (e.shiftKey && (active === first || active === panelRef.current || focusOutsidePanel)) {
        e.preventDefault();
        last.focus();
      } else if (
        !e.shiftKey &&
        (active === last || active === panelRef.current || focusOutsidePanel)
      ) {
        e.preventDefault();
        first.focus();
      }
    },
    [onClose],
  );

  useEffect(() => {
    if (!open) return;
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const previousOverflow = document.body.style.overflow;
    document.addEventListener("keydown", handleKeyDown);
    document.body.style.overflow = "hidden";
    panelRef.current?.focus();
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = previousOverflow;
      if (previouslyFocused?.isConnected) previouslyFocused.focus();
    };
  }, [open, handleKeyDown]);

  if (!open) return null;
  if (typeof document === "undefined") return null;

  return createPortal(
    <div className="fixed inset-0 z-[1000] overscroll-contain">
      <div className="absolute inset-0 animate-fade bg-black/60" onClick={onClose} />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title ? titleId : undefined}
        tabIndex={-1}
        className={`
          absolute inset-y-0 right-0 w-full ${widthClassName}
          flex flex-col border-l border-edge-strong bg-surface shadow-2xl shadow-black/50
          animate-rise focus:outline-none
        `}
      >
        <div className="flex items-start justify-between gap-4 border-b border-edge px-5 py-4">
          <div className="min-w-0">
            {title && (
              <h2 id={titleId} className="text-sm font-semibold text-fg">
                {title}
              </h2>
            )}
            {description && <div className="mt-0.5 text-xs text-muted">{description}</div>}
          </div>
          <IconButton label="Close" size="sm" onClick={onClose}>
            <XIcon className="size-4" />
          </IconButton>
        </div>
        <div className="flex-1 overflow-y-auto p-5">{children}</div>
      </div>
    </div>,
    document.body,
  );
}
