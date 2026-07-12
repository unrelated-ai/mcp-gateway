"use client";

import { type ReactNode, useCallback, useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { WarningIcon, XIcon } from "@/components/icons";
import { Button } from "./button";
import { IconButton } from "./button";
import { Input } from "./input";
import { CopyBlock } from "./copy-block";

interface ModalProps {
  open: boolean;
  onClose: () => void;
  children: ReactNode;
  title?: string;
  description?: string;
  size?: "sm" | "md" | "lg" | "xl";
}

const sizeStyles = {
  sm: "max-w-sm",
  md: "max-w-md",
  lg: "max-w-lg",
  xl: "max-w-xl",
};

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function Modal({ open, onClose, children, title, description, size = "md" }: ModalProps) {
  const hasHeader = Boolean(title || description);
  const panelRef = useRef<HTMLDivElement>(null);
  const titleId = useId();

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
        return;
      }
      if (e.key === "Tab" && panelRef.current) {
        const focusables = panelRef.current.querySelectorAll<HTMLElement>(FOCUSABLE);
        if (focusables.length === 0) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        const active = document.activeElement;
        if (e.shiftKey && (active === first || active === panelRef.current)) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && active === last) {
          e.preventDefault();
          first.focus();
        }
      }
    },
    [onClose],
  );

  useEffect(() => {
    if (!open) return;
    document.addEventListener("keydown", handleKeyDown);
    document.body.style.overflow = "hidden";
    const previouslyFocused = document.activeElement as HTMLElement | null;
    panelRef.current?.focus();
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = "";
      previouslyFocused?.focus?.();
    };
  }, [open, handleKeyDown]);

  if (!open) return null;
  if (typeof document === "undefined") return null;

  return createPortal(
    <div className="fixed inset-0 z-[1000] flex items-center justify-center p-4">
      {/* Backdrop */}
      <div className="absolute inset-0 animate-fade bg-black/60" onClick={onClose} />

      {/* Panel */}
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title ? titleId : undefined}
        tabIndex={-1}
        className={`
          relative w-full ${sizeStyles[size]}
          max-h-[calc(100vh-2rem)] overflow-y-auto
          animate-rise rounded-xl border border-edge-strong bg-surface shadow-2xl shadow-black/50
          focus:outline-none
        `}
      >
        {hasHeader && (
          <div className="px-6 pt-6 pb-4">
            {title && (
              <h2 id={titleId} className="pr-8 text-base font-semibold text-fg">
                {title}
              </h2>
            )}
            {description && <p className="mt-1 text-sm text-muted">{description}</p>}
          </div>
        )}

        <div className={`px-6 pb-6 ${hasHeader ? "" : "pt-6"}`.trim()}>{children}</div>

        <IconButton label="Close" size="sm" onClick={onClose} className="absolute right-4 top-4">
          <XIcon className="size-4" />
        </IconButton>
      </div>
    </div>,
    document.body,
  );
}

interface ModalActionsProps {
  children: ReactNode;
  className?: string;
}

export function ModalActions({ children, className = "" }: ModalActionsProps) {
  return (
    <div
      className={`mt-6 flex items-center justify-end gap-3 border-t border-edge pt-4 ${className}`}
    >
      {children}
    </div>
  );
}

interface ConfirmModalProps {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  description: string;
  confirmLabel?: string;
  danger?: boolean;
  loading?: boolean;
  requireText?: string;
}

export function ConfirmModal({ open, ...rest }: ConfirmModalProps) {
  // Mount a fresh stateful inner component only while open so the typed
  // confirmation resets between uses (repo lint discourages setState in effects).
  if (!open) return null;
  return <ConfirmModalOpen {...rest} />;
}

function ConfirmModalOpen({
  onClose,
  onConfirm,
  title,
  description,
  confirmLabel = "Confirm",
  danger = false,
  loading = false,
  requireText,
}: Omit<ConfirmModalProps, "open">) {
  const [typed, setTyped] = useState("");

  const isTypedOk = !requireText || typed === requireText;

  return (
    <Modal open onClose={onClose} size="sm" title={title}>
      <div className="flex items-start gap-3">
        {danger && (
          <span className="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-md bg-danger/10">
            <WarningIcon className="size-4 text-danger" />
          </span>
        )}
        <p className="text-sm text-muted">{description}</p>
      </div>

      {requireText && (
        <div className="mt-5 space-y-3">
          <CopyBlock value={requireText} label="Type this to confirm" compact />
          <Input
            label="Confirmation"
            placeholder={requireText}
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            className="font-mono"
          />
          <p className="text-xs text-faint">Proceed is enabled only after an exact match.</p>
        </div>
      )}

      <ModalActions>
        <Button variant="ghost" onClick={onClose} disabled={loading}>
          Cancel
        </Button>
        <Button
          variant={danger ? "danger" : "primary"}
          onClick={onConfirm}
          loading={loading}
          disabled={!isTypedOk || loading}
        >
          {confirmLabel}
        </Button>
      </ModalActions>
    </Modal>
  );
}
