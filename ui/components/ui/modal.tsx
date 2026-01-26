"use client";

import { type ReactNode, useEffect, useCallback, useState } from "react";
import { createPortal } from "react-dom";
import { Button } from "./button";
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

export function Modal({ open, onClose, children, title, description, size = "md" }: ModalProps) {
  const hasHeader = Boolean(title || description);
  const handleEscape = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    },
    [onClose],
  );

  useEffect(() => {
    if (open) {
      document.addEventListener("keydown", handleEscape);
      document.body.style.overflow = "hidden";
    }
    return () => {
      document.removeEventListener("keydown", handleEscape);
      document.body.style.overflow = "";
    };
  }, [open, handleEscape]);

  if (!open) return null;

  if (typeof document === "undefined") return null;

  return createPortal(
    <div className="fixed inset-0 z-[1000] flex items-center justify-center p-4">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm animate-in fade-in duration-200"
        onClick={onClose}
      />

      {/* Modal */}
      <div
        className={`
          relative w-full ${sizeStyles[size]}
          max-h-[calc(100vh-2rem)] overflow-y-auto
          bg-zinc-900 border border-zinc-800 rounded-2xl shadow-2xl shadow-black/50
          animate-in fade-in zoom-in-95 duration-200
        `}
      >
        {/* Header */}
        {hasHeader && (
          <div className="px-6 pt-6 pb-4">
            {title && <h2 className="text-lg font-semibold text-zinc-100">{title}</h2>}
            {description && <p className="mt-1 text-sm text-zinc-400">{description}</p>}
          </div>
        )}

        {/* Content */}
        <div className={`px-6 pb-6 ${hasHeader ? "" : "pt-6"}`.trim()}>{children}</div>

        {/* Close button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1.5 rounded-lg text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800 transition-colors"
        >
          <XIcon className="w-5 h-5" />
        </button>
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
      className={`flex items-center justify-end gap-3 mt-6 pt-4 border-t border-zinc-800 ${className}`}
    >
      {children}
    </div>
  );
}

// Confirmation modal helper
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
  // Lint rule in this repo discourages setState in effects; instead, we mount a fresh
  // stateful inner component only when open.
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
    <Modal open onClose={onClose} size="sm">
      <div className="text-center">
        <div
          className={`
            mx-auto w-12 h-12 rounded-full flex items-center justify-center
            ${danger ? "bg-red-500/10" : "bg-violet-500/10"}
          `}
        >
          {danger ? (
            <AlertIcon className="w-6 h-6 text-red-400" />
          ) : (
            <QuestionIcon className="w-6 h-6 text-violet-400" />
          )}
        </div>
        <h3 className="mt-4 text-lg font-semibold text-zinc-100">{title}</h3>
        <p className="mt-2 text-sm text-zinc-400">{description}</p>
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
          <p className="text-xs text-zinc-500 text-center">
            Proceed is enabled only after an exact match.
          </p>
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

function XIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth={2}
    >
      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
    </svg>
  );
}

function AlertIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth={2}
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
      />
    </svg>
  );
}

function QuestionIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth={2}
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
      />
    </svg>
  );
}
