"use client";

import { type ReactNode } from "react";
import { Button } from "./button";

interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: {
    label: string;
    onClick: () => void;
  };
}

export function EmptyState({ icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-edge-strong px-4 py-12 text-center">
      {icon && (
        <div className="mb-4 flex size-12 items-center justify-center rounded-lg border border-edge bg-raised text-muted">
          {icon}
        </div>
      )}
      <h3 className="text-sm font-semibold text-fg">{title}</h3>
      {description && <p className="mt-1 max-w-sm text-sm text-muted">{description}</p>}
      {action && (
        <Button onClick={action.onClick} className="mt-4" size="sm">
          {action.label}
        </Button>
      )}
    </div>
  );
}

// Icon re-exports kept for backwards compatibility with existing call sites.
export { FolderIcon, KeyIcon, LockIcon, ServerIconStack as ServerIcon } from "@/components/icons";
