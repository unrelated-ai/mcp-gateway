"use client";

import Link from "next/link";
import { UnlockTenantCard } from "../_components/UnlockTenantCard";
import { ArrowLeftIcon, WarningIcon } from "@/components/icons";

export default function UnlockPage() {
  return (
    <div className="flex min-h-full items-center justify-center bg-bg p-6">
      <div className="w-full max-w-2xl">
        {/* Header */}
        <div className="mb-8 text-center">
          <Link
            href="/"
            className="mb-6 inline-flex items-center gap-2 text-sm text-faint transition-colors hover:text-fg"
          >
            <ArrowLeftIcon className="size-4" />
            Back to home
          </Link>

          <h1 className="text-2xl font-semibold text-fg">Unlock tenant</h1>
          <p className="mx-auto mt-2 max-w-sm text-sm text-muted">
            Paste your tenant token to access the Gateway dashboard.
          </p>
        </div>

        <UnlockTenantCard />

        {/* Warning */}
        <div className="mt-6 flex items-start gap-3 rounded-lg border border-warn/25 bg-warn/5 p-4">
          <WarningIcon className="mt-0.5 size-5 shrink-0 text-warn" />
          <div>
            <p className="text-sm font-medium text-warn">Full tenant access</p>
            <p className="mt-1 text-xs text-muted">
              This token grants administrative privileges to the tenant. Keep it secure and avoid
              sharing it. This UI stores the session in this browser.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
