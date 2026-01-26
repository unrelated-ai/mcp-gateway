"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { CheckCircleIconBold, CheckIcon, ExclamationIcon, UnlockIcon } from "@/components/icons";
import { CopyBlock, Modal } from "@/components/ui";
import {
  decodeTenantTokenPayload,
  setTenantSessionCookies,
  type TenantTokenPayloadV1,
} from "@/src/lib/tenant-session";

const unlockSchema = z.object({
  token: z.string().trim().min(1, "Tenant token is required"),
});

type UnlockForm = z.infer<typeof unlockSchema>;

export function UnlockTenantCard() {
  const router = useRouter();
  const [isValidating, setIsValidating] = useState(false);
  const [showResetHelp, setShowResetHelp] = useState(false);
  const [tokenInfo, setTokenInfo] = useState<{
    payload: TenantTokenPayloadV1;
    expires_at: string;
  } | null>(null);
  const {
    register,
    handleSubmit,
    getValues,
    setError,
    clearErrors,
    watch,
    formState: { errors },
  } = useForm<UnlockForm>({
    resolver: zodResolver(unlockSchema),
    defaultValues: { token: "" },
  });

  const token = watch("token");

  const handleValidate = handleSubmit((values) => {
    setIsValidating(true);
    setTokenInfo(null);
    clearErrors("token");

    // v0 validation: local decode only.
    setTimeout(() => {
      try {
        const payload = decodeTenantTokenPayload(values.token);
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp_unix_secs <= now) {
          throw new Error(
            `Token expired (${new Date(payload.exp_unix_secs * 1000).toLocaleString()}). Issue a new token and try again.`,
          );
        }
        const expires_at = new Date(payload.exp_unix_secs * 1000).toISOString();
        setTokenInfo({ payload, expires_at });
      } catch (e) {
        setTokenInfo(null);
        setError("token", {
          type: "validate",
          message: e instanceof Error ? e.message : "Invalid token",
        });
      } finally {
        setIsValidating(false);
      }
    }, 250);
  });

  const handleUnlock = () => {
    if (!tokenInfo) return;
    setTenantSessionCookies(getValues("token").trim(), tokenInfo.payload);

    const next =
      typeof window !== "undefined"
        ? new URLSearchParams(window.location.search).get("next")
        : null;
    router.replace(next && next.startsWith("/") ? next : "/profiles");
  };

  return (
    <div className="rounded-2xl border border-zinc-800/80 bg-zinc-900/60 backdrop-blur-sm overflow-hidden">
      <div className="p-6">
        <div className="flex items-center justify-between gap-4">
          <h2 className="text-sm font-semibold text-zinc-100">Unlock tenant</h2>
        </div>

        <p className="mt-2 text-sm text-zinc-400">
          Paste your tenant token to access the dashboard. This token grants administrative access
          to the tenant.
        </p>

        <textarea
          aria-label="Tenant token"
          {...register("token", {
            onChange: () => {
              setTokenInfo(null);
              clearErrors("token");
            },
          })}
          rows={4}
          placeholder="tv1.<payload_b64>.<sig_b64>"
          className="w-full rounded-xl border border-zinc-800 bg-zinc-950/80 p-4 font-mono text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:ring-2 focus:ring-violet-500/50 focus:border-violet-500/50 transition-all resize-none"
        />
        <p className="mt-2 text-xs text-zinc-500">
          Token format:{" "}
          <code className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400">
            tv1.&lt;payload_b64&gt;.&lt;sig_b64&gt;
          </code>
        </p>

        {errors.token?.message && (
          <div className="mt-3 flex items-start gap-2 rounded-xl bg-red-500/5 border border-red-500/20 p-3 text-sm text-red-300">
            <ExclamationIcon className="w-5 h-5 shrink-0 mt-0.5 text-red-400" />
            <div className="min-w-0">
              <div className="font-medium text-red-300">Token invalid</div>
              <div className="text-xs text-red-300/80 mt-0.5 break-words whitespace-pre-wrap">
                {errors.token.message}
              </div>
            </div>
          </div>
        )}

        <button
          onClick={handleValidate}
          disabled={!token.trim() || isValidating}
          className="mt-4 w-full inline-flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-zinc-800 text-zinc-100 font-medium border border-zinc-700 hover:bg-zinc-700 hover:border-zinc-600 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-150"
        >
          {isValidating ? (
            <>
              <LoadingSpinner className="w-4 h-4" />
              Validating...
            </>
          ) : (
            <>
              <CheckIcon className="w-4 h-4" />
              Validate Token
            </>
          )}
        </button>
      </div>

      {tokenInfo && (
        <div className="border-t border-zinc-800/80 bg-zinc-900/40 p-6">
          <div className="flex items-center gap-2 text-sm font-medium text-emerald-400 mb-4">
            <CheckCircleIconBold className="w-5 h-5" />
            Token validated successfully
          </div>

          <div className="space-y-3">
            <InfoRow label="Tenant ID" value={tokenInfo.payload.tenant_id} highlight />
            <InfoRow label="Expires" value={formatDate(tokenInfo.expires_at)} />
          </div>

          <button
            onClick={handleUnlock}
            className="mt-6 w-full inline-flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-gradient-to-b from-violet-500 to-violet-600 text-white font-medium shadow-lg shadow-violet-500/25 hover:from-violet-400 hover:to-violet-500 transition-all duration-150"
          >
            <UnlockIcon className="w-5 h-5" />
            Unlock &amp; Enter Dashboard
          </button>
        </div>
      )}

      <div className="border-t border-zinc-800/80 bg-zinc-950/30 p-4 text-xs text-zinc-500">
        Can&apos;t find your tenant token? If you want to start over, reset the DB and then revisit
        this page to re-run onboarding.{" "}
        <button
          type="button"
          onClick={() => setShowResetHelp(true)}
          className="text-zinc-300 hover:text-white underline decoration-dotted underline-offset-4"
        >
          I want to know how
        </button>
      </div>

      <ResetDbHelpModal open={showResetHelp} onClose={() => setShowResetHelp(false)} />
    </div>
  );
}

function ResetDbHelpModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Reset the DB (start over)"
      description="This deletes ALL tenants and configuration in the docker-compose Postgres DB."
      size="lg"
    >
      <div className="space-y-4 text-sm text-zinc-300">
        <p className="text-zinc-400">
          If you manage the machine running the stack (local/dev), you can wipe the database so the
          Gateway boots into onboarding again.
        </p>

        <CopyBlock
          label="Recommended (Makefile)"
          language="bash"
          value={`make up-reset\nmake up`}
        />

        <CopyBlock
          label="Docker Compose (equivalent)"
          language="bash"
          value={`docker compose --profile manual run --rm gateway_db_reset\ndocker compose up -d --build`}
        />

        <p className="text-xs text-zinc-500">
          After resetting, refresh this page. Onboarding will appear only if bootstrap is enabled
          and the DB has zero tenants.
        </p>
      </div>
    </Modal>
  );
}

function InfoRow({
  label,
  value,
  highlight = false,
}: {
  label: string;
  value: string;
  highlight?: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-4 py-2 border-b border-zinc-800/40 last:border-0">
      <span className="text-sm text-zinc-400">{label}</span>
      <span
        className={`text-sm font-mono ${highlight ? "text-white font-medium" : "text-zinc-300"}`}
      >
        {value}
      </span>
    </div>
  );
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function LoadingSpinner({ className }: { className?: string }) {
  return (
    <svg className={`animate-spin ${className}`} fill="none" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
      />
    </svg>
  );
}
