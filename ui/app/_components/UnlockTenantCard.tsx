"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { CheckCircleIconBold, CheckIcon, ExclamationIcon, UnlockIcon } from "@/components/icons";
import { Button, CopyBlock, Modal } from "@/components/ui";
import {
  decodeTenantTokenPayload,
  establishTenantSession,
  type TenantTokenPayloadV1,
} from "@/src/lib/tenant-session";

const unlockSchema = z.object({
  token: z.string().trim().min(1, "Tenant token is required"),
});

type UnlockForm = z.infer<typeof unlockSchema>;

/**
 * Only allow same-origin path redirects. `//evil.com` is a protocol-relative
 * external URL and must not pass (open redirect).
 */
function safeNextPath(raw: string | null): string {
  if (raw && raw.startsWith("/") && !raw.startsWith("//")) return raw;
  return "/profiles";
}

export function UnlockTenantCard() {
  const router = useRouter();
  const [isValidating, setIsValidating] = useState(false);
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [showResetHelp, setShowResetHelp] = useState(false);
  const [tokenDraft, setTokenDraft] = useState("");
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
    formState: { errors },
  } = useForm<UnlockForm>({
    resolver: zodResolver(unlockSchema),
    defaultValues: { token: "" },
  });

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

  const handleUnlock = async () => {
    if (!tokenInfo) return;
    setIsUnlocking(true);
    clearErrors("token");
    try {
      await establishTenantSession(getValues("token").trim());

      const next =
        typeof window !== "undefined"
          ? new URLSearchParams(window.location.search).get("next")
          : null;
      router.replace(safeNextPath(next));
    } catch (e) {
      setError("token", {
        type: "validate",
        message: e instanceof Error ? e.message : "Failed to unlock tenant session",
      });
    } finally {
      setIsUnlocking(false);
    }
  };

  return (
    <div className="overflow-hidden rounded-lg border border-edge bg-surface">
      <div className="p-6">
        <div className="eyebrow">Unlock tenant</div>

        <p className="mt-2 text-sm text-muted">
          Paste your tenant token to access the dashboard. This token grants administrative access
          to the tenant.
        </p>

        <textarea
          aria-label="Tenant token"
          {...register("token", {
            onChange: (event) => {
              setTokenDraft(event.target.value);
              setTokenInfo(null);
              clearErrors("token");
            },
          })}
          rows={4}
          placeholder="tv1.<payload_b64>.<sig_b64>"
          className="mt-4 w-full resize-none rounded-md border border-edge-strong bg-well p-4 font-mono text-sm text-fg transition-colors placeholder:text-faint hover:border-faint/40 focus:border-accent/60 focus:outline-none focus:ring-2 focus:ring-accent/60"
        />
        <p className="mt-2 text-xs text-faint">
          Token format:{" "}
          <code className="rounded bg-raised px-1.5 py-0.5 font-mono text-muted">
            tv1.&lt;payload_b64&gt;.&lt;sig_b64&gt;
          </code>
        </p>

        {errors.token?.message && (
          <div className="mt-3 flex items-start gap-2 rounded-lg border border-danger/25 bg-danger/5 p-3 text-sm">
            <ExclamationIcon className="mt-0.5 size-5 shrink-0 text-danger" />
            <div className="min-w-0">
              <div className="font-medium text-danger">Token invalid</div>
              <div className="mt-0.5 whitespace-pre-wrap break-words text-xs text-muted">
                {errors.token.message}
              </div>
            </div>
          </div>
        )}

        <Button
          variant="secondary"
          onClick={handleValidate}
          disabled={!tokenDraft.trim()}
          loading={isValidating}
          className="mt-4 w-full"
          size="lg"
        >
          {!isValidating && <CheckIcon className="size-4" />}
          {isValidating ? "Validating…" : "Validate token"}
        </Button>
      </div>

      {tokenInfo && (
        <div className="border-t border-edge bg-raised/40 p-6">
          <div className="mb-4 flex items-center gap-2 text-sm font-medium text-ok">
            <CheckCircleIconBold className="size-5" />
            Token validated
          </div>

          <div className="space-y-1">
            <InfoRow label="Tenant ID" value={tokenInfo.payload.tenant_id} highlight />
            <InfoRow label="Expires" value={formatDate(tokenInfo.expires_at)} />
          </div>

          <Button onClick={handleUnlock} loading={isUnlocking} className="mt-6 w-full" size="lg">
            {!isUnlocking && <UnlockIcon className="size-4" />}
            {isUnlocking ? "Unlocking…" : "Unlock and enter dashboard"}
          </Button>
        </div>
      )}

      <div className="border-t border-edge bg-well/60 p-4 text-xs text-faint">
        Can&apos;t find your tenant token? If you want to start over, reset the DB and then revisit
        this page to re-run onboarding.{" "}
        <button
          type="button"
          onClick={() => setShowResetHelp(true)}
          className="text-muted underline decoration-dotted underline-offset-4 transition-colors hover:text-fg"
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
      <div className="space-y-4 text-sm text-fg">
        <p className="text-muted">
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

        <p className="text-xs text-faint">
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
    <div className="flex items-center justify-between gap-4 border-b border-edge/60 py-2 last:border-0">
      <span className="text-sm text-muted">{label}</span>
      <span className={`font-mono text-sm ${highlight ? "font-medium text-fg" : "text-muted"}`}>
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
