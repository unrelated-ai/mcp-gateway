"use client";

import { useEffect, useMemo, useState } from "react";
import { CheckIcon, CopyIcon, SparkIcon } from "@/components/icons";
import { Button, Callout, CopyBlock } from "@/components/ui";
import { useCopyToClipboard } from "@/src/lib/useCopyToClipboard";

const STORAGE_KEY = "ugw_onboarding_step_v1";

type Step = 1 | 2 | 3 | 4;

type BootstrapStatusResponse =
  | { ok: true; canBootstrap: boolean }
  | { ok: false; error?: string; status?: number; body?: string };

export default function OnboardingPage() {
  const [step, setStep] = useState<Step>(1);
  const [hasRestoredProgress, setHasRestoredProgress] = useState(false);
  const [createLoading, setCreateLoading] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const [token, setToken] = useState<string | null>(null);
  const [tokenCopied, setTokenCopied] = useState(false);

  // Extra safety: in case the page is reached via cached navigation/back button,
  // redirect away if bootstrapping is no longer allowed.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch("/api/bootstrap/status", { cache: "no-store" });
        if (!res.ok) return;
        const json = (await res.json()) as BootstrapStatusResponse;
        if (!cancelled && json.ok === true && json.canBootstrap === false) {
          window.location.replace("/");
        }
      } catch {
        // ignore
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Load persisted wizard progress.
  useEffect(() => {
    let frame = 0;
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      const n = raw ? Number(raw) : NaN;
      // This page only renders on fresh install (no tenants), so step 4 is never a valid resume state.
      const next: Step = n === 2 ? 2 : n === 3 ? 3 : 1;
      frame = window.requestAnimationFrame(() => {
        setStep(next);
        setHasRestoredProgress(true);
      });
    } catch {
      frame = window.requestAnimationFrame(() => {
        setStep(1);
        setHasRestoredProgress(true);
      });
    }
    return () => {
      if (frame) {
        window.cancelAnimationFrame(frame);
      }
    };
  }, []);

  // Persist step progress (best-effort).
  useEffect(() => {
    if (!hasRestoredProgress) return;
    try {
      localStorage.setItem(STORAGE_KEY, String(step));
    } catch {
      // ignore
    }
  }, [hasRestoredProgress, step]);

  const title = useMemo(() => {
    switch (step) {
      case 1:
        return "Tenant";
      case 2:
        return "Profile";
      case 3:
        return "Create your first tenant";
      case 4:
        return "Save your tenant token";
      default:
        return "Onboarding";
    }
  }, [step]);

  const stepLabel = useMemo(() => `Step ${step} of 4`, [step]);

  const goNext = () => {
    setCreateError(null);
    setTokenCopied(false);
    setStep((s) => (s < 4 ? ((s + 1) as Step) : s));
  };

  const createTenant = async () => {
    setCreateLoading(true);
    setCreateError(null);
    try {
      const res = await fetch("/api/bootstrap/tenant", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          // v0: a stable default tenant id. This is not exposed publicly; the token is what matters.
          tenantId: "default",
          // Long-lived tenant token for onboarding (you must save it; UI does not store it server-side).
          ttlSeconds: 31536000,
          // createProfile defaults to true on the server (creates a starter profile automatically).
        }),
      });
      const text = await res.text();
      if (!res.ok) {
        throw new Error(text);
      }
      const json = JSON.parse(text) as unknown as { token?: string };
      if (!json.token || typeof json.token !== "string") {
        throw new Error("Bootstrap response missing token");
      }
      setToken(json.token);
      setStep(4);
    } catch (e) {
      setCreateError(e instanceof Error ? e.message : "Failed to create tenant");
    } finally {
      setCreateLoading(false);
    }
  };

  const tokenClipboard = useCopyToClipboard(token ?? "", { resetAfterMs: 0 });
  const copyToken = async () => {
    if (!token) return;
    const ok = await tokenClipboard.copy();
    setTokenCopied(ok);
  };

  const finish = () => {
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch {
      // ignore
    }
    // Use a hard navigation to avoid any stale client router redirect caching.
    window.location.replace("/");
  };

  return (
    <div className="flex min-h-full items-center justify-center bg-bg p-6">
      <div className="w-full max-w-2xl">
        <div className="overflow-hidden rounded-lg border border-edge bg-surface">
          <div className="p-8">
            <div className="flex items-center justify-between gap-4">
              <div className="eyebrow">{stepLabel}</div>
              <div className="text-xs text-faint">Fresh install onboarding</div>
            </div>

            <h1 className="mt-4 text-2xl font-semibold tracking-tight text-fg">{title}</h1>

            {step === 1 && (
              <p className="mt-4 max-w-2xl text-sm text-muted">
                A <b className="text-fg">tenant</b> is an isolated configuration scope. Think of it
                as a team of developers or a big isolated project: it owns its profiles, upstreams,
                secrets, tool sources, and API keys.
              </p>
            )}

            {step === 2 && (
              <p className="mt-4 max-w-2xl text-sm text-muted">
                A <b className="text-fg">profile</b> is a tenant-owned MCP endpoint (a URL path). It
                defines how requests are routed to upstream MCP servers, and lets you transform,
                filter, and control what tools/resources/prompts are exposed.
              </p>
            )}

            {step === 3 && (
              <>
                <p className="mt-4 max-w-2xl text-sm text-muted">
                  You’re ready to create your first tenant. This will also create a starter profile
                  automatically.
                </p>

                {createError && (
                  <Callout tone="danger" title="Could not create tenant" className="mt-5">
                    <span className="whitespace-pre-wrap break-words">{createError}</span>
                  </Callout>
                )}

                <Button
                  onClick={createTenant}
                  loading={createLoading}
                  size="lg"
                  className="mt-6 w-full"
                >
                  {!createLoading && <SparkIcon className="size-4" />}
                  {createLoading ? "Creating tenant…" : "Create first tenant"}
                </Button>

                <div className="mt-6 rounded-lg border border-edge p-4">
                  <div className="text-sm font-medium text-fg">More tenants later</div>
                  <p className="mt-2 text-sm text-muted">
                    Additional tenants require Gateway admin credentials. For this repository&apos;s
                    local Docker Compose stack, use the authenticated CLI helper:
                  </p>
                  <div className="mt-3">
                    <CopyBlock
                      label="Local Docker Compose"
                      language="bash"
                      value={`# Create a new tenant
make cli-dev CLI_ARGS="tenants put my-tenant"

# Issue a tenant token
make cli-dev CLI_ARGS="tenants issue-token my-tenant --ttl-seconds 3600"`}
                    />
                  </div>
                </div>
              </>
            )}

            {step === 4 && (
              <>
                <p className="mt-4 max-w-2xl text-sm text-muted">
                  This is your <b className="text-fg">tenant token</b>. Save it now — you won’t be
                  able to view it again after you refresh this page or leave onboarding.
                </p>

                <div className="mt-6 rounded-lg border border-edge bg-well p-4">
                  <div className="eyebrow mb-2">Tenant token</div>
                  <div className="select-none break-all font-mono text-sm text-fg">
                    {token ?? "(token unavailable)"}
                  </div>
                </div>

                <Button
                  variant="secondary"
                  size="lg"
                  onClick={copyToken}
                  disabled={!token}
                  className="mt-4 w-full"
                >
                  {tokenCopied ? (
                    <>
                      <CheckIcon className="size-4 text-ok" />
                      Token copied
                    </>
                  ) : (
                    <>
                      <CopyIcon className="size-4" />
                      Copy token
                    </>
                  )}
                </Button>
              </>
            )}
          </div>

          {step !== 3 && (
            <div className="border-t border-edge bg-raised/40 p-6">
              {step === 4 ? (
                <Button onClick={finish} disabled={!tokenCopied} size="lg" className="w-full">
                  Next
                </Button>
              ) : (
                <Button onClick={goNext} size="lg" className="w-full">
                  Next
                </Button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
