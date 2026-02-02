"use client";

import { useEffect, useMemo, useState } from "react";
import { CheckIcon, CopyIcon, SparkIcon } from "@/components/icons";
import { useCopyToClipboard } from "@/src/lib/useCopyToClipboard";

const STORAGE_KEY = "ugw_onboarding_step_v1";

type Step = 1 | 2 | 3 | 4;

type BootstrapStatusResponse =
  | { ok: true; canBootstrap: boolean }
  | { ok: false; error?: string; status?: number; body?: string };

export default function OnboardingPage() {
  const [step, setStep] = useState<Step>(1);
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
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      const n = raw ? Number(raw) : NaN;
      // This page only renders on fresh install (no tenants), so step 4 is never a valid resume state.
      const next: Step = n === 2 ? 2 : n === 3 ? 3 : 1;
      setStep(next);
    } catch {
      setStep(1);
    }
  }, []);

  // Persist step progress (best-effort).
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, String(step));
    } catch {
      // ignore
    }
  }, [step]);

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
    <div className="min-h-full bg-zinc-950 flex items-center justify-center p-6">
      {/* Background effects */}
      <div className="fixed inset-0 bg-gradient-to-br from-emerald-500/5 via-transparent to-violet-500/5" />
      <div className="fixed top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[450px] bg-emerald-500/10 blur-[110px] rounded-full" />

      <div className="relative w-full max-w-2xl">
        <div className="rounded-2xl border border-zinc-800/80 bg-zinc-900/60 backdrop-blur-sm overflow-hidden">
          <div className="p-8">
            <div className="flex items-center justify-between gap-4">
              <div className="text-sm text-zinc-400">{stepLabel}</div>
              <div className="text-xs text-zinc-500">Fresh install onboarding</div>
            </div>

            <h1 className="mt-4 text-3xl sm:text-4xl font-bold text-white tracking-tight">
              {title}
            </h1>

            {step === 1 && (
              <p className="mt-4 text-lg text-zinc-400 max-w-2xl">
                A <b className="text-zinc-200">tenant</b> is an isolated configuration scope. Think
                of it as a team of developers or a big isolated project: it owns its profiles,
                upstreams, secrets, tool sources, and API keys.
              </p>
            )}

            {step === 2 && (
              <p className="mt-4 text-lg text-zinc-400 max-w-2xl">
                A <b className="text-zinc-200">profile</b> is a tenant-owned MCP endpoint (a URL
                path). It defines how requests are routed to upstream MCP servers, and lets you
                transform, filter, and control what tools/resources/prompts are exposed.
              </p>
            )}

            {step === 3 && (
              <>
                <p className="mt-4 text-lg text-zinc-400 max-w-2xl">
                  You’re ready to create your first tenant. This will also create a starter profile
                  automatically.
                </p>

                {createError && (
                  <div className="mt-5 rounded-xl bg-red-500/5 border border-red-500/20 p-4 text-sm text-red-300">
                    <div className="font-medium">Could not create tenant</div>
                    <div className="mt-1 text-xs text-red-300/80 break-words whitespace-pre-wrap">
                      {createError}
                    </div>
                  </div>
                )}

                <button
                  onClick={createTenant}
                  disabled={createLoading}
                  className="mt-6 w-full inline-flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-gradient-to-b from-emerald-500 to-emerald-600 text-white font-semibold shadow-lg shadow-emerald-500/20 hover:from-emerald-400 hover:to-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-150"
                >
                  {createLoading ? (
                    <>
                      <LoadingSpinner className="w-4 h-4" />
                      Creating tenant…
                    </>
                  ) : (
                    <>
                      <SparkIcon className="w-4 h-4" />
                      Create first tenant
                    </>
                  )}
                </button>

                <div className="mt-6 rounded-xl border border-zinc-800/80 bg-zinc-950/40 p-4">
                  <div className="text-sm font-medium text-zinc-200">More tenants later</div>
                  <p className="mt-2 text-sm text-zinc-400">
                    You can always create more tenants using the CLI.
                  </p>
                  <div className="mt-3 text-xs text-zinc-400">Example:</div>
                  <pre className="mt-2 rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 text-xs text-zinc-200 overflow-x-auto">
                    {`# Create a new tenant
cargo run -p unrelated-gateway-admin -- tenants put my-tenant

# Issue a tenant token
cargo run -p unrelated-gateway-admin -- tenants issue-token my-tenant --ttl-seconds 3600`}
                  </pre>
                </div>
              </>
            )}

            {step === 4 && (
              <>
                <p className="mt-4 text-lg text-zinc-400 max-w-2xl">
                  This is your <b className="text-zinc-200">tenant token</b>. Save it now — you
                  won’t be able to view it again after you refresh this page or leave onboarding.
                </p>

                <div className="mt-6 rounded-xl border border-zinc-800 bg-zinc-950/60 p-4">
                  <div className="text-xs text-zinc-400 mb-2">Tenant token</div>
                  <div className="font-mono text-sm text-zinc-100 break-all select-none">
                    {token ?? "(token unavailable)"}
                  </div>
                </div>

                <button
                  onClick={copyToken}
                  disabled={!token}
                  className="mt-4 w-full inline-flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-zinc-800 text-zinc-100 font-semibold border border-zinc-700 hover:bg-zinc-700 hover:border-zinc-600 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-150"
                >
                  {tokenCopied ? (
                    <>
                      <CheckIcon className="w-5 h-5 text-emerald-400" />
                      Token copied
                    </>
                  ) : (
                    <>
                      <CopyIcon className="w-5 h-5" />
                      Copy token
                    </>
                  )}
                </button>
              </>
            )}
          </div>

          {step !== 3 && (
            <div className="border-t border-zinc-800/80 bg-zinc-900/40 p-6">
              {step === 4 ? (
                <button
                  onClick={finish}
                  disabled={!tokenCopied}
                  className="w-full inline-flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-gradient-to-b from-emerald-500 to-emerald-600 text-white font-semibold shadow-lg shadow-emerald-500/20 hover:from-emerald-400 hover:to-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-150"
                >
                  Next
                </button>
              ) : (
                <button
                  onClick={goNext}
                  className="w-full inline-flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-gradient-to-b from-emerald-500 to-emerald-600 text-white font-semibold shadow-lg shadow-emerald-500/20 hover:from-emerald-400 hover:to-emerald-500 transition-all duration-150"
                >
                  Next
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
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
