import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { UnlockTenantCard } from "./_components/UnlockTenantCard";
import { TENANT_TOKEN_COOKIE } from "@/src/lib/tenant-session";
import { GATEWAY_DATA_BASE, UI_VERSION } from "@/src/lib/env";

export const dynamic = "force-dynamic";

export default async function Home() {
  const cookieStore = await cookies();
  const hasSession = cookieStore.has(TENANT_TOKEN_COOKIE);
  if (hasSession) {
    redirect("/profiles");
  }
  const dataBase = GATEWAY_DATA_BASE;

  return (
    <div className="min-h-full bg-bg">
      <div className="mx-auto max-w-4xl px-6 pb-20 pt-20">
        {/* Masthead */}
        <div className="flex items-center gap-3">
          <div className="flex size-9 items-center justify-center rounded-md bg-accent-strong">
            <span className="text-base font-semibold leading-none text-white">U</span>
          </div>
          <div>
            <div className="eyebrow">unrelated.ai · {UI_VERSION}</div>
          </div>
        </div>

        <h1 className="mt-8 text-3xl font-semibold tracking-tight text-fg">MCP Gateway</h1>
        <p className="mt-3 max-w-xl text-base text-muted">
          Turn HTTP APIs and stdio servers into managed MCP endpoints. Wire tool sources into
          profiles, hand your agents one URL each, and control what they can call.
        </p>

        {/* The subject's core artifact: what a profile endpoint looks like. */}
        <div className="mt-6 max-w-xl">
          <div className="eyebrow mb-1.5">Profile endpoint</div>
          <div className="flex items-center gap-2.5 rounded-md border border-edge bg-well px-3 py-2">
            <span aria-hidden="true" className="size-1.5 shrink-0 rounded-[1px] bg-ok" />
            <code className="truncate font-mono text-[13px] text-muted">
              {dataBase}/<span className="text-accent">&lt;profile-id&gt;</span>/mcp
            </code>
          </div>
        </div>

        <div className="mt-10 grid gap-6 lg:grid-cols-[1.3fr_0.7fr]">
          <UnlockTenantCard />

          <div className="h-fit rounded-lg border border-edge bg-surface p-6">
            <div className="eyebrow">Gateway configuration</div>
            <div className="mt-4 space-y-1">
              <ConfigRow label="Data plane" value={dataBase} />
            </div>
            <p className="mt-4 text-xs text-faint">
              After unlocking, you&apos;ll be able to create profiles and copy MCP client configs.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

function ConfigRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-edge/60 py-2 last:border-0">
      <span className="text-sm text-muted">{label}</span>
      <span className="max-w-[200px] truncate font-mono text-sm text-fg" title={value}>
        {value}
      </span>
    </div>
  );
}
