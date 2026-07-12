import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

type BootstrapStatusOk = {
  ok: true;
  bootstrapEnabled: boolean;
  canBootstrap: boolean;
  tenantCount?: number;
};

type BootstrapStatusErr = {
  ok: false;
  error?: string;
  status?: number;
  body?: string;
};

export async function GET() {
  const base = process.env.GATEWAY_ADMIN_BASE;
  if (!base) {
    const resp: BootstrapStatusOk = {
      ok: true,
      bootstrapEnabled: false,
      canBootstrap: false,
    };
    return NextResponse.json(resp, { status: 200 });
  }

  const url = `${base.replace(/\/+$/, "")}/bootstrap/v1/tenant/status`;
  let res: Response;
  try {
    res = await fetch(url, { cache: "no-store", signal: AbortSignal.timeout(15_000) });
  } catch (e) {
    const timedOut = e instanceof Error && e.name === "TimeoutError";
    const resp: BootstrapStatusErr = {
      ok: false,
      error: timedOut ? "gateway request timed out" : "gateway unreachable",
    };
    return NextResponse.json(resp, { status: 504 });
  }
  const text = await res.text();

  // Mirror gateway behavior: 404 means "bootstrap disabled / hidden".
  if (res.status === 404) {
    const resp: BootstrapStatusOk = {
      ok: true,
      bootstrapEnabled: false,
      canBootstrap: false,
    };
    return NextResponse.json(resp, { status: 200 });
  }

  if (!res.ok) {
    const resp: BootstrapStatusErr = { ok: false, status: res.status, body: text };
    return NextResponse.json(resp, { status: 502 });
  }

  try {
    const json = JSON.parse(text) as unknown as {
      bootstrapEnabled?: boolean;
      canBootstrap?: boolean;
      tenantCount?: number;
    };
    const resp: BootstrapStatusOk = {
      ok: true,
      bootstrapEnabled: json.bootstrapEnabled === true,
      canBootstrap: json.canBootstrap === true,
      tenantCount: typeof json.tenantCount === "number" ? json.tenantCount : undefined,
    };
    return NextResponse.json(resp, { status: 200 });
  } catch {
    const resp: BootstrapStatusErr = {
      ok: false,
      error: "invalid JSON from gateway",
      body: text,
    };
    return NextResponse.json(resp, { status: 502 });
  }
}
