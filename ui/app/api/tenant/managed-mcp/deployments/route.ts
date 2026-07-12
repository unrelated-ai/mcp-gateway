import { NextResponse } from "next/server";
import {
  gatewayAdminBase,
  proxyTenantRequest,
  tenantAuthHeader,
} from "@/src/lib/server/gateway-proxy";

export const dynamic = "force-dynamic";

// Kept inline: unlike the shared helper, this route passes the gateway's
// success status code through to the client (e.g. 201/202 on create).
export async function POST(req: Request) {
  const base = gatewayAdminBase();
  if (!base) {
    return NextResponse.json(
      { ok: false, error: "GATEWAY_ADMIN_BASE is not set" },
      { status: 500 },
    );
  }
  const auth = await tenantAuthHeader();
  if (!auth) {
    return NextResponse.json({ ok: false, error: "missing tenant session" }, { status: 401 });
  }

  const body = await req.text();
  let res: Response;
  try {
    res = await fetch(`${base}/tenant/v1/managed-mcp/deployments`, {
      method: "POST",
      cache: "no-store",
      headers: { Authorization: auth, "Content-Type": "application/json" },
      body,
      signal: AbortSignal.timeout(15_000),
    });
  } catch (e) {
    const timedOut = e instanceof Error && e.name === "TimeoutError";
    return NextResponse.json(
      { ok: false, error: timedOut ? "gateway request timed out" : "gateway unreachable" },
      { status: 504 },
    );
  }
  const text = await res.text();
  if (!res.ok) {
    return NextResponse.json({ ok: false, status: res.status, body: text }, { status: 502 });
  }
  try {
    return NextResponse.json(JSON.parse(text) as unknown, { status: res.status });
  } catch {
    return NextResponse.json(
      { ok: false, error: "invalid JSON from gateway", body: text },
      { status: 502 },
    );
  }
}

export async function GET(req: Request) {
  return proxyTenantRequest(req, { path: "/tenant/v1/managed-mcp/deployments" });
}
