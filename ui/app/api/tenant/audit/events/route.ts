import { NextResponse } from "next/server";
import { cookies } from "next/headers";

export const dynamic = "force-dynamic";

function gatewayAdminBase(): string | null {
  const base = process.env.GATEWAY_ADMIN_BASE;
  if (!base) return null;
  return base.replace(/\/+$/, "");
}

async function tenantAuthHeader(): Promise<string | null> {
  const cookieStore = await cookies();
  const token = cookieStore.get("ugw_tenant_token")?.value;
  if (!token) return null;
  return `Bearer ${token}`;
}

export async function GET(req: Request) {
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

  const url = new URL(req.url);
  const qs = url.searchParams.toString();
  const res = await fetch(`${base}/tenant/v1/audit/events${qs ? `?${qs}` : ""}`, {
    cache: "no-store",
    headers: { Authorization: auth },
  });
  const text = await res.text();
  if (!res.ok) {
    return NextResponse.json({ ok: false, status: res.status, body: text }, { status: 502 });
  }
  try {
    return NextResponse.json(JSON.parse(text) as unknown);
  } catch {
    return NextResponse.json(
      { ok: false, error: "invalid JSON from gateway", body: text },
      { status: 502 },
    );
  }
}
