import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const TENANT_TOKEN_COOKIE = "ugw_tenant_token";
const TENANT_ID_COOKIE = "ugw_tenant_id";
const TENANT_EXP_COOKIE = "ugw_tenant_exp_unix";
const ONE_YEAR_SECS = 31_536_000;

type UnlockRequest = {
  token?: string;
};

type TenantTokenPayload = {
  tenant_id: string;
  exp_unix_secs: number;
};

function gatewayAdminBase(): string | null {
  const base = process.env.GATEWAY_ADMIN_BASE;
  if (!base) return null;
  return base.replace(/\/+$/, "");
}

function decodeTenantTokenPayload(rawToken: string): TenantTokenPayload {
  const token = rawToken.trim().startsWith("Bearer ")
    ? rawToken.trim().slice("Bearer ".length).trim()
    : rawToken.trim();
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== "tv1") {
    throw new Error("Invalid token format");
  }

  const payloadB64Url = parts[1] ?? "";
  const payloadB64 = payloadB64Url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = payloadB64 + "=".repeat((4 - (payloadB64.length % 4)) % 4);
  const payloadJson = Buffer.from(padded, "base64").toString("utf8");
  const payload = JSON.parse(payloadJson) as
    | { tenant_id?: unknown; exp_unix_secs?: unknown }
    | { tenantId?: unknown; expUnixSecs?: unknown };

  const tenantId =
    typeof (payload as { tenant_id?: unknown }).tenant_id === "string"
      ? ((payload as { tenant_id: string }).tenant_id ?? "")
      : typeof (payload as { tenantId?: unknown }).tenantId === "string"
        ? ((payload as { tenantId: string }).tenantId ?? "")
        : "";
  const expUnixSecs =
    typeof (payload as { exp_unix_secs?: unknown }).exp_unix_secs === "number"
      ? Number((payload as { exp_unix_secs: number }).exp_unix_secs)
      : typeof (payload as { expUnixSecs?: unknown }).expUnixSecs === "number"
        ? Number((payload as { expUnixSecs: number }).expUnixSecs)
        : Number.NaN;

  if (!tenantId || !Number.isFinite(expUnixSecs)) {
    throw new Error("Invalid token payload");
  }
  return {
    tenant_id: tenantId,
    exp_unix_secs: expUnixSecs,
  };
}

async function validateTenantToken(base: string, token: string): Promise<void> {
  const res = await fetch(`${base}/tenant/v1/profiles`, {
    method: "GET",
    cache: "no-store",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (res.ok) return;
  const body = await res.text();
  throw new Error(body || `Gateway validation failed (${res.status})`);
}

export async function POST(req: Request) {
  const base = gatewayAdminBase();
  if (!base) {
    return NextResponse.json(
      { ok: false, error: "GATEWAY_ADMIN_BASE is not set" },
      { status: 500 },
    );
  }

  let body: UnlockRequest;
  try {
    body = (await req.json()) as UnlockRequest;
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid JSON payload" }, { status: 400 });
  }

  const token = body.token?.trim() ?? "";
  if (!token) {
    return NextResponse.json({ ok: false, error: "token is required" }, { status: 400 });
  }

  let payload: TenantTokenPayload;
  try {
    payload = decodeTenantTokenPayload(token);
  } catch (e) {
    return NextResponse.json(
      { ok: false, error: e instanceof Error ? e.message : "Invalid token format" },
      { status: 400 },
    );
  }

  try {
    await validateTenantToken(base, token);
  } catch (e) {
    return NextResponse.json(
      { ok: false, error: e instanceof Error ? e.message : "Tenant token validation failed" },
      { status: 401 },
    );
  }

  const now = Math.floor(Date.now() / 1000);
  const maxAge = Math.max(1, Math.min(ONE_YEAR_SECS, payload.exp_unix_secs - now));
  const secure = process.env.NODE_ENV === "production";

  const res = NextResponse.json({
    ok: true,
    tenantId: payload.tenant_id,
    expUnixSecs: payload.exp_unix_secs,
  });

  res.cookies.set({
    name: TENANT_TOKEN_COOKIE,
    value: token,
    path: "/",
    maxAge,
    sameSite: "lax",
    httpOnly: true,
    secure,
  });
  // These are non-sensitive UX helpers used by client-side pre-expiry checks.
  res.cookies.set({
    name: TENANT_ID_COOKIE,
    value: payload.tenant_id,
    path: "/",
    maxAge,
    sameSite: "lax",
    httpOnly: false,
    secure,
  });
  res.cookies.set({
    name: TENANT_EXP_COOKIE,
    value: String(payload.exp_unix_secs),
    path: "/",
    maxAge,
    sameSite: "lax",
    httpOnly: false,
    secure,
  });

  return res;
}
