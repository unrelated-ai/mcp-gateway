import { NextResponse } from "next/server";
import { TENANT_EXP_COOKIE, TENANT_ID_COOKIE, TENANT_TOKEN_COOKIE } from "@/src/lib/tenant-session";
import { gatewayErrorResponse } from "@/src/lib/server/gateway-http";
import { validateTenantTokenRequest } from "@/src/lib/server/tenant-token";

export const dynamic = "force-dynamic";
const ONE_YEAR_SECS = 31_536_000;

export async function POST(req: Request) {
  let validated;
  try {
    validated = await validateTenantTokenRequest(req);
  } catch (error) {
    return gatewayErrorResponse(error);
  }
  const { token, payload } = validated;

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
