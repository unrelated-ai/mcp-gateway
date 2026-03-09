import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const TENANT_TOKEN_COOKIE = "ugw_tenant_token";
const TENANT_ID_COOKIE = "ugw_tenant_id";
const TENANT_EXP_COOKIE = "ugw_tenant_exp_unix";

function sanitizeNextPath(raw: string | null): string {
  if (!raw) return "/unlock";
  if (!raw.startsWith("/") || raw.startsWith("//")) return "/unlock";
  return raw;
}

function clearTenantCookies(res: NextResponse): NextResponse {
  for (const name of [TENANT_TOKEN_COOKIE, TENANT_ID_COOKIE, TENANT_EXP_COOKIE]) {
    res.cookies.set({
      name,
      value: "",
      path: "/",
      maxAge: 0,
      sameSite: "lax",
      httpOnly: name === TENANT_TOKEN_COOKIE,
      secure: process.env.NODE_ENV === "production",
    });
  }
  return res;
}

function redirectToPath(path: string): NextResponse {
  // Use a relative Location header so redirects stay correct behind reverse proxies
  // (docker-compose, k8s ingress, etc.) regardless of internal host/origin.
  return new NextResponse(null, {
    status: 307,
    headers: { Location: path },
  });
}

export async function GET(req: Request) {
  const url = new URL(req.url);
  const nextPath = sanitizeNextPath(url.searchParams.get("next"));
  const res = redirectToPath(nextPath);
  return clearTenantCookies(res);
}

export async function POST() {
  const res = NextResponse.json({ ok: true });
  return clearTenantCookies(res);
}
