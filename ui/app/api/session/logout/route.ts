import { NextResponse } from "next/server";
import { TENANT_EXP_COOKIE, TENANT_ID_COOKIE, TENANT_TOKEN_COOKIE } from "@/src/lib/tenant-session";

export const dynamic = "force-dynamic";

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

// Logout is POST-only: clearing the session is a state change, and a GET
// endpoint would be triggerable cross-site (forced logout via <img src=...>).
export async function POST() {
  const res = NextResponse.json({ ok: true });
  return clearTenantCookies(res);
}
