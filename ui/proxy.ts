import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

const TENANT_TOKEN_COOKIE = "ugw_tenant_token";

type BootstrapStatusResponse =
  | {
      ok: true;
      bootstrapEnabled: boolean;
      canBootstrap: boolean;
      tenantCount?: number;
    }
  | { ok: false; error?: string; status?: number; body?: string };

async function canBootstrapFirstTenant(req: NextRequest): Promise<boolean> {
  try {
    const url = new URL("/api/bootstrap/status", req.nextUrl.origin);
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) return false;
    const json = (await res.json()) as BootstrapStatusResponse;
    return json.ok === true && json.canBootstrap === true;
  } catch {
    return false;
  }
}

function redirectNoStore(url: URL): NextResponse {
  const res = NextResponse.redirect(url);
  // Avoid sticky onboarding: the redirect decision can change after bootstrap,
  // and Next's router/middleware layer may cache redirects unless explicitly disabled.
  res.headers.set("Cache-Control", "no-store");
  res.headers.set("x-middleware-cache", "no-cache");
  return res;
}

function isProtectedPath(pathname: string): boolean {
  return (
    pathname.startsWith("/profiles") ||
    pathname.startsWith("/sources") ||
    pathname.startsWith("/api-keys") ||
    pathname.startsWith("/secrets") ||
    pathname.startsWith("/audit") ||
    pathname.startsWith("/settings")
  );
}

export async function proxy(req: NextRequest) {
  const pathname = req.nextUrl.pathname;

  // Fresh install: always guide the user through onboarding first.
  const canBootstrap = await canBootstrapFirstTenant(req);
  if (pathname.startsWith("/onboarding")) {
    if (!canBootstrap) {
      return redirectNoStore(new URL("/", req.url));
    }
    return NextResponse.next();
  }
  if (canBootstrap) {
    return redirectNoStore(new URL("/onboarding", req.url));
  }

  // Normal flow: protected pages require a tenant token.
  if (!isProtectedPath(pathname)) {
    return NextResponse.next();
  }

  const token = req.cookies.get(TENANT_TOKEN_COOKIE)?.value;
  if (token) return NextResponse.next();

  const url = req.nextUrl.clone();
  url.pathname = "/unlock";
  url.searchParams.set("next", req.nextUrl.pathname);
  return redirectNoStore(url);
}

export const config = {
  matcher: [
    // All pages except API routes + Next internals + common static files.
    "/((?!api/|_next/|favicon.ico$|robots.txt$|sitemap.xml$).*)",
  ],
};
