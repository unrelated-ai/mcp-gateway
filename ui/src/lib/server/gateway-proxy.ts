import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { TENANT_TOKEN_COOKIE } from "@/src/lib/tenant-session";

const GATEWAY_TIMEOUT_MS = 15_000;

export function gatewayAdminBase(): string | null {
  const base = process.env.GATEWAY_ADMIN_BASE;
  if (!base) return null;
  return base.replace(/\/+$/, "");
}

export async function tenantAuthHeader(): Promise<string | null> {
  const cookieStore = await cookies();
  const token = cookieStore.get(TENANT_TOKEN_COOKIE)?.value;
  if (!token) return null;
  return `Bearer ${token}`;
}

/**
 * Defense-in-depth CSRF check for state-changing requests. Blocks only when
 * the browser explicitly reports a cross-site fetch; requests without the
 * header (older browsers, server-to-server) pass through, and the gateway's
 * bearer-token auth remains the primary control.
 */
function isCrossSite(req: Request): boolean {
  const site = req.headers.get("sec-fetch-site");
  return site === "cross-site";
}

export interface ProxyTenantOptions {
  /** Gateway path, e.g. `/tenant/v1/profiles/${encodeURIComponent(id)}`. */
  path: string;
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  /** Forward the incoming request body as JSON (default: true for non-GET). */
  forwardBody?: boolean;
  /** Query string (without leading `?`) appended to the gateway URL. */
  search?: string;
}

/**
 * Shared BFF proxy: forwards a tenant-scoped request to the gateway admin API
 * with the session bearer token, a request timeout, and uniform error mapping.
 *
 * Contract (unchanged from the previous per-route implementations):
 * - 500 `{ok:false,error}` when GATEWAY_ADMIN_BASE is unset
 * - 401 `{ok:false,error}` when the tenant session cookie is missing
 * - 502 `{ok:false,status,body}` when the gateway responds non-2xx
 * - gateway JSON body passed through on success ({ok:true} for empty non-GET)
 */
export async function proxyTenantRequest(
  req: Request,
  { path, method = "GET", forwardBody, search }: ProxyTenantOptions,
): Promise<NextResponse> {
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
  if (method !== "GET" && isCrossSite(req)) {
    return NextResponse.json({ ok: false, error: "cross-site request blocked" }, { status: 403 });
  }

  const shouldForwardBody = forwardBody ?? method !== "GET";
  const headers: Record<string, string> = { Authorization: auth };
  let body: string | undefined;
  if (shouldForwardBody) {
    body = await req.text();
    headers["Content-Type"] = "application/json";
  }

  let res: Response;
  try {
    res = await fetch(`${base}${path}${search ? `?${search}` : ""}`, {
      method,
      cache: "no-store",
      headers,
      body,
      signal: AbortSignal.timeout(GATEWAY_TIMEOUT_MS),
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
    return NextResponse.json(JSON.parse(text) as unknown);
  } catch {
    if (method === "GET") {
      return NextResponse.json(
        { ok: false, error: "invalid JSON from gateway", body: text },
        { status: 502 },
      );
    }
    return NextResponse.json({ ok: true });
  }
}
