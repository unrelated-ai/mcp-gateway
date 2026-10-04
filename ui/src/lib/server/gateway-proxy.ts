import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { TENANT_TOKEN_COOKIE } from "@/src/lib/tenant-session";

import {
  gatewayAdminBase,
  gatewayErrorResponse,
  gatewayJsonResponse,
  GatewayHttpError,
  requestGateway,
} from "./gateway-http";
export { gatewayAdminBase, GATEWAY_TIMEOUT_MS } from "./gateway-http";

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
  /** Gateway path, e.g. tenantRoutes.PROFILE(id). */
  path: string;
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  /** Forward the incoming request body as JSON (default: true for non-GET). */
  forwardBody?: boolean;
  /** Query string (without leading `?`) appended to the gateway URL. */
  search?: string;
  /** Preserve create/accepted status codes; require valid JSON on success. */
  preserveSuccessStatus?: boolean;
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
  { path, method = "GET", forwardBody, search, preserveSuccessStatus }: ProxyTenantOptions,
): Promise<Response> {
  const base = gatewayAdminBase();
  if (!base) {
    return gatewayErrorResponse(new GatewayHttpError(500, "GATEWAY_ADMIN_BASE is not set"));
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

  try {
    const reply = await requestGateway(path + (search ? `?${search}` : ""), {
      method,
      headers,
      body,
    });
    return gatewayJsonResponse(reply, {
      preserveSuccessStatus,
      allowNonJsonSuccess: method !== "GET" && !preserveSuccessStatus,
    });
  } catch (error) {
    return gatewayErrorResponse(error);
  }
}
