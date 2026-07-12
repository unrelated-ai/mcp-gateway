import { proxyTenantRequest } from "@/src/lib/server/gateway-proxy";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  return proxyTenantRequest(req, { path: "/tenant/v1/secrets" });
}

export async function POST(req: Request) {
  return proxyTenantRequest(req, { path: "/tenant/v1/secrets", method: "POST" });
}
