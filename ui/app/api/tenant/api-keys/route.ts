import { proxyTenantRequest } from "@/src/lib/server/gateway-proxy";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  return proxyTenantRequest(req, { path: "/tenant/v1/api-keys" });
}

export async function POST(req: Request) {
  return proxyTenantRequest(req, { path: "/tenant/v1/api-keys", method: "POST" });
}
