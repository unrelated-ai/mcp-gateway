import { proxyTenantRequest } from "@/src/lib/server/gateway-proxy";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  return proxyTenantRequest(req, { path: "/tenant/v1/audit/settings" });
}

export async function PUT(req: Request) {
  return proxyTenantRequest(req, { path: "/tenant/v1/audit/settings", method: "PUT" });
}
