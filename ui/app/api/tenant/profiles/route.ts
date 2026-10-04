import { tenantRoutes } from "@/src/lib/gatewayRoutes";
import { proxyTenantRequest } from "@/src/lib/server/gateway-proxy";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  return proxyTenantRequest(req, { path: tenantRoutes.PROFILES });
}

export async function POST(req: Request) {
  return proxyTenantRequest(req, { path: tenantRoutes.PROFILES, method: "POST" });
}
