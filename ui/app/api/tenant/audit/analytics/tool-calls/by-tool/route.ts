import { tenantRoutes } from "@/src/lib/gatewayRoutes";
import { proxyTenantRequest } from "@/src/lib/server/gateway-proxy";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  return proxyTenantRequest(req, {
    path: tenantRoutes.AUDIT_BY_TOOL,
    search: new URL(req.url).searchParams.toString(),
  });
}
