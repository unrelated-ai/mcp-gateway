import { tenantRoutes } from "@/src/lib/gatewayRoutes";
import { proxyTenantRequest } from "@/src/lib/server/gateway-proxy";
export const dynamic = "force-dynamic";
type Params = { params: Promise<{ id: string }> };
export async function GET(req: Request, { params }: Params) {
  const { id } = await params;
  return proxyTenantRequest(req, { path: tenantRoutes.DEPLOYMENT(id) });
}
export async function PATCH(req: Request, { params }: Params) {
  const { id } = await params;
  return proxyTenantRequest(req, {
    path: tenantRoutes.DEPLOYMENT(id),
    method: "PATCH",
    preserveSuccessStatus: true,
  });
}
