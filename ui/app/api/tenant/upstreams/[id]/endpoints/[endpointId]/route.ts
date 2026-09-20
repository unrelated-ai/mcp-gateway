import { tenantRoutes } from "@/src/lib/gatewayRoutes";
import { proxyTenantRequest } from "@/src/lib/server/gateway-proxy";

export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ id: string; endpointId: string }> };

export async function PATCH(req: Request, ctx: Ctx) {
  const { id, endpointId } = await ctx.params;
  return proxyTenantRequest(req, {
    path: tenantRoutes.ENDPOINT(id, endpointId),
    method: "PATCH",
  });
}

export async function DELETE(req: Request, ctx: Ctx) {
  const { id, endpointId } = await ctx.params;
  return proxyTenantRequest(req, {
    path: tenantRoutes.ENDPOINT(id, endpointId),
    method: "DELETE",
  });
}
