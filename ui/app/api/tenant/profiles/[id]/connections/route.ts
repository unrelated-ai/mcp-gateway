import { tenantRoutes } from "@/src/lib/gatewayRoutes";
import { proxyTenantRequest } from "@/src/lib/server/gateway-proxy";

export const dynamic = "force-dynamic";

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  return proxyTenantRequest(req, {
    path: tenantRoutes.PROFILE_CONNECTIONS(id),
    method: "POST",
    forwardBody: false,
  });
}
