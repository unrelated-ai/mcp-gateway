import { proxyTenantRequest } from "@/src/lib/server/gateway-proxy";

export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ id: string; endpointId: string }> };

export async function PATCH(req: Request, ctx: Ctx) {
  const { id, endpointId } = await ctx.params;
  return proxyTenantRequest(req, {
    path: `/tenant/v1/upstreams/${encodeURIComponent(id)}/endpoints/${encodeURIComponent(endpointId)}`,
    method: "PATCH",
  });
}

export async function DELETE(req: Request, ctx: Ctx) {
  const { id, endpointId } = await ctx.params;
  return proxyTenantRequest(req, {
    path: `/tenant/v1/upstreams/${encodeURIComponent(id)}/endpoints/${encodeURIComponent(endpointId)}`,
    method: "DELETE",
  });
}
