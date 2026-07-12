import { proxyTenantRequest } from "@/src/lib/server/gateway-proxy";

export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ id: string }> };

export async function DELETE(req: Request, ctx: Ctx) {
  const { id } = await ctx.params;
  return proxyTenantRequest(req, {
    path: `/tenant/v1/api-keys/${encodeURIComponent(id)}`,
    method: "DELETE",
  });
}
