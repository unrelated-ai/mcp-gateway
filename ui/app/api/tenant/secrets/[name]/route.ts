import { proxyTenantRequest } from "@/src/lib/server/gateway-proxy";

export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ name: string }> };

export async function DELETE(req: Request, ctx: Ctx) {
  const { name } = await ctx.params;
  return proxyTenantRequest(req, {
    path: `/tenant/v1/secrets/${encodeURIComponent(name)}`,
    method: "DELETE",
  });
}
