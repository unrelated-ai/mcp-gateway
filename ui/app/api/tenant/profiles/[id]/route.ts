import { proxyTenantRequest } from "@/src/lib/server/gateway-proxy";

export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ id: string }> };

export async function GET(req: Request, ctx: Ctx) {
  const { id } = await ctx.params;
  return proxyTenantRequest(req, { path: `/tenant/v1/profiles/${encodeURIComponent(id)}` });
}

export async function PUT(req: Request, ctx: Ctx) {
  const { id } = await ctx.params;
  return proxyTenantRequest(req, {
    path: `/tenant/v1/profiles/${encodeURIComponent(id)}`,
    method: "PUT",
  });
}

export async function DELETE(req: Request, ctx: Ctx) {
  const { id } = await ctx.params;
  return proxyTenantRequest(req, {
    path: `/tenant/v1/profiles/${encodeURIComponent(id)}`,
    method: "DELETE",
  });
}
