import { proxyTenantRequest } from "@/src/lib/server/gateway-proxy";

export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ id: string }> };

export async function GET(req: Request, ctx: Ctx) {
  const { id } = await ctx.params;

  // Forward only the ttlSecs query param (matching the previous behavior).
  const ttlSecs = new URL(req.url).searchParams.get("ttlSecs");
  const qs = new URLSearchParams();
  if (ttlSecs) qs.set("ttlSecs", ttlSecs);

  return proxyTenantRequest(req, {
    path: `/tenant/v1/upstreams/${encodeURIComponent(id)}/session-activity`,
    search: qs.toString(),
  });
}
