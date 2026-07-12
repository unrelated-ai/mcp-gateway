import { proxyTenantRequest } from "@/src/lib/server/gateway-proxy";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  return proxyTenantRequest(req, {
    path: "/tenant/v1/audit/analytics/tool-calls/by-tool",
    search: new URL(req.url).searchParams.toString(),
  });
}
