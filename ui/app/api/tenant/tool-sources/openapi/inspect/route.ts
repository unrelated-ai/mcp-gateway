import { proxyTenantRequest } from "@/src/lib/server/gateway-proxy";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  return proxyTenantRequest(req, {
    path: "/tenant/v1/tool-sources/openapi/inspect",
    method: "POST",
  });
}
