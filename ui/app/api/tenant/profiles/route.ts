import { proxyTenantRequest } from "@/src/lib/server/gateway-proxy";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  return proxyTenantRequest(req, { path: "/tenant/v1/profiles" });
}

export async function POST(req: Request) {
  return proxyTenantRequest(req, { path: "/tenant/v1/profiles", method: "POST" });
}
