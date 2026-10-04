import { NextResponse } from "next/server";
import { gatewayErrorResponse } from "@/src/lib/server/gateway-http";
import { validateTenantTokenRequest } from "@/src/lib/server/tenant-token";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  try {
    const { payload } = await validateTenantTokenRequest(req);
    return NextResponse.json(
      { ok: true, tenantId: payload.tenant_id, expUnixSecs: payload.exp_unix_secs },
      { headers: { "Cache-Control": "no-store" } },
    );
  } catch (error) {
    return gatewayErrorResponse(error);
  }
}
