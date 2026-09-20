import { bootstrapRoutes } from "@/src/lib/gatewayRoutes";
import {
  gatewayAdminBase,
  requestGateway,
  decodeGatewayJson,
  gatewayFailureResponse,
  gatewayErrorResponse,
} from "@/src/lib/server/gateway-http";
import { NextResponse } from "next/server";
export const dynamic = "force-dynamic";
const disabled = () =>
  NextResponse.json({ ok: true, bootstrapEnabled: false, canBootstrap: false });
export async function GET() {
  if (!gatewayAdminBase()) return disabled();
  try {
    const reply = await requestGateway(bootstrapRoutes.STATUS);
    if (reply.response.status === 404) return disabled();
    if (!reply.response.ok) return gatewayFailureResponse(reply);
    const json = decodeGatewayJson<{
      bootstrapEnabled?: boolean;
      canBootstrap?: boolean;
      tenantCount?: number;
    }>(reply);
    return NextResponse.json({
      ok: true,
      bootstrapEnabled: json.bootstrapEnabled === true,
      canBootstrap: json.canBootstrap === true,
      tenantCount: typeof json.tenantCount === "number" ? json.tenantCount : undefined,
    });
  } catch (error) {
    return gatewayErrorResponse(error);
  }
}
