import {
  requestGateway,
  decodeGatewayJson,
  gatewayFailureResponse,
  gatewayErrorResponse,
} from "@/src/lib/server/gateway-http";
import { NextResponse } from "next/server";
export const dynamic = "force-dynamic";
export async function GET() {
  try {
    const reply = await requestGateway("/status");
    if (!reply.response.ok) return gatewayFailureResponse(reply);
    return NextResponse.json({ ok: true, status: decodeGatewayJson(reply) });
  } catch (error) {
    return gatewayErrorResponse(error);
  }
}
