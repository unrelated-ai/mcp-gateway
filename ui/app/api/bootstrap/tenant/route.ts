import { bootstrapRoutes } from "@/src/lib/gatewayRoutes";
import {
  requestGateway,
  gatewayJsonResponse,
  gatewayErrorResponse,
} from "@/src/lib/server/gateway-http";
export const dynamic = "force-dynamic";
export async function POST(req: Request) {
  try {
    const reply = await requestGateway(bootstrapRoutes.TENANT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: await req.text(),
    });
    return gatewayJsonResponse(reply, { preserveErrorStatus: true });
  } catch (error) {
    return gatewayErrorResponse(error);
  }
}
