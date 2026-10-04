import { tenantRoutes } from "@/src/lib/gatewayRoutes";
import { decodeTenantTokenPayload, normalizeTenantToken } from "@/src/lib/tenant-session";
import { GatewayHttpError, requestGateway } from "./gateway-http";

/** Decode for display only; the Gateway verifies the signature and tenant access. */
export async function validateTenantTokenRequest(req: Request) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    throw new GatewayHttpError(400, "Invalid JSON payload");
  }
  const raw = body && typeof body === "object" && "token" in body ? body.token : null;
  if (typeof raw !== "string" || !raw.trim()) throw new GatewayHttpError(400, "token is required");
  const token = normalizeTenantToken(raw);
  let payload;
  try {
    payload = decodeTenantTokenPayload(token);
  } catch {
    throw new GatewayHttpError(400, "Invalid token format or payload");
  }
  if (payload.exp_unix_secs <= Math.floor(Date.now() / 1000)) {
    throw new GatewayHttpError(
      401,
      "Token expired. Request a new tenant token from a Gateway operator.",
    );
  }
  const { response } = await requestGateway(tenantRoutes.PROFILES, {
    method: "GET",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      throw new GatewayHttpError(
        response.status,
        "The Gateway rejected this token or its tenant access.",
      );
    }
    throw new GatewayHttpError(502, "The Gateway could not validate the token. Try again.");
  }
  return { token, payload };
}
