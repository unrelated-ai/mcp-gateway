import { NextResponse } from "next/server";

export const GATEWAY_TIMEOUT_MS = 15_000;

export function gatewayAdminBase(): string | null {
  const base = process.env.GATEWAY_ADMIN_BASE;
  return base ? base.replace(/\/+$/, "") : null;
}

export class GatewayHttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly body?: string,
  ) {
    super(message);
  }
}

export function gatewayErrorResponse(error: unknown): NextResponse {
  const failure =
    error instanceof GatewayHttpError
      ? error
      : new GatewayHttpError(
          504,
          error instanceof Error && error.name === "TimeoutError"
            ? "gateway request timed out"
            : "gateway unreachable",
        );
  return NextResponse.json(
    {
      ok: false,
      error: failure.message,
      ...(failure.body === undefined ? {} : { body: failure.body }),
    },
    { status: failure.status },
  );
}

export interface GatewayReply {
  response: Response;
  text: string;
}

/** The timeout covers both response headers and body consumption. */
export async function requestGateway(path: string, init: RequestInit = {}): Promise<GatewayReply> {
  const base = gatewayAdminBase();
  if (!base) throw new GatewayHttpError(500, "GATEWAY_ADMIN_BASE is not set");
  const response = await fetch(`${base}${path}`, {
    ...init,
    cache: "no-store",
    signal: AbortSignal.timeout(GATEWAY_TIMEOUT_MS),
  });
  return { response, text: await response.text() };
}

export function decodeGatewayJson<T = unknown>({ text }: GatewayReply): T {
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new GatewayHttpError(502, "invalid JSON from gateway", text);
  }
}

export function gatewayFailureResponse(
  { response, text }: GatewayReply,
  preserveStatus = false,
): Response {
  if (preserveStatus)
    return new Response(text, {
      status: response.status,
      headers: {
        "content-type": response.headers.get("content-type") ?? "text/plain; charset=utf-8",
        "cache-control": "no-store",
      },
    });
  return NextResponse.json({ ok: false, status: response.status, body: text }, { status: 502 });
}

export function gatewayJsonResponse(
  reply: GatewayReply,
  options: {
    preserveSuccessStatus?: boolean;
    preserveErrorStatus?: boolean;
    allowNonJsonSuccess?: boolean;
  } = {},
): Response {
  if (!reply.response.ok) return gatewayFailureResponse(reply, options.preserveErrorStatus);
  const status = options.preserveSuccessStatus ? reply.response.status : 200;
  if (status === 204 || status === 205) return new Response(null, { status });
  try {
    return NextResponse.json(decodeGatewayJson(reply), { status });
  } catch (error) {
    if (options.allowNonJsonSuccess) return NextResponse.json({ ok: true }, { status });
    return gatewayErrorResponse(error);
  }
}
