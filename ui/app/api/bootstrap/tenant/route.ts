import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  const base = process.env.GATEWAY_ADMIN_BASE;
  if (!base) {
    return NextResponse.json(
      { ok: false, error: "GATEWAY_ADMIN_BASE is not set" },
      { status: 500 },
    );
  }
  const url = `${base.replace(/\/+$/, "")}/bootstrap/v1/tenant`;
  const body = await req.text();

  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body,
      signal: AbortSignal.timeout(15_000),
    });
  } catch (e) {
    const timedOut = e instanceof Error && e.name === "TimeoutError";
    return NextResponse.json(
      { ok: false, error: timedOut ? "gateway request timed out" : "gateway unreachable" },
      { status: 504 },
    );
  }
  const text = await res.text();
  if (!res.ok) {
    // Propagate gateway errors (e.g. 409 already bootstrapped) to avoid misleading 502s in the browser.
    return new Response(text, {
      status: res.status,
      headers: {
        "content-type": res.headers.get("content-type") ?? "text/plain; charset=utf-8",
        "cache-control": "no-store",
      },
    });
  }
  try {
    return NextResponse.json(JSON.parse(text) as unknown);
  } catch {
    return NextResponse.json(
      { ok: false, error: "invalid JSON from gateway", body: text },
      { status: 502 },
    );
  }
}
