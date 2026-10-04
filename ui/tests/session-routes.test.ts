import assert from "node:assert/strict";
import test from "node:test";

import { POST as logoutPost } from "../app/api/session/logout/route";
import { POST as unlockPost } from "../app/api/session/unlock/route";
import { POST as validatePost } from "../app/api/session/validate/route";

function buildTenantToken(payload: { tenant_id: string; exp_unix_secs: number }): string {
  const payloadB64Url = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  return `tv1.${payloadB64Url}.sig`;
}

function getSetCookieHeaders(res: Response): string[] {
  const headers = res.headers as Headers & { getSetCookie?: () => string[] };
  if (typeof headers.getSetCookie === "function") {
    return headers.getSetCookie();
  }
  const single = res.headers.get("set-cookie");
  return single ? [single] : [];
}

function setNodeEnv(value: string | undefined): void {
  const env = process.env as Record<string, string | undefined>;
  if (value === undefined) {
    delete env.NODE_ENV;
  } else {
    env.NODE_ENV = value;
  }
}

test("logout POST clears tenant cookies", async () => {
  const res = await logoutPost();
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.deepEqual(body, { ok: true });

  const cookies = getSetCookieHeaders(res);
  assert.equal(cookies.length, 3);
  assert.ok(
    cookies.some(
      (c) => c.startsWith("ugw_tenant_token=") && c.includes("Max-Age=0") && c.includes("HttpOnly"),
    ),
  );
  assert.ok(cookies.some((c) => c.startsWith("ugw_tenant_id=") && c.includes("Max-Age=0")));
  assert.ok(cookies.some((c) => c.startsWith("ugw_tenant_exp_unix=") && c.includes("Max-Age=0")));
});

test("validation checks Gateway access without setting cookies; unlock checks again", async () => {
  const originalFetch = globalThis.fetch;
  const previousBase = process.env.GATEWAY_ADMIN_BASE;
  process.env.GATEWAY_ADMIN_BASE = "http://gateway:4001";
  const token = buildTenantToken({
    tenant_id: "café",
    exp_unix_secs: Math.floor(Date.now() / 1000) + 3600,
  });
  const request = (value: unknown = `Bearer ${token}`) =>
    new Request("http://localhost/api/session/validate", {
      method: "POST",
      body: JSON.stringify({ token: value }),
    });
  let calls = 0;
  let status = 401;
  try {
    globalThis.fetch = async (_input, init) => {
      calls++;
      assert.equal(new Headers(init?.headers).get("authorization"), `Bearer ${token}`);
      return new Response("{}", { status });
    };
    const rejected = await validatePost(request());
    assert.equal(rejected.status, 401);
    assert.equal(getSetCookieHeaders(rejected).length, 0);
    status = 200;
    const accepted = await validatePost(request());
    assert.equal(accepted.status, 200);
    assert.equal((await accepted.json()).tenantId, "café");
    assert.equal(getSetCookieHeaders(accepted).length, 0);
    status = 403;
    const revoked = await unlockPost(request());
    assert.equal(revoked.status, 403);
    assert.equal(getSetCookieHeaders(revoked).length, 0);
    assert.equal(calls, 3);
    for (const value of [null, 42, "bad", buildTenantToken({ tenant_id: "t", exp_unix_secs: 1 })]) {
      const invalid = await validatePost(request(value));
      assert.ok(invalid.status === 400 || invalid.status === 401);
    }
    assert.equal(calls, 3, "malformed and expired tokens should be rejected before network access");
    status = 500;
    assert.equal((await validatePost(request())).status, 502);
    globalThis.fetch = async () => {
      throw new TypeError("offline");
    };
    const offline = await validatePost(request());
    assert.equal(offline.status, 504);
    assert.match((await offline.json()).error, /unreachable/);
  } finally {
    globalThis.fetch = originalFetch;
    if (previousBase === undefined) delete process.env.GATEWAY_ADMIN_BASE;
    else process.env.GATEWAY_ADMIN_BASE = previousBase;
  }
});

test("unlock POST sets HttpOnly token cookie and helper cookies", async () => {
  const originalFetch = globalThis.fetch;
  const prevGatewayAdminBase = process.env.GATEWAY_ADMIN_BASE;
  const prevNodeEnv = process.env.NODE_ENV;

  try {
    const token = buildTenantToken({
      tenant_id: "default",
      exp_unix_secs: Math.floor(Date.now() / 1000) + 3600,
    });

    process.env.GATEWAY_ADMIN_BASE = "http://gateway:4001";
    setNodeEnv("production");

    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      assert.equal(String(input), "http://gateway:4001/tenant/v1/profiles");
      assert.equal(init?.method, "GET");
      const headers = new Headers(init?.headers);
      assert.equal(headers.get("authorization"), `Bearer ${token}`);
      return new Response("{}", { status: 200 });
    };

    const req = new Request("http://127.0.0.1:3000/api/session/unlock", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token }),
    });
    const res = await unlockPost(req);
    assert.equal(res.status, 200);

    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.tenantId, "default");

    const cookies = getSetCookieHeaders(res);
    assert.equal(cookies.length, 3);
    assert.ok(
      cookies.some(
        (c) => c.startsWith("ugw_tenant_token=") && c.includes("HttpOnly") && c.includes("Secure"),
      ),
    );
    assert.ok(
      cookies.some(
        (c) => c.startsWith("ugw_tenant_id=") && !c.includes("HttpOnly") && c.includes("Secure"),
      ),
    );
    assert.ok(
      cookies.some(
        (c) =>
          c.startsWith("ugw_tenant_exp_unix=") && !c.includes("HttpOnly") && c.includes("Secure"),
      ),
    );
  } finally {
    globalThis.fetch = originalFetch;
    if (prevGatewayAdminBase === undefined) {
      delete process.env.GATEWAY_ADMIN_BASE;
    } else {
      process.env.GATEWAY_ADMIN_BASE = prevGatewayAdminBase;
    }
    setNodeEnv(prevNodeEnv);
  }
});
