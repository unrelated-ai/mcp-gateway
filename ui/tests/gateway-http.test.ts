import assert from "node:assert/strict";
import test from "node:test";
import { bffRoute, tenantRoutes } from "../src/lib/gatewayRoutes";
import {
  gatewayJsonResponse,
  requestGateway,
  gatewayErrorResponse,
} from "../src/lib/server/gateway-http";
import { POST as bootstrap } from "../app/api/bootstrap/tenant/route";
import { GET as bootstrapStatus } from "../app/api/bootstrap/status/route";

function reply(status: number, text: string) {
  return { response: new Response(text, { status }), text };
}

test("route identifiers cannot inject path segments, query strings, or fragments", () => {
  const path = tenantRoutes.ENDPOINT("a/b", "café ?#%");
  assert.equal(path, "/tenant/v1/upstreams/a%2Fb/endpoints/caf%C3%A9%20%3F%23%25");
  assert.equal(bffRoute(path), "/api/tenant/upstreams/a%2Fb/endpoints/caf%C3%A9%20%3F%23%25");
  for (const id of ["", ".", ".."]) assert.throws(() => tenantRoutes.PROFILE(id));
  assert.throws(() => bffRoute("https://elsewhere.example"));
});

test("proxy response policies preserve managed statuses, bootstrap conflicts, and legacy empty writes", async () => {
  for (const status of [201, 202]) {
    const response = gatewayJsonResponse(reply(status, '{"id":"created"}'), {
      preserveSuccessStatus: true,
    });
    assert.equal(response.status, status);
    assert.deepEqual(await response.json(), { id: "created" });
  }
  const conflict = gatewayJsonResponse(reply(409, "already bootstrapped"), {
    preserveErrorStatus: true,
  });
  assert.equal(conflict.status, 409);
  assert.equal(await conflict.text(), "already bootstrapped");
  const wrapped = gatewayJsonResponse(reply(409, "revision conflict"));
  assert.equal(wrapped.status, 502);
  assert.deepEqual(await wrapped.json(), { ok: false, status: 409, body: "revision conflict" });
  const invalid = gatewayJsonResponse(reply(200, "not JSON"));
  assert.equal(invalid.status, 502);
  assert.deepEqual(await invalid.json(), {
    ok: false,
    error: "invalid JSON from gateway",
    body: "not JSON",
  });
  const empty = gatewayJsonResponse(reply(200, ""), { allowNonJsonSuccess: true });
  assert.deepEqual(await empty.json(), { ok: true });
});

test("bootstrap route keeps hidden status and conflicts, and reports body-read timeouts", async () => {
  const originalFetch = globalThis.fetch;
  const originalBase = process.env.GATEWAY_ADMIN_BASE;
  try {
    delete process.env.GATEWAY_ADMIN_BASE;
    assert.deepEqual(await (await bootstrapStatus()).json(), {
      ok: true,
      bootstrapEnabled: false,
      canBootstrap: false,
    });
    await assert.rejects(requestGateway("/status"), /GATEWAY_ADMIN_BASE/);
    process.env.GATEWAY_ADMIN_BASE = "http://gateway:4001/";
    globalThis.fetch = async () => new Response("hidden", { status: 404 });
    assert.deepEqual(await (await bootstrapStatus()).json(), {
      ok: true,
      bootstrapEnabled: false,
      canBootstrap: false,
    });
    globalThis.fetch = async (input, init) => {
      assert.equal(String(input), "http://gateway:4001/bootstrap/v1/tenant");
      assert.equal(init?.method, "POST");
      assert.ok(init?.signal);
      return new Response("already bootstrapped", { status: 409 });
    };
    const conflict = await bootstrap(
      new Request("http://ui/api/bootstrap/tenant", { method: "POST", body: "{}" }),
    );
    assert.equal(conflict.status, 409);
    assert.equal(await conflict.text(), "already bootstrapped");
    globalThis.fetch = async () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.error(new DOMException("deadline", "TimeoutError"));
          },
        }),
      );
    try {
      await requestGateway("/status");
      assert.fail("expected timeout");
    } catch (error) {
      const response = gatewayErrorResponse(error);
      assert.equal(response.status, 504);
      assert.deepEqual(await response.json(), { ok: false, error: "gateway request timed out" });
    }
  } finally {
    globalThis.fetch = originalFetch;
    if (originalBase === undefined) delete process.env.GATEWAY_ADMIN_BASE;
    else process.env.GATEWAY_ADMIN_BASE = originalBase;
  }
});
