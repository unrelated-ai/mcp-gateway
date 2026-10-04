import assert from "node:assert/strict";
import test from "node:test";
import { buildJsonSourceUpdate, buildOpenApiSourceUpdate } from "../src/lib/tool-source-updates";

test("OpenAPI form edits preserve advanced configuration and clear owned optional fields", () => {
  const source = {
    revision: 7,
    type: "openapi",
    enabled: true,
    spec: {
      spec: "https://example.com/openapi.json",
      specHash: "pin",
      specHashPolicy: "fail",
      endpoints: { "/ping": { get: { tool: "ping" } } },
      overrides: { tools: { custom: { description: "Keep" } } },
      responseTransforms: [{ type: "pick", path: "data" }],
      defaults: { timeout: 30, retry: { maximumAttempts: 3 }, headers: { Old: "header" } },
      auth: { type: "bearer", token: "${secret:api_token}" },
      baseUrl: "https://old.example.com",
    },
  };
  const original = structuredClone(source);
  const value = JSON.parse(
    JSON.stringify(
      buildOpenApiSourceUpdate(source, {
        enabled: false,
        auth: null,
        baseUrl: null,
        defaults: { timeout: undefined, headers: {} },
      }),
    ),
  );
  assert.equal(value.expectedRevision, 7);
  assert.equal(value.enabled, false);
  for (const key of [
    "specHash",
    "specHashPolicy",
    "endpoints",
    "overrides",
    "responseTransforms",
  ] as const) {
    assert.deepEqual(value[key], source.spec[key]);
  }
  assert.deepEqual(value.defaults, { retry: { maximumAttempts: 3 }, headers: {} });
  assert.equal(value.auth, null);
  assert.equal(value.baseUrl, null);
  assert.deepEqual(source, original);
});

test("JSON edits retain the loaded revision and source type", () => {
  const source = { revision: 2, type: "http", enabled: true, spec: {} };
  assert.deepEqual(buildJsonSourceUpdate(source, '{"enabled":false,"expectedRevision":9}'), {
    enabled: false,
    expectedRevision: 2,
    type: "http",
  });
  for (const text of ["[]", "null", '"text"']) {
    assert.throws(() => buildJsonSourceUpdate(source, text), /JSON object/);
  }
});
