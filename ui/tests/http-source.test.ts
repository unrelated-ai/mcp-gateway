import assert from "node:assert/strict";
import test from "node:test";
import {
  buildHttpSourceConfig,
  changeSchemaType,
  newHttpParam,
  newHttpTool,
  readHttpSourceDraft,
} from "../src/lib/http-source";
import { buildJsonSourceUpdate } from "../src/lib/tool-source-updates";

const config = {
  baseUrl: "https://example.com/v1",
  enabled: false,
  auth: { type: "bearer", token: "${secret:api_token}" },
  defaults: { timeout: 0, arrayStyle: "pipeDelimited", headers: { "X-Client": "gateway" } },
  responseTransforms: [{ type: "redactKeys", keys: ["token"] }],
  tools: {
    lookup: {
      method: "GET",
      path: "/items/{itemId}",
      description: "Original",
      params: {
        id: { in: "path", name: "itemId", schema: { type: "string", minLength: 3 } },
        filters: {
          in: "query",
          name: "filter",
          style: "deepObject",
          explode: true,
          allowReserved: true,
          allowEmptyValue: false,
          schema: { type: "object", properties: { active: { type: "boolean" } } },
          default: { active: true },
        },
      },
      response: {
        mode: "json",
        outputSchema: { type: "object", properties: { id: { type: "string" } } },
        transforms: { mode: "append", pipeline: [{ type: "dropNulls" }] },
      },
    },
  },
};

test("guided HTTP edits and renames preserve advanced settings and the loaded revision", () => {
  const original = structuredClone(config);
  const source = { revision: 17, type: "http", enabled: false, spec: config };
  const draft = readHttpSourceDraft(config);
  draft.enabled = true;
  draft.tools[0].name = "renamed";
  draft.tools[0].description = "Updated";
  draft.tools[0].params.find((param) => param.name === "filters")!.name = "search";
  const result = JSON.parse(
    JSON.stringify(buildJsonSourceUpdate(source, JSON.stringify(buildHttpSourceConfig(draft)))),
  );
  assert.equal(result.expectedRevision, 17);
  assert.equal(result.enabled, true);
  assert.equal(result.defaults.timeout, 0);
  assert.deepEqual(result.defaults, config.defaults);
  assert.deepEqual(result.auth, config.auth);
  assert.deepEqual(result.responseTransforms, config.responseTransforms);
  assert.equal(result.tools.lookup, undefined);
  assert.equal(result.tools.renamed.description, "Updated");
  assert.deepEqual(result.tools.renamed.response, config.tools.lookup.response);
  assert.deepEqual(result.tools.renamed.params.search, {
    ...config.tools.lookup.params.filters,
    required: false,
  });
  assert.equal(result.tools.renamed.params.id.required, true);
  assert.deepEqual(config, original);
});

test("HTTP optional fields can be cleared and tools or parameters removed", () => {
  const draft = readHttpSourceDraft(config);
  draft.timeout = "";
  draft.auth = { type: "none" };
  draft.headers = [];
  draft.arrayStyle = "";
  draft.tools[0].outputSchema = "";
  draft.tools[0].params[1].defaultValue = "";
  let value = JSON.parse(JSON.stringify(buildHttpSourceConfig(draft)));
  assert.deepEqual(value.defaults, { headers: {} });
  assert.equal(value.auth, null);
  assert.equal(value.tools.lookup.response.outputSchema, undefined);
  assert.deepEqual(value.tools.lookup.response.transforms, config.tools.lookup.response.transforms);
  assert.equal(value.tools.lookup.params.filters.default, undefined);
  draft.tools[0].params.splice(1, 1);
  value = buildHttpSourceConfig(draft);
  assert.equal(Object.keys(value.tools.lookup.params).length, 1);
  draft.tools = [];
  assert.deepEqual(buildHttpSourceConfig(draft).tools, {});
});

test("HTTP editor rejects collisions, invalid JSON, missing path bindings, and ignored body fields", () => {
  const invalid: [string, (draft: ReturnType<typeof readHttpSourceDraft>) => void][] = [
    [
      "Base URL",
      (d) => {
        d.baseUrl = "file:///tmp/private";
      },
    ],
    [
      "Base URL",
      (d) => {
        d.baseUrl = "https://user:password@example.com";
      },
    ],
    [
      "Timeout",
      (d) => {
        d.timeout = "1.5";
      },
    ],
    [
      "Authentication",
      (d) => {
        d.auth = { type: "bearer", token: "" };
      },
    ],
    [
      "duplicate",
      (d) => {
        d.tools.push(structuredClone(d.tools[0]));
      },
    ],
    [
      "duplicate",
      (d) => {
        d.headers.push({ id: "new", key: "x-client", value: "other" });
      },
    ],
    [
      "duplicate",
      (d) => {
        d.tools[0].params.push(structuredClone(d.tools[0].params[0]));
      },
    ],
    [
      "path parameter",
      (d) => {
        d.tools[0].path = "/items/{missing}";
      },
    ],
    [
      "JSON",
      (d) => {
        d.tools[0].params[0].schema = "{";
      },
    ],
    [
      "object",
      (d) => {
        d.tools[0].outputSchema = "[]";
      },
    ],
    [
      "body",
      (d) => {
        d.tools[0].params.push(
          { ...newHttpParam(), name: "body", location: "body" },
          { ...newHttpParam(), name: "field", location: "body" },
        );
      },
    ],
  ];
  for (const [message, change] of invalid) {
    const draft = readHttpSourceDraft(config);
    change(draft);
    assert.throws(() => buildHttpSourceConfig(draft), new RegExp(message));
  }
});

test("custom HTTP methods and schemas survive form/JSON round trips", () => {
  const draft = readHttpSourceDraft(config);
  draft.tools[0].method = "PROPFIND";
  draft.tools[0].params[1].schema = JSON.stringify({
    anyOf: [{ type: "string" }, { type: "integer" }],
  });
  const first = JSON.parse(JSON.stringify(buildHttpSourceConfig(draft)));
  assert.deepEqual(
    JSON.parse(JSON.stringify(buildHttpSourceConfig(readHttpSourceDraft(first)))),
    first,
  );
  assert.deepEqual(
    JSON.parse(changeSchemaType('{"type":"string","description":"Keep","minLength":3}', "array")),
    { type: "array", description: "Keep", minLength: 3, items: {} },
  );
  assert.equal(newHttpTool().method, "GET");
  assert.throws(() => readHttpSourceDraft({ baseUrl: "https://example.com", tools: [] }));
});
