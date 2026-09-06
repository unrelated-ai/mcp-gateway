import assert from "node:assert/strict";
import test from "node:test";
import { readRuntimeConfig } from "../src/lib/server/runtime-config";

test("runtime URL takes precedence and supports existing deployment variables", () => {
  assert.equal(
    readRuntimeConfig({
      GATEWAY_DATA_BASE: " https://gateway.test/base/// ",
      NEXT_PUBLIC_GATEWAY_DATA_BASE: "http://old.test",
    }).gatewayDataBase,
    "https://gateway.test/base",
  );
  assert.equal(
    readRuntimeConfig({ NEXT_PUBLIC_GATEWAY_DATA_BASE: "https://legacy.test/" }).gatewayDataBase,
    "https://legacy.test",
  );
  assert.equal(readRuntimeConfig({}).gatewayDataBase, "http://localhost:27100");
});
