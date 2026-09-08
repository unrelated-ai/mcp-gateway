import assert from "node:assert/strict";
import test from "node:test";
import { createProfileUpdater } from "../src/lib/profile-updates";
import { defaultMcpSettings } from "../src/lib/mcpSettings";
import type { Profile } from "../src/lib/types";

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function profile(): Profile {
  return {
    id: "one",
    tenantId: "tenant",
    dataPlanePath: "/one/mcp",
    name: "Original",
    description: "Description",
    enabled: true,
    allowPartialUpstreams: false,
    upstreams: [],
    sources: [],
    transforms: {},
    tools: [],
    dataPlaneAuth: { mode: "apiKey", acceptXApiKey: false },
    dataPlaneLimits: { rateLimitEnabled: false, quotaEnabled: false },
    toolCallTimeoutSecs: 15,
    toolPolicies: [],
    mcp: defaultMcpSettings(),
  };
}

test("overlapping panel edits serialize and preserve the latest saved fields", async () => {
  let stored = profile();
  const blocked = deferred();
  const entered = deferred();
  const writes: number[] = [];
  const update = createProfileUpdater({
    read: async () => structuredClone(stored),
    write: async (_id, body) => {
      writes.push(body.toolCallTimeoutSecs!);
      if (writes.length === 1) {
        entered.resolve();
        await blocked.promise;
      }
      stored = { ...stored, ...body };
    },
  });
  const first = update("one", { toolCallTimeoutSecs: 31 });
  await entered.promise;
  const second = update("one", { toolCallTimeoutSecs: 32 });
  const meta = update("one", { name: "Renamed" });
  assert.deepEqual(writes, [31]);
  blocked.resolve();
  await Promise.all([first, second, meta]);
  assert.deepEqual(writes, [31, 32, 32]);
  assert.equal(stored.name, "Renamed");
  assert.equal(stored.toolCallTimeoutSecs, 32);
});

test("a failed save can be retried, null clears fields, and submitted drafts are captured", async () => {
  let stored = profile();
  let fail = true;
  const update = createProfileUpdater({
    read: async () => structuredClone(stored),
    write: async (_id, body) => {
      if (fail) {
        fail = false;
        throw new Error("Gateway unavailable");
      }
      stored = { ...stored, ...body };
    },
  });
  await assert.rejects(update("one", { toolCallTimeoutSecs: null }), /Gateway unavailable/);
  assert.equal(stored.toolCallTimeoutSecs, 15);
  const patch = { toolCallTimeoutSecs: null, description: null, tools: ["echo"] };
  const retry = update("one", patch);
  patch.tools.push("later edit");
  await retry;
  assert.equal(stored.toolCallTimeoutSecs, null);
  assert.equal(stored.description, null);
  assert.deepEqual(stored.tools, ["echo"]);
});

test("a slow profile does not block another profile", async () => {
  const blocked = deferred();
  const writes: string[] = [];
  const update = createProfileUpdater({
    read: async (id) => {
      if (id === "slow") await blocked.promise;
      return profile();
    },
    write: async (id) => {
      writes.push(id);
    },
  });
  const slow = update("slow", { name: "Slow" });
  await update("fast", { name: "Fast" });
  assert.deepEqual(writes, ["fast"]);
  blocked.resolve();
  await slow;
});
