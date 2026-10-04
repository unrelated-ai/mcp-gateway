import { test, expect, type Page } from "@playwright/test";
import { execFile } from "node:child_process";
import { mkdir, readFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import type { Stack } from "./setup";

const run = promisify(execFile);
async function exec(
  command: string,
  args: string[],
  options: { env: NodeJS.ProcessEnv; timeout: number },
) {
  try {
    return await run(command, args, options);
  } catch (error) {
    const detail = error as Error & { stdout?: string; stderr?: string };
    throw new Error(`${detail.message}\n${detail.stdout ?? ""}\n${detail.stderr ?? ""}`);
  }
}
let stack: Stack;
let tenantToken = "";
let profileId = "";
const profilePath = () => `/profiles/${profileId}`;
const apiPath = () => `/api/tenant/profiles/${profileId}`;

test.describe.configure({ mode: "serial" });
test.beforeAll(async () => {
  stack = JSON.parse(await readFile(process.env.MCP_UI_E2E_STATE!, "utf8"));
});
test.beforeEach(async ({ page }) => {
  if (tenantToken) {
    const response = await page.request.post(`${stack.uiBase}/api/session/unlock`, {
      data: { token: tenantToken },
    });
    expect(response.ok()).toBeTruthy();
  }
});

async function openProfile(page: Page) {
  await page.goto(`${stack.uiBase}${profilePath()}`);
  await expect(page.getByRole("textbox", { name: "Timeout (seconds)" })).toBeVisible();
}

async function stored(page: Page) {
  const response = await page.request.get(`${stack.adminBase}/tenant/v1/profiles/${profileId}`, {
    headers: { Authorization: `Bearer ${tenantToken}` },
  });
  expect(response.ok(), await response.text()).toBeTruthy();
  return response.json();
}

async function timeout(page: Page, value: string) {
  const field = page.getByRole("textbox", { name: "Timeout (seconds)" });
  await field.fill(value);
  await field.press("Enter");
}

test("onboard, configure two real upstreams, create a key and call both tools with the CLI", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(stack.uiBase);
  await expect(page).toHaveURL(/\/onboarding$/);
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByRole("button", { name: "Next", exact: true }).click();
  const bootstrap = page.waitForResponse(
    (r) => r.url().endsWith("/api/bootstrap/tenant") && r.request().method() === "POST",
  );
  await page.getByRole("button", { name: "Create first tenant" }).click();
  const response = await bootstrap;
  expect(response.ok()).toBeTruthy();
  tenantToken = (await response.json()).token;
  await page.getByRole("button", { name: "Copy token", exact: true }).click();
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByRole("textbox", { name: "Tenant token" }).fill(tenantToken);
  await page.getByRole("button", { name: "Validate token", exact: true }).click();
  await page.getByRole("button", { name: "Unlock and enter dashboard" }).click();
  await expect(page).toHaveURL(/\/profiles$/);

  for (const [name, endpoint] of [
    ["remote", stack.remoteUrl],
    ["adapter", stack.adapterUrl],
  ]) {
    await page.goto(`${stack.uiBase}/sources/new/upstream`);
    await page.getByRole("textbox", { name: "Endpoint URL" }).fill(endpoint);
    await page.getByRole("button", { name: "Next", exact: true }).click();
    await page.getByRole("textbox", { name: "Upstream name" }).fill(name);
    await page.getByRole("button", { name: "Create upstream" }).click();
    await expect(page).toHaveURL(new RegExp(`/sources/upstreams/${name}$`));
  }

  await page.goto(`${stack.uiBase}/profiles/new`);
  await page.getByRole("textbox", { name: "Name", exact: true }).fill("Browser journey");
  await page
    .getByRole("textbox", { name: "Description (optional)" })
    .fill("Created from the browser");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByText("remote", { exact: true }).click();
  await page.getByText("adapter", { exact: true }).click();
  await page.getByRole("button", { name: "Create profile", exact: true }).click();
  await expect(page).toHaveURL(/\/profiles\/[a-f0-9-]{36}$/);
  profileId = page.url().split("/").pop()!;
  await page.getByRole("button", { name: "Probe surface" }).click();
  await expect(page.getByRole("textbox", { name: "Search tools" })).toBeVisible();
  await expect(page.getByText("whoami", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("echo", { exact: true }).first()).toBeVisible();
  await expect(
    page
      .locator("code")
      .filter({ hasText: `${stack.dataBase}/${profileId}/mcp` })
      .first(),
  ).toBeVisible();

  await page.getByRole("tab", { name: "API keys", exact: true }).click();
  await page.getByRole("button", { name: "Create API key", exact: true }).click();
  await page.getByRole("textbox", { name: "Key name (optional)" }).fill("browser-client");
  const createdKey = page.waitForResponse(
    (r) => r.url().endsWith("/api/tenant/api-keys") && r.request().method() === "POST",
  );
  await page.getByRole("button", { name: "Create key", exact: true }).click();
  const keyResponse = await createdKey;
  expect(keyResponse.ok()).toBeTruthy();
  const { secret } = await keyResponse.json();
  await expect(page.getByRole("dialog", { name: "API key created" })).toBeVisible();
  await page.getByRole("button", { name: "Done", exact: true }).click();

  const env = {
    ...process.env,
    XDG_CONFIG_HOME: path.join(stack.directory, "cli-config"),
    XDG_CACHE_HOME: path.join(stack.directory, "cli-cache"),
    UNRELATED_TOKEN: secret,
  };
  await exec(
    stack.cli,
    [
      "context",
      "add",
      "browser",
      "--url",
      `${stack.dataBase}/${profileId}/mcp`,
      "--auth",
      "api-key",
    ],
    { env, timeout: 15_000 },
  );
  const remoteSearch = JSON.parse(
    (await exec(stack.cli, ["--json", "tools", "search", "sessionless"], { env, timeout: 15_000 }))
      .stdout,
  );
  const adapterSearch = JSON.parse(
    (await exec(stack.cli, ["--json", "tools", "search", "whoami"], { env, timeout: 15_000 }))
      .stdout,
  );
  expect(remoteSearch).toHaveLength(1);
  expect(adapterSearch).toHaveLength(1);
  const remote = await exec(
    stack.cli,
    ["--json", "tools", "call", remoteSearch[0].toolRef, "--input", "{}", "--yes"],
    { env, timeout: 15_000 },
  );
  expect(JSON.parse(remote.stdout).content[0].text).toBe("ui-e2e");
  const adapter = await exec(
    stack.cli,
    ["--json", "tools", "call", adapterSearch[0].toolRef, "--input", "{}", "--yes"],
    { env, timeout: 15_000 },
  );
  expect(JSON.parse(adapter.stdout).content[0].text).toContain("instanceId");
  expect(errors).toEqual([]);
});

test("delayed saves retain the latest timeout and changes from another panel", async ({ page }) => {
  await openProfile(page);
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const writes: number[] = [];
  await page.route(`**${apiPath()}`, async (route) => {
    if (route.request().method() === "PUT") {
      writes.push(route.request().postDataJSON().toolCallTimeoutSecs);
      if (writes.length === 1) await gate;
    }
    await route.continue();
  });
  try {
    await timeout(page, "31");
    await expect.poll(() => writes.length).toBe(1);
    await timeout(page, "32");
    await page.getByRole("button", { name: "Edit profile name and description" }).click();
    await page.getByRole("textbox", { name: "Name", exact: true }).fill("Queued edits");
    await page.getByRole("textbox", { name: "Description", exact: true }).fill("");
    await page.getByRole("button", { name: "Save", exact: true }).click();
    // Give an overlapping request time to reach the intercepted network boundary.
    await page.waitForTimeout(250);
    expect(writes).toEqual([31]);
    release();
    await expect(page.getByRole("dialog", { name: "Edit profile" })).toBeHidden();
    await expect(page.getByRole("status", { name: "Timeout save status" })).toHaveText("Saved");
    const persisted = await stored(page);
    expect(persisted).toMatchObject({ toolCallTimeoutSecs: 32, name: "Queued edits" });
    expect(persisted.description ?? null).toBeNull();
    await page.reload();
    await expect(page.getByRole("textbox", { name: "Timeout (seconds)" })).toHaveValue("32");
  } finally {
    release();
    await page.unrouteAll({ behavior: "wait" });
  }
});

test("failed saves retain the draft, retry explicitly, and allow clearing the timeout", async ({
  page,
}) => {
  await openProfile(page);
  let fail = true;
  await page.route(`**${apiPath()}`, async (route) => {
    if (fail && route.request().method() === "PUT") {
      fail = false;
      await route.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify({ error: "Temporary test outage" }),
      });
    } else await route.continue();
  });
  await timeout(page, "51");
  const status = page.getByRole("status", { name: "Timeout save status" });
  await expect(status).toContainText("Not saved.");
  await expect(page.getByRole("textbox", { name: "Timeout (seconds)" })).toHaveValue("51");
  expect((await stored(page)).toolCallTimeoutSecs).toBe(32);
  await status.getByRole("button", { name: "Retry save" }).click();
  await expect(status).toHaveText("Saved");
  expect((await stored(page)).toolCallTimeoutSecs).toBe(51);
  await timeout(page, "");
  await expect(status).toHaveText("Saved");
  expect((await stored(page)).toolCallTimeoutSecs ?? null).toBeNull();
  await page.reload();
  await expect(page.getByRole("textbox", { name: "Timeout (seconds)" })).toHaveValue("");
});

test("queued edits finish when the user changes tabs", async ({ page }) => {
  await openProfile(page);
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  let writes = 0;
  await page.route(`**${apiPath()}`, async (route) => {
    if (route.request().method() === "PUT" && ++writes === 1) await gate;
    await route.continue();
  });
  try {
    await timeout(page, "41");
    await expect.poll(() => writes).toBe(1);
    await timeout(page, "42");
    await page.getByRole("tab", { name: "API keys", exact: true }).click();
    const latest = page.waitForResponse(
      (r) =>
        r.request().method() === "PUT" && r.request().postDataJSON().toolCallTimeoutSecs === 42,
    );
    release();
    const latestResponse = await latest;
    expect(latestResponse.ok(), await latestResponse.text()).toBeTruthy();
    await page.getByRole("tab", { name: "Tools", exact: true }).click();
    await expect(page.getByRole("textbox", { name: "Timeout (seconds)" })).toHaveValue("42");
  } finally {
    release();
    await page.unrouteAll({ behavior: "wait" });
  }
});

test("transform retries and MCP edits preserve each other", async ({ page }) => {
  await openProfile(page);
  await page.getByRole("button", { name: "Probe surface" }).click();
  const rename = page.getByRole("textbox", { name: "(optional) New exposed tool name" });
  await expect(rename).toBeVisible();
  let fail = true;
  await page.route(`**${apiPath()}`, async (route) => {
    if (fail && route.request().method() === "PUT") {
      fail = false;
      await route.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify({ error: "Temporary test outage" }),
      });
    } else await route.continue();
  });
  await rename.fill("whoami_browser");
  await rename.press("Enter");
  const transforms = page.getByRole("status", { name: "Tool transforms save status" });
  await expect(transforms).toContainText("Not saved.");
  await expect(rename).toHaveValue("whoami_browser");
  expect((await stored(page)).transforms?.toolOverrides?.whoami).toBeUndefined();
  await transforms.getByRole("button", { name: "Retry save" }).click();
  await expect(transforms).toHaveText("Saved");
  expect((await stored(page)).transforms.toolOverrides.whoami.rename).toBe("whoami_browser");
  await page.getByRole("tab", { name: "MCP settings", exact: true }).click();
  await page.getByRole("switch", { name: /^Logging/ }).uncheck();
  await expect(page.getByRole("status", { name: "MCP capabilities save status" })).toHaveText(
    "Saved",
  );
  await page.getByRole("tab", { name: "Security", exact: true }).click();
  await page
    .getByRole("combobox", { name: "Default upstream policy preset" })
    .selectOption("untrusted");
  await expect(page.getByRole("status", { name: "Security settings save status" })).toHaveText(
    "Saved",
  );
  const persisted = await stored(page);
  expect(persisted.mcp.capabilities.deny).toContain("logging");
  expect(persisted.mcp.security.upstreamDefault.clientCapabilitiesMode).toBe("strip");
  expect(persisted.transforms.toolOverrides.whoami.rename).toBe("whoami_browser");
  expect(persisted.toolCallTimeoutSecs).toBe(42);
  await page.reload();
  await page.getByRole("button", { name: "Probe surface" }).click();
  await expect(rename).toHaveValue("whoami_browser");
});

test("another browser edit requires reload even after a background refresh", async ({
  page,
  browser,
}) => {
  await openProfile(page);
  const otherContext = await browser.newContext();
  try {
    const other = await otherContext.newPage();
    await other.request.post(`${stack.uiBase}/api/session/unlock`, {
      data: { token: tenantToken },
    });
    await openProfile(other);
    await timeout(other, "55");
    await expect(other.getByRole("status", { name: "Timeout save status" })).toHaveText("Saved");
    const refresh = page.waitForResponse(
      (response) => response.url().endsWith(apiPath()) && response.request().method() === "GET",
    );
    await page.evaluate(async () => {
      window.dispatchEvent(new Event("offline"));
      await new Promise((resolve) => setTimeout(resolve, 0));
      window.dispatchEvent(new Event("online"));
    });
    expect((await refresh).ok()).toBeTruthy();
    await timeout(page, "56");
    const status = page.getByRole("status", { name: "Timeout save status" });
    await expect(status).toContainText("Profile changed in another window");
    expect((await stored(page)).toolCallTimeoutSecs).toBe(55);
    await expect(page.getByRole("textbox", { name: "Timeout (seconds)" })).toHaveValue("56");
    await status.getByRole("button", { name: "Reload profile" }).click();
    await expect(page.getByRole("textbox", { name: "Timeout (seconds)" })).toHaveValue("55");
    await timeout(page, "42");
    await expect(status).toHaveText("Saved");
  } finally {
    await otherContext.close();
  }
});

test("one standalone build serves two runtime Gateway URLs, including copied configs", async ({
  page,
  context,
}) => {
  await openProfile(page);
  await page.getByRole("button", { name: "Copy endpoint URL" }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(
    `${stack.dataBase}/${profileId}/mcp`,
  );
  const alternate = await context.newPage();
  await alternate.goto(`${stack.alternateUiBase}${profilePath()}`);
  await alternate.getByRole("button", { name: "Copy endpoint URL" }).click();
  expect(await alternate.evaluate(() => navigator.clipboard.readText())).toBe(
    `${stack.alternateDataBase}/${profileId}/mcp`,
  );
  await alternate.getByRole("button", { name: "Copy to clipboard", exact: true }).click();
  const config = JSON.parse(await alternate.evaluate(() => navigator.clipboard.readText()));
  expect(Object.values(config.mcpServers)[0]).toMatchObject({
    url: `${stack.alternateDataBase}/${profileId}/mcp`,
  });
  await alternate.close();
});

test("phone navigation and profile controls fit, with keyboard dismissal and focus return", async ({
  page,
}, testInfo) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await openProfile(page);
  const menu = page.getByRole("button", { name: "Open navigation" });
  await menu.click();
  const drawer = page.getByRole("dialog", { name: "Navigation" });
  await expect(drawer).toBeVisible();
  await expect(drawer).toHaveCSS("opacity", "1");
  await page.screenshot({ path: testInfo.outputPath("navigation-mobile.png") });
  await page.keyboard.press("Escape");
  await expect(drawer).toBeHidden();
  await expect(menu).toBeFocused();
  await menu.click();
  await drawer.getByRole("link", { name: "Profiles", exact: true }).click();
  await expect(drawer).toBeHidden();
  await page.getByRole("link", { name: "Queued edits", exact: true }).click();
  await page.getByRole("button", { name: "Probe surface" }).click();
  await expect(page.getByRole("textbox", { name: "Search tools" })).toBeVisible();
  const widths = await page.evaluate(() => ({
    viewport: innerWidth,
    document: document.documentElement.scrollWidth,
    main: document.querySelector("main")!.clientWidth,
    content: document.querySelector("main")!.scrollWidth,
  }));
  expect(widths.document).toBeLessThanOrEqual(widths.viewport);
  expect(widths.main).toBe(widths.viewport);
  expect(widths.content).toBeLessThanOrEqual(widths.main);
  await page.screenshot({ path: testInfo.outputPath("tools-mobile.png") });
  await page.locator("main").evaluate((main) => {
    main.scrollTop = 0;
  });
  await page.screenshot({ path: testInfo.outputPath("profile-mobile.png") });
});

test("connection checks run on demand and allow retry after failure", async ({ page }) => {
  let requests = 0;
  await page.route(`**${apiPath()}/connections`, async (route) => {
    requests++;
    if (requests === 1) {
      await route.fulfill({ status: 503, json: { error: "Temporary connection check outage" } });
    } else await route.continue();
  });
  await openProfile(page);
  expect(requests).toBe(0);
  const button = page.getByRole("button", { name: "Check connections", exact: true });
  await button.click();
  await expect(page.getByText("Temporary connection check outage", { exact: true })).toBeVisible();
  const response = page.waitForResponse((r) => r.url().endsWith(`${apiPath()}/connections`));
  await button.click();
  const results = await (await response).json();
  expect(results.checks.map((c: { sourceId: string }) => c.sourceId).sort()).toEqual([
    "adapter",
    "remote",
  ]);
  await expect(page.getByText("Connected", { exact: true })).toHaveCount(2);
  expect(requests).toBe(2);
  const card = page.locator("section").filter({ has: button });
  await mkdir(path.join(process.cwd(), "../output/playwright"), { recursive: true });
  await card.screenshot({ path: "../output/playwright/profile-connection-check.png" });
});

test("settings hydrate without browser errors and show tenant audit controls", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(`${stack.uiBase}/settings`);
  const audit = page.locator("section").filter({ has: page.getByText("Audit", { exact: true }) });
  await expect(audit.getByRole("combobox", { name: "Default detail level" })).toHaveValue(
    "metadata",
  );
  const tenant = page
    .locator("section")
    .filter({ has: page.getByText("Current tenant", { exact: true }) });
  await expect(tenant).not.toContainText("unknown");
  await mkdir(path.join(process.cwd(), "../output/playwright"), { recursive: true });
  await audit.screenshot({ path: "../output/playwright/tenant-audit-settings.png" });
  expect(errors).toEqual([]);
});

test("tenant writes keep session and cross-site protection", async ({ page, browser }) => {
  const unauthenticated = await browser.newContext();
  try {
    // Explicitly authenticate this raw HTTP request before testing the CSRF layer.
    const cookie = (await page.context().cookies()).map((c) => `${c.name}=${c.value}`).join("; ");
    for (const [method, endpoint] of [
      ["POST", "/api/tenant/managed-mcp/deployments"],
      ["PATCH", "/api/tenant/managed-mcp/deployments/test-request"],
      ["POST", `${apiPath()}/connections`],
      ["PUT", `${apiPath()}/audit/settings`],
    ]) {
      const url = `${stack.uiBase}${endpoint}`;
      const anonymous = await unauthenticated.request.fetch(url, { method, data: {} });
      expect(anonymous.status()).toBe(401);
      const crossSite = await page.request.fetch(url, {
        method,
        data: {},
        headers: { cookie, "sec-fetch-site": "cross-site" },
      });
      expect(crossSite.status()).toBe(403);
      expect(await crossSite.json()).toEqual({ ok: false, error: "cross-site request blocked" });
    }
  } finally {
    await unauthenticated.close();
  }
});

test("tool-call limits and advanced MCP controls persist without resetting other panels", async ({
  page,
}) => {
  await openProfile(page);
  const before = await stored(page);
  await page.getByRole("tab", { name: "Security", exact: true }).click();
  await page.getByRole("switch", { name: "Limit calls per minute", exact: true }).check();
  const save = page.getByRole("button", { name: "Save tool-call limits", exact: true });
  await page.getByRole("textbox", { name: "Calls per minute", exact: true }).fill("1.5");
  await expect(save).toBeDisabled();
  await page.getByRole("textbox", { name: "Calls per minute", exact: true }).fill("25");
  await page.getByRole("switch", { name: "Limit total calls", exact: true }).check();
  await page.getByRole("textbox", { name: "Initial call quota", exact: true }).fill("300");
  await save.click();
  await expect(page.getByRole("status", { name: "Tool-call limits save status" })).toHaveText(
    "Saved",
  );
  await page.getByRole("tab", { name: "MCP settings", exact: true }).click();
  await page
    .getByRole("textbox", { name: "Allowed notifications", exact: true })
    .fill("notifications/progress\nnotifications/progress");
  await page
    .getByRole("textbox", { name: "Denied notifications", exact: true })
    .fill("notifications/message");
  await page.getByRole("combobox", { name: "Proxied request IDs" }).selectOption("readable");
  await page.getByRole("combobox", { name: "SSE event IDs" }).selectOption("none");
  await page.getByRole("button", { name: "Save advanced MCP settings" }).click();
  await expect(page.getByRole("status", { name: "Advanced MCP settings save status" })).toHaveText(
    "Saved",
  );
  const after = await stored(page);
  expect(after.dataPlaneLimits).toEqual({
    rateLimitEnabled: true,
    rateLimitToolCallsPerMinute: 25,
    quotaEnabled: true,
    quotaToolCalls: 300,
  });
  expect(after.mcp.notifications).toEqual({
    allow: ["notifications/progress"],
    deny: ["notifications/message"],
  });
  expect(after.mcp.namespacing).toEqual({ requestId: "readable", sseEventId: "none" });
  expect(after.mcp.security).toEqual(before.mcp.security);
  expect(after.mcp.capabilities).toEqual(before.mcp.capabilities);
  expect(after.transforms).toEqual(before.transforms);
  await page.reload();
  await page.getByRole("tab", { name: "Security", exact: true }).click();
  await expect(page.getByRole("textbox", { name: "Initial call quota" })).toHaveValue("300");
  await page.getByRole("tab", { name: "MCP settings", exact: true }).click();
  await expect(page.getByRole("textbox", { name: "Allowed notifications" })).toHaveValue(
    "notifications/progress",
  );
  await expect(
    page.getByText("Enable native MCP above to use task routing.", { exact: false }),
  ).toBeVisible();
});

test("OpenAPI form preserves advanced fields and HTTP drafts survive refresh, failure, and conflicts", async ({
  page,
}) => {
  const headers = { Authorization: `Bearer ${tenantToken}` };
  const sourceUrl = (id: string) => `${stack.adminBase}/tenant/v1/tool-sources/${id}`;
  const advanced = {
    type: "openapi",
    enabled: true,
    spec: `${stack.remoteUrl}/spec.json`,
    specHash: "a".repeat(64),
    specHashPolicy: "ignore",
    endpoints: { "/ping": { get: { tool: "ping" } } },
    overrides: {
      tools: {
        custom: {
          match: { operationId: "ping" },
          request: { method: "GET", path: "/ping" },
          description: "Keep override",
        },
      },
    },
    responseOverrides: [{ match: { operationId: "ping" }, outputSchema: { type: "object" } }],
    defaults: { timeout: 10, headers: { "X-Test": "keep" } },
  };
  const create = await page.request.put(sourceUrl("editor-openapi"), { headers, data: advanced });
  expect(create.ok(), await create.text()).toBeTruthy();
  const original = await (await page.request.get(sourceUrl("editor-openapi"), { headers })).json();
  await page.goto(`${stack.uiBase}/sources/tool-sources/editor-openapi`);
  await page.getByRole("textbox", { name: "Default timeout (seconds)", exact: true }).fill("19");
  await page.getByRole("switch", { name: /^Source enabled/ }).uncheck();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByRole("tab", { name: "Tools", exact: true })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  const saved = await (await page.request.get(sourceUrl("editor-openapi"), { headers })).json();
  expect(saved.enabled).toBe(false);
  expect(saved.spec.defaults.timeout).toBe(19);
  for (const key of ["specHash", "specHashPolicy", "endpoints", "overrides", "responseOverrides"])
    expect(saved.spec[key]).toEqual(original.spec[key]);

  const http = {
    type: "http",
    enabled: true,
    baseUrl: stack.remoteUrl,
    tools: { ping: { method: "GET", path: "/ping" } },
  };
  expect(
    (await page.request.put(sourceUrl("editor-http"), { headers, data: http })).ok(),
  ).toBeTruthy();
  await page.goto(`${stack.uiBase}/sources/tool-sources/editor-http`);
  await page.getByRole("tab", { name: "Advanced JSON", exact: true }).click();
  const editor = page.getByRole("textbox", { name: "Source configuration JSON" });
  const draft = JSON.stringify(
    { ...http, tools: { ping: { method: "GET", path: "/draft" } } },
    null,
    2,
  );
  await editor.fill(draft);
  const refresh = page.waitForResponse(
    (r) =>
      r.request().method() === "GET" && r.url().endsWith("/api/tenant/tool-sources/editor-http"),
  );
  await page.evaluate(async () => {
    window.dispatchEvent(new Event("offline"));
    await new Promise((resolve) => setTimeout(resolve, 0));
    window.dispatchEvent(new Event("online"));
  });
  await refresh;
  await expect(editor).toHaveValue(draft);
  let fail = true;
  await page.route("**/api/tenant/tool-sources/editor-http", async (route) => {
    if (fail && route.request().method() === "PUT") {
      fail = false;
      await route.fulfill({ status: 503, json: { error: "Temporary source outage" } });
    } else await route.continue();
  });
  await page.getByRole("button", { name: "Save JSON", exact: true }).click();
  await expect(page.getByText("Temporary source outage", { exact: true }).first()).toBeVisible();
  await expect(editor).toHaveValue(draft);
  expect(
    (
      await page.request.put(sourceUrl("editor-http"), {
        headers,
        data: { ...http, enabled: false },
      })
    ).ok(),
  ).toBeTruthy();
  await page.getByRole("button", { name: "Save JSON", exact: true }).click();
  await expect(page.getByText(/Tool source changed in another window/).first()).toBeVisible();
  await expect(editor).toHaveValue(draft);
  await page.getByRole("button", { name: "Reload source", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Reload", exact: true }).click();
  await page.getByRole("tab", { name: "Advanced JSON", exact: true }).click();
  await expect.poll(async () => JSON.parse(await editor.inputValue()).enabled).toBe(false);
  await page.getByRole("switch", { name: /^Source enabled/ }).check();
  await page.getByRole("button", { name: "Save JSON", exact: true }).click();
  await expect
    .poll(
      async () =>
        (await (await page.request.get(sourceUrl("editor-http"), { headers })).json()).enabled,
    )
    .toBe(true);
});

test("catalogs expose later pages and searchable resource templates", async ({ page }) => {
  const resources = Array.from({ length: 65 }, (_, i) => ({
    uri: `resource:${i}`,
    name: `Resource ${i}`,
  }));
  const prompts = Array.from({ length: 65 }, (_, i) => ({ name: `prompt-${i}` }));
  const resourceTemplates = Array.from({ length: 65 }, (_, i) => ({
    uriTemplate: `template:${i}/{id}`,
    name: `Template ${i}`,
  }));
  await page.route(`**${apiPath()}/surface`, (route) =>
    route.fulfill({
      json: { sources: [], tools: [], allTools: [], resources, prompts, resourceTemplates },
    }),
  );
  await openProfile(page);
  await page.getByRole("tab", { name: "MCP settings", exact: true }).click();
  await page.getByRole("button", { name: "Probe surface", exact: true }).click();
  await page
    .getByRole("navigation", { name: "Resources pages" })
    .getByRole("button", { name: "Next" })
    .click();
  await expect(page.getByText("resource:64", { exact: true })).toBeVisible();
  await page.getByRole("textbox", { name: "Search resource templates" }).fill("64");
  await expect(page.getByText("template:64/{id}", { exact: true })).toBeVisible();
  await page.getByRole("textbox", { name: "Search prompts" }).fill("prompt-64");
  await expect(page.getByText("prompt-64", { exact: true })).toBeVisible();
});

test("audit loads older pages, preserves rows on failure, and scopes outcome to events", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  let failEvents = true;
  const eventQueries: URL[] = [];
  await page.route("**/api/tenant/audit/events?*", async (route) => {
    const url = new URL(route.request().url());
    eventQueries.push(url);
    const before = Number(url.searchParams.get("beforeId") ?? 251);
    if (before < 251 && failEvents) {
      await route.fulfill({ status: 503, json: { error: "Audit temporarily unavailable" } });
      return;
    }
    const count = Math.min(before - 1, Number(url.searchParams.get("limit")));
    const events = Array.from({ length: count }, (_, i) => ({
      id: before - i - 1,
      tsUnixSecs: 1700000000,
      action: "mcp.tools_call",
      toolRef: `tool-${before - i - 1}`,
      ok: true,
      meta: {},
    }));
    await route.fulfill({ json: { events } });
  });
  const statQueries: URL[] = [];
  await page.route("**/api/tenant/audit/analytics/tool-calls/*?*", async (route) => {
    const url = new URL(route.request().url());
    statQueries.push(url);
    const offset = Number(url.searchParams.get("offset"));
    const items = Array.from({ length: offset === 0 ? 100 : 1 }, (_, i) => ({
      toolRef: `stat-${offset + i}`,
      apiKeyId: `key-${offset + i}`,
      total: 1,
      ok: 1,
      err: 0,
    }));
    await route.fulfill({ json: { items } });
  });
  await page.goto(`${stack.uiBase}/audit?profileId=${profileId}`);
  await expect(page.getByRole("combobox", { name: "Profile", exact: true })).toHaveValue(profileId);
  await page.getByRole("combobox", { name: "Time range" }).selectOption("all");
  await expect(page.getByText("tool-250", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Load more events", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Could not load events" })).toContainText(
    "Audit temporarily unavailable",
  );
  await expect(page.getByText("tool-250", { exact: true })).toBeVisible();
  failEvents = false;
  await page.getByRole("button", { name: "Retry events", exact: true }).click();
  await expect(page.getByText("tool-51", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Load more events", exact: true }).click();
  await expect(page.getByText("tool-1", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Load more events", exact: true })).toBeHidden();
  const lastPages = eventQueries.filter((url) => !url.searchParams.has("fromUnixSecs"));
  expect(new Set(lastPages.map((url) => url.searchParams.get("toUnixSecs"))).size).toBe(1);
  await page.getByRole("combobox", { name: "Outcome" }).selectOption("error");
  await page.getByRole("tab", { name: "Analytics", exact: true }).click();
  await expect(page.getByRole("combobox", { name: "Outcome" })).toBeHidden();
  await page.getByRole("button", { name: "Load more tools", exact: true }).click();
  await expect(page.getByText("stat-100", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Load more API keys", exact: true }).click();
  await expect(page.getByText("key-100", { exact: true })).toBeVisible();
  expect(statQueries.every((url) => !url.searchParams.has("ok"))).toBe(true);
  expect(statQueries.some((url) => url.searchParams.get("offset") === "100")).toBe(true);
  expect(statQueries.every((url) => url.searchParams.get("profileId") === profileId)).toBe(true);
  expect(errors).toEqual([]);
});

test("token validation rejects a forged signature before offering to unlock", async ({ page }) => {
  await page.goto(`${stack.uiBase}/unlock`);
  const parts = tenantToken.split(".");
  parts[2] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  await page.getByRole("textbox", { name: "Tenant token" }).fill(parts.join("."));
  await page.getByRole("button", { name: "Validate token", exact: true }).click();
  await expect(page.getByText("Token validation failed", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Unlock and enter dashboard" })).toBeHidden();
  await page.getByRole("textbox", { name: "Tenant token" }).fill(`Bearer ${tenantToken}`);
  await page.getByRole("button", { name: "Validate token", exact: true }).click();
  await expect(page.getByText("Token validated", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Unlock and enter dashboard" }).click();
  await expect(page).toHaveURL(/\/profiles$/);
});

test("profile audit shows inherited policy, retries failed saves, and shares revisions with other panels", async ({
  page,
}) => {
  const headers = { Authorization: `Bearer ${tenantToken}` };
  const tenantSettingsUrl = `${stack.adminBase}/tenant/v1/audit/settings`;
  expect(
    (
      await page.request.put(tenantSettingsUrl, {
        headers,
        data: { enabled: true, retentionDays: 17, defaultLevel: "metadata" },
      })
    ).ok(),
  ).toBeTruthy();
  await openProfile(page);
  await page.getByRole("tab", { name: "Security", exact: true }).click();
  const select = page.getByRole("combobox", { name: "Profile audit detail" });
  const effective = page.getByLabel("Effective audit level", { exact: true });
  const status = page.getByRole("status", { name: "Profile audit save status" });
  await expect(select).toHaveValue("inherit");
  await expect(effective).toHaveText("Metadata");
  await expect(page.getByText("17 days · tenant-wide", { exact: true })).toBeVisible();
  let fail = true;
  await page.route(`**${apiPath()}/audit/settings`, async (route) => {
    if (fail && route.request().method() === "PUT") {
      fail = false;
      await route.fulfill({ status: 503, json: { error: "Temporary audit save outage" } });
    } else await route.continue();
  });
  await select.selectOption("summary");
  await page.getByRole("button", { name: "Save profile audit", exact: true }).click();
  await expect(status).toContainText("Temporary audit save outage");
  await expect(select).toHaveValue("summary");
  await expect(effective).toHaveText("Metadata");
  await status.getByRole("button", { name: "Retry save", exact: true }).click();
  await expect(status).toHaveText("Saved");
  await expect(effective).toHaveText("Summary");
  await page.getByRole("button", { name: "Edit profile name and description" }).click();
  await page
    .getByRole("textbox", { name: "Description", exact: true })
    .fill("Audit settings share profile revisions");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "Edit profile" })).toBeHidden();
  await select.selectOption("off");
  await page.getByRole("button", { name: "Save profile audit", exact: true }).click();
  await expect(status).toHaveText("Saved");
  await expect(effective).toHaveText("Off");
  expect((await stored(page)).description).toBe("Audit settings share profile revisions");
  await page.reload();
  await page.getByRole("tab", { name: "Security", exact: true }).click();
  await expect(select).toHaveValue("off");
  await expect(effective).toHaveText("Off");
  const card = page.locator("section").filter({ has: select });
  await card.screenshot({ path: "../output/playwright/profile-audit-settings.png" });
});

test("profile audit preserves conflicting drafts and shows the tenant master switch", async ({
  page,
}) => {
  await openProfile(page);
  await page.getByRole("tab", { name: "Security", exact: true }).click();
  const select = page.getByRole("combobox", { name: "Profile audit detail" });
  const effective = page.getByLabel("Effective audit level", { exact: true });
  await expect(select).toHaveValue("off");
  await select.selectOption("payload");
  const headers = { Authorization: `Bearer ${tenantToken}` };
  const auditUrl = `${stack.adminBase}/tenant/v1/profiles/${profileId}/audit/settings`;
  const before = await (await page.request.get(auditUrl, { headers })).json();
  expect(
    (
      await page.request.put(auditUrl, {
        headers,
        data: { auditSettings: { level: "summary" }, expectedRevision: before.revision },
      })
    ).ok(),
  ).toBeTruthy();
  const refresh = page.waitForResponse(
    (r) => r.request().method() === "GET" && r.url().endsWith(`${apiPath()}/audit/settings`),
  );
  await page.evaluate(async () => {
    window.dispatchEvent(new Event("offline"));
    await new Promise((resolve) => setTimeout(resolve, 0));
    window.dispatchEvent(new Event("online"));
  });
  await refresh;
  await expect(select).toHaveValue("payload");
  await expect(effective).toHaveText("Summary");
  await page.getByRole("button", { name: "Save profile audit", exact: true }).click();
  const status = page.getByRole("status", { name: "Profile audit save status" });
  await expect(status).toContainText("Profile changed in another window");
  await expect(select).toHaveValue("payload");
  await status.getByRole("button", { name: "Reload profile", exact: true }).click();
  await page.getByRole("tab", { name: "Security", exact: true }).click();
  await expect(select).toHaveValue("summary");
  const tenantSettingsUrl = `${stack.adminBase}/tenant/v1/audit/settings`;
  expect(
    (
      await page.request.put(tenantSettingsUrl, {
        headers,
        data: { enabled: false, retentionDays: 17, defaultLevel: "metadata" },
      })
    ).ok(),
  ).toBeTruthy();
  await page.reload();
  await page.getByRole("tab", { name: "Security", exact: true }).click();
  await expect(effective).toHaveText("Off");
  await expect(
    page.getByText("Audit logging is off for the tenant.", { exact: false }),
  ).toBeVisible();
  await expect(select).toHaveValue("summary");
  expect(
    (
      await page.request.put(tenantSettingsUrl, {
        headers,
        data: { enabled: true, retentionDays: 17, defaultLevel: "payload" },
      })
    ).ok(),
  ).toBeTruthy();
  await page.reload();
  await page.getByRole("tab", { name: "Security", exact: true }).click();
  await expect(effective).toHaveText("Summary");
  await select.selectOption("inherit");
  await page.getByRole("button", { name: "Save profile audit", exact: true }).click();
  await expect(status).toHaveText("Saved");
  await expect(effective).toHaveText("Payload samples");
});

test("unsupported profile audit settings can be explicitly replaced with inheritance", async ({
  page,
}) => {
  let legacy = true;
  await page.route(`**${apiPath()}/audit/settings`, async (route) => {
    if (route.request().method() === "PUT") legacy = false;
    if (route.request().method() === "GET" && legacy) {
      const response = await route.fetch();
      await route.fulfill({
        response,
        json: { ...(await response.json()), auditSettings: {}, hasUnrecognizedSettings: true },
      });
    } else await route.continue();
  });
  await openProfile(page);
  await page.getByRole("tab", { name: "Security", exact: true }).click();
  const select = page.getByRole("combobox", { name: "Profile audit detail" });
  await expect(select).toHaveValue("inherit");
  const notice = page.getByText("The saved settings use an unsupported format.", { exact: false });
  await expect(notice).toBeVisible();
  await page.getByRole("button", { name: "Save profile audit", exact: true }).click();
  await expect(page.getByRole("status", { name: "Profile audit save status" })).toHaveText("Saved");
  await expect(notice).toBeHidden();
  await expect(select).toHaveValue("inherit");
});

test("guided HTTP creation produces a working tool with path, query, body, and secret authentication", async ({
  page,
}) => {
  const headers = { Authorization: `Bearer ${tenantToken}` };
  expect(
    (
      await page.request.post(`${stack.adminBase}/tenant/v1/secrets`, {
        headers,
        data: { name: "EDITOR_TOKEN", value: "local-http-token" },
      })
    ).ok(),
  ).toBeTruthy();
  await page.goto(`${stack.uiBase}/sources`);
  await page.getByRole("button", { name: "Add source", exact: true }).first().click();
  await page
    .getByRole("button", { name: "HTTP Define API requests as tools", exact: true })
    .click();
  await expect(page).toHaveURL(/\/sources\/new\/http$/);
  await page.getByRole("textbox", { name: "Source name", exact: true }).fill("browser-http");
  await page.getByRole("textbox", { name: "Base URL", exact: true }).fill(stack.httpBase);
  await page.getByRole("combobox", { name: "Source authentication" }).selectOption("bearer");
  await page.getByLabel("Bearer token", { exact: true }).fill("${secret:EDITOR_TOKEN}");
  await page.getByRole("textbox", { name: "Timeout (seconds)" }).fill("17");
  await page.getByRole("button", { name: "Add header", exact: true }).click();
  await page.getByRole("textbox", { name: "Header 1 name", exact: true }).fill("X-Client");
  await page.getByRole("textbox", { name: "Header 1 value", exact: true }).fill("guided-editor");
  await page.getByRole("button", { name: "Add tool", exact: true }).click();
  const tool = page.getByRole("group", { name: "Tool 1", exact: true });
  await tool.getByRole("textbox", { name: "Tool name", exact: true }).fill("update_item");
  await tool.getByRole("textbox", { name: "Description", exact: true }).fill("Update an item");
  await tool.getByLabel("HTTP method", { exact: true }).fill("POST");
  await tool.getByRole("textbox", { name: "Request path", exact: true }).fill("/items/{itemId}");
  for (const [index, name, location, type] of [
    [1, "id", "path", "string"],
    [2, "limit", "query", "integer"],
    [3, "body", "body", "object"],
  ] as const) {
    await tool.getByRole("button", { name: "Add parameter", exact: true }).click();
    const param = tool.getByRole("group", { name: `Parameter ${index}`, exact: true });
    await param.getByRole("textbox", { name: "Argument name", exact: true }).fill(name);
    await param.getByRole("combobox", { name: "Send in", exact: true }).selectOption(location);
    await param.getByRole("combobox", { name: "Argument type", exact: true }).selectOption(type);
    if (index < 3)
      await param
        .getByRole("textbox", { name: "HTTP name (optional)", exact: true })
        .fill(index === 1 ? "itemId" : "count");
  }
  await tool.getByText("Output schema", { exact: true }).click();
  await tool
    .getByRole("textbox", { name: "Output schema JSON", exact: true })
    .fill('{"type":"object"}');
  await page.getByRole("button", { name: "Create HTTP source", exact: true }).click();
  await expect(page).toHaveURL(/\/sources\/tool-sources\/browser-http$/);
  await expect(page.getByLabel("Bearer token", { exact: true })).toHaveValue(
    "${secret:EDITOR_TOKEN}",
  );
  const created = await page.request.post(`${stack.adminBase}/tenant/v1/profiles`, {
    headers,
    data: {
      name: "HTTP editor call",
      enabled: true,
      sources: ["browser-http"],
      upstreams: [],
      dataPlaneAuth: { mode: "disabled" },
    },
  });
  expect(created.ok(), await created.text()).toBeTruthy();
  const profile = await created.json();
  const env = {
    ...process.env,
    XDG_CONFIG_HOME: path.join(stack.directory, "http-client-config"),
    XDG_CACHE_HOME: path.join(stack.directory, "http-client-cache"),
    UNRELATED_TOKEN: undefined,
  };
  await exec(
    stack.cli,
    [
      "context",
      "add",
      "http-editor",
      "--url",
      `${stack.dataBase}/${profile.id}/mcp`,
      "--auth",
      "none",
    ],
    { env, timeout: 15000 },
  );
  const search = JSON.parse(
    (
      await exec(stack.cli, ["--json", "tools", "search", "Update an item"], {
        env,
        timeout: 15000,
      })
    ).stdout,
  );
  expect(search).toHaveLength(1);
  const response = JSON.parse(
    (
      await exec(
        stack.cli,
        [
          "--json",
          "tools",
          "call",
          search[0].toolRef,
          "--input",
          JSON.stringify({
            id: "item-42",
            limit: 5,
            body: { title: "Saved from the guided editor" },
          }),
          "--yes",
        ],
        { env, timeout: 15000 },
      )
    ).stdout,
  );
  expect(response.structuredContent.body).toEqual({
    id: "item-42",
    query: { count: "5" },
    caller: "guided-editor",
    body: { title: "Saved from the guided editor" },
  });
  await page.screenshot({ path: "../output/playwright/http-source-editor.png", fullPage: true });
  await tool.screenshot({ path: "../output/playwright/http-tool-editor.png" });
});

test("HTTP editors share drafts, preserve advanced fields, and reject invalid or conflicting saves", async ({
  page,
}) => {
  const headers = { Authorization: `Bearer ${tenantToken}` };
  const url = `${stack.adminBase}/tenant/v1/tool-sources/browser-http`;
  const loaded = await (await page.request.get(url, { headers })).json();
  const advanced = {
    ...loaded.spec,
    type: "http",
    enabled: true,
    responseTransforms: [{ type: "dropNulls" }],
    tools: {
      ...loaded.spec.tools,
      custom: {
        method: "PROPFIND",
        path: "/custom",
        params: {
          filter: {
            in: "query",
            schema: { type: "object", additionalProperties: false },
            style: "deepObject",
            explode: true,
            allowReserved: true,
          },
        },
        response: {
          mode: "json",
          transforms: { mode: "append", pipeline: [{ type: "redactKeys", keys: ["token"] }] },
        },
      },
    },
  };
  expect((await page.request.put(url, { headers, data: advanced })).ok()).toBeTruthy();
  const canonical = (await (await page.request.get(url, { headers })).json()).spec;
  await page.goto(`${stack.uiBase}/sources/tool-sources/browser-http`);
  const tool = page
    .getByRole("group", { name: /^Tool \d+$/ })
    .filter({
      has: page
        .getByRole("textbox", { name: "Tool name", exact: true })
        .and(page.locator('input[value="custom"]')),
    })
    .first();
  // The source's tool order is a map; locate by its configured name.
  await expect(tool).toBeVisible();
  await tool.getByRole("textbox", { name: "Description", exact: true }).fill("Guided change");
  await page.getByRole("tab", { name: "Advanced JSON", exact: true }).click();
  const editor = page.getByRole("textbox", { name: "Source configuration JSON" });
  const draft = JSON.parse(await editor.inputValue());
  expect(draft.tools.custom.description).toBe("Guided change");
  expect(draft.tools.custom.response.transforms).toEqual(
    canonical.tools.custom.response.transforms,
  );
  await editor.fill("{");
  await page.getByRole("tab", { name: "Guided editor", exact: true }).click();
  await expect(page.getByRole("tab", { name: "Advanced JSON", exact: true })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(editor).toHaveValue("{");
  draft.tools.custom.description = "JSON change";
  await editor.fill(JSON.stringify(draft, null, 2));
  await page.getByRole("tab", { name: "Guided editor", exact: true }).click();
  await expect(tool.getByRole("textbox", { name: "Description", exact: true })).toHaveValue(
    "JSON change",
  );
  const parameter = tool.getByRole("group", { name: "Parameter 1", exact: true });
  await parameter.getByText("Argument schema", { exact: true }).click();
  const schema = parameter.getByRole("textbox", { name: "Argument schema JSON", exact: true });
  const schemaBefore = await schema.inputValue();
  await schema.fill("[]");
  await expect(
    parameter.getByRole("combobox", { name: "Argument type", exact: true }),
  ).toBeDisabled();
  await schema.fill(schemaBefore);
  await expect(
    parameter.getByRole("combobox", { name: "Argument type", exact: true }),
  ).toBeEnabled();
  await tool.getByRole("textbox", { name: "Tool name", exact: true }).fill("renamed_custom");
  const timeout = page.getByRole("textbox", { name: "Timeout (seconds)" });
  await timeout.fill("1.5");
  await page.getByRole("button", { name: "Save HTTP source", exact: true }).click();
  await expect(page.getByRole("alert", { name: "HTTP source error" })).toContainText(
    "whole number",
  );
  await timeout.fill("0");
  let fail = true;
  await page.route("**/api/tenant/tool-sources/browser-http", async (route) => {
    if (fail && route.request().method() === "PUT") {
      fail = false;
      await route.fulfill({ status: 503, json: { error: "Temporary HTTP source outage" } });
    } else await route.continue();
  });
  await page.getByRole("button", { name: "Save HTTP source", exact: true }).click();
  await expect(page.getByRole("alert", { name: "HTTP source error" })).toContainText(
    "Temporary HTTP source outage",
  );
  await expect(
    page
      .getByRole("textbox", { name: "Tool name", exact: true })
      .and(page.locator('input[value="renamed_custom"]')),
  ).toBeVisible();
  await page.getByRole("button", { name: "Save HTTP source", exact: true }).click();
  await expect
    .poll(
      async () => (await (await page.request.get(url, { headers })).json()).spec.defaults.timeout,
    )
    .toBe(0);
  const saved = await (await page.request.get(url, { headers })).json();
  expect(saved.spec.responseTransforms).toEqual(canonical.responseTransforms);
  expect(saved.spec.tools.renamed_custom.response.transforms).toEqual(
    canonical.tools.custom.response.transforms,
  );
  expect(saved.spec.tools.renamed_custom.params.filter).toMatchObject(
    advanced.tools.custom.params.filter,
  );
  expect(saved.spec.tools.custom).toBeUndefined();
  await expect(timeout).toHaveValue("0");
  await timeout.fill("29");
  expect(
    (
      await page.request.put(url, {
        headers,
        data: { ...saved.spec, type: "http", enabled: false },
      })
    ).ok(),
  ).toBeTruthy();
  const refresh = page.waitForResponse(
    (r) =>
      r.request().method() === "GET" && r.url().endsWith("/api/tenant/tool-sources/browser-http"),
  );
  await page.evaluate(async () => {
    window.dispatchEvent(new Event("offline"));
    await new Promise((r) => setTimeout(r, 0));
    window.dispatchEvent(new Event("online"));
  });
  await refresh;
  await expect(timeout).toHaveValue("29");
  await page.getByRole("button", { name: "Save HTTP source", exact: true }).click();
  await expect(page.getByRole("alert", { name: "HTTP source error" })).toContainText(
    "Tool source changed in another window",
  );
  await expect(timeout).toHaveValue("29");
  await page.getByRole("button", { name: "Reload source", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Reload", exact: true }).click();
  await expect(timeout).toHaveValue("0");
  await expect(page.getByRole("switch", { name: /^Source enabled/ })).not.toBeChecked();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({
    path: "../output/playwright/http-source-editor-mobile.png",
    fullPage: true,
  });
});

test("resource and prompt controls persist, retry, preview, and preserve tool transforms", async ({
  page,
}) => {
  await page.goto(`${stack.uiBase}/sources/new/upstream`);
  await page.getByRole("textbox", { name: "Endpoint URL" }).fill(`${stack.httpBase}/mcp`);
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByRole("textbox", { name: "Upstream name" }).fill("catalog");
  await page.getByRole("button", { name: "Create upstream" }).click();
  await expect(page).toHaveURL(/\/sources\/upstreams\/catalog$/);
  const headers = { Authorization: `Bearer ${tenantToken}` };
  const created = await page.request.post(`${stack.adminBase}/tenant/v1/profiles`, {
    headers,
    data: {
      name: "Catalog controls",
      upstreams: ["catalog"],
      sources: [],
      dataPlaneAuth: { mode: "disabled" },
      mcp: { modernProtocol: true },
    },
  });
  expect(created.ok(), await created.text()).toBeTruthy();
  const { id } = await created.json();
  const url = `${stack.adminBase}/tenant/v1/profiles/${id}`;
  const storedCatalog = async () => await (await page.request.get(url, { headers })).json();
  await page.goto(`${stack.uiBase}/profiles/${id}`);
  await page.getByRole("button", { name: "Probe surface", exact: true }).click();
  await page.getByRole("tab", { name: "MCP settings", exact: true }).click();
  const entry = page.getByRole("combobox", { name: "Catalog entry", exact: true });
  await expect(entry).toContainText("Guide");
  const source = JSON.parse(await entry.inputValue())[0];
  await page.getByRole("textbox", { name: "Display name", exact: true }).fill("Team handbook");
  await expect(page.getByRole("region", { name: "Client preview" })).toContainText("Team handbook");
  let fail = true;
  await page.route(`**/api/tenant/profiles/${id}`, async (route) => {
    if (fail && route.request().method() === "PUT") {
      fail = false;
      await route.fulfill({ status: 503, json: { error: "Temporary catalog save outage" } });
    } else await route.continue();
  });
  await page.getByRole("button", { name: "Save catalog settings" }).click();
  await expect(page.getByRole("alert", { name: "Catalog settings error" })).toContainText(
    "Temporary catalog save outage",
  );
  await expect(page.getByRole("textbox", { name: "Display name", exact: true })).toHaveValue(
    "Team handbook",
  );
  await page.getByRole("button", { name: "Save catalog settings" }).click();
  await expect(page.getByRole("status", { name: "Catalog settings save status" })).toHaveText(
    "Saved",
  );
  expect((await storedCatalog()).transforms.resourceOverrides[source]["docs:///guide"].name).toBe(
    "Team handbook",
  );
  await page.getByRole("switch", { name: /^Available to clients/ }).uncheck();
  await page.getByRole("button", { name: "Save catalog settings" }).click();
  await expect(page.getByRole("status", { name: "Catalog settings save status" })).toHaveText(
    "Saved",
  );
  await expect(entry).toContainText("disabled");
  await page.getByRole("tab", { name: "Resource templates", exact: true }).click();
  await page.getByRole("textbox", { name: "Display title", exact: true }).fill("Order details");
  await page.getByRole("button", { name: "Save catalog settings" }).click();
  await expect(page.getByRole("status", { name: "Catalog settings save status" })).toHaveText(
    "Saved",
  );
  await page.getByRole("tab", { name: "Prompts", exact: true }).click();
  await page.getByRole("textbox", { name: "Prompt alias", exact: true }).fill("review_changes");
  const argument = page.getByRole("group", { name: "Prompt argument topic", exact: true });
  await argument.getByRole("textbox", { name: "Argument alias" }).fill("subject");
  await page.getByRole("tab", { name: "Tools", exact: true }).click();
  await page.getByRole("tab", { name: "MCP settings", exact: true }).click();
  await expect(argument.getByRole("textbox", { name: "Argument alias" })).toHaveValue("subject");
  await argument.getByRole("switch", { name: /^Supply a default/ }).check();
  await argument.getByRole("textbox", { name: "Default argument value" }).fill("Recent changes");
  await expect(page.getByRole("region", { name: "Client preview" })).toContainText("subject");
  await expect(page.getByRole("region", { name: "Client preview" })).toContainText(
    "Recent changes",
  );
  await page.getByRole("button", { name: "Save catalog settings" }).click();
  await expect(page.getByRole("status", { name: "Catalog settings save status" })).toHaveText(
    "Saved",
  );
  const catalogRules = (await storedCatalog()).transforms;
  await page.getByRole("tab", { name: "Tools", exact: true }).click();
  const rename = page.getByRole("textbox", { name: "(optional) New exposed tool name" });
  await rename.fill("find_item");
  await rename.press("Enter");
  await expect(page.getByRole("status", { name: "Tool transforms save status" })).toHaveText(
    "Saved",
  );
  const latest = await storedCatalog();
  expect(latest.transforms.resourceOverrides).toEqual(catalogRules.resourceOverrides);
  expect(latest.transforms.resourceTemplateOverrides).toEqual(
    catalogRules.resourceTemplateOverrides,
  );
  expect(latest.transforms.promptOverrides).toEqual(catalogRules.promptOverrides);
  expect(latest.transforms.toolOverrides.lookup.rename).toBe("find_item");
  await page.getByRole("tab", { name: "MCP settings", exact: true }).click();
  await page.getByRole("tab", { name: "Prompts", exact: true }).click();
  await expect(page.getByRole("textbox", { name: "Prompt alias", exact: true })).toHaveValue(
    "review_changes",
  );
  await page.getByRole("textbox", { name: "Prompt alias", exact: true }).fill("unsaved_review");
  expect(
    (
      await page.request.put(url, { headers, data: { ...latest, description: "Edited elsewhere" } })
    ).ok(),
  ).toBeTruthy();
  await page.getByRole("button", { name: "Save catalog settings" }).click();
  await expect(page.getByRole("alert", { name: "Catalog settings error" })).toContainText(
    "Profile changed in another window",
  );
  await expect(page.getByRole("textbox", { name: "Prompt alias", exact: true })).toHaveValue(
    "unsaved_review",
  );
  await page.getByRole("button", { name: "Reload saved settings" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Reload", exact: true }).click();
  await expect(page.getByRole("textbox", { name: "Prompt alias", exact: true })).toHaveValue(
    "review_changes",
  );
  await page.getByRole("textbox", { name: "Prompt alias", exact: true }).fill("review_final");
  await page.getByRole("button", { name: "Save catalog settings" }).click();
  await expect(page.getByRole("status", { name: "Catalog settings save status" })).toHaveText(
    "Saved",
  );
  expect((await storedCatalog()).transforms.toolOverrides.lookup.rename).toBe("find_item");
  await page.getByRole("region", { name: "Client preview" }).scrollIntoViewIfNeeded();
  await page.screenshot({ path: "../output/playwright/catalog-transforms.png" });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
