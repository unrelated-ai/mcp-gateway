import { test, expect, type Page } from "@playwright/test";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
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
