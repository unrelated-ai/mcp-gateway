import { spawn, type ChildProcess } from "node:child_process";
import { createWriteStream } from "node:fs";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";

export type Stack = {
  adminBase: string;
  dataBase: string;
  remoteUrl: string;
  adapterUrl: string;
  cli: string;
  uiBase: string;
  alternateUiBase: string;
  alternateDataBase: string;
  directory: string;
};

async function port() {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("No local port available");
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  return address.port;
}

async function until(
  check: () => Promise<boolean>,
  child: ChildProcess,
  label: string,
  timeout = 120_000,
) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null)
      throw new Error(`${label} exited; inspect output/playwright/e2e-logs`);
    if (await check()) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`${label} did not become ready; inspect output/playwright/e2e-logs`);
}

async function stop(child: ChildProcess) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
  child.kill("SIGTERM");
  const timer = setTimeout(() => child.kill("SIGKILL"), 5000);
  await exited;
  clearTimeout(timer);
}

export default async function setup() {
  const ui = path.resolve(__dirname, "..");
  const root = path.resolve(ui, "..");
  const directory = await mkdtemp(path.join(tmpdir(), "mcp-ui-e2e-"));
  const state = path.join(directory, "fixture.json");
  const logs = path.join(root, "output/playwright/e2e-logs");
  await mkdir(logs, { recursive: true });
  const launch = (command: string, args: string[], name: string, env: NodeJS.ProcessEnv) => {
    const log = createWriteStream(path.join(logs, `${name}.log`));
    const child = spawn(command, args, { cwd: root, env, stdio: ["ignore", "pipe", "pipe"] });
    child.stdout!.pipe(log, { end: false });
    child.stderr!.pipe(log, { end: false });
    child.once("close", () => log.end());
    return child;
  };
  const fixture = launch(
    "cargo",
    [
      "test",
      "-p",
      "unrelated-mcp-gateway",
      "--test",
      "integration_ui_fixture",
      "--",
      "--ignored",
      "--nocapture",
    ],
    "fixture",
    { ...process.env, MCP_UI_FIXTURE_STATE: state },
  );
  const servers: ChildProcess[] = [];
  const cleanup = async () => {
    await Promise.all(servers.map(stop));
    await writeFile(path.join(directory, "fixture.done"), "done");
    // Let the Rust fixture drop its services and PostgreSQL container normally.
    const deadline = Date.now() + 15_000;
    while (fixture.exitCode === null && fixture.signalCode === null && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    await stop(fixture);
    await rm(directory, { recursive: true, force: true });
  };
  try {
    await until(
      async () => {
        try {
          JSON.parse(await readFile(state, "utf8"));
          return true;
        } catch {
          return false;
        }
      },
      fixture,
      "Gateway fixture",
    );
    const stack = JSON.parse(await readFile(state, "utf8")) as Stack;
    const standalone = path.join(directory, "standalone");
    await cp(path.join(ui, ".next/standalone"), standalone, { recursive: true });
    await cp(path.join(ui, ".next/static"), path.join(standalone, ".next/static"), {
      recursive: true,
    });
    await cp(path.join(ui, "public"), path.join(standalone, "public"), { recursive: true });
    const startUi = async (name: string, config: Record<string, string | undefined>) => {
      const listen = await port();
      const base = `http://127.0.0.1:${listen}`;
      const child = launch(process.execPath, [path.join(standalone, "server.js")], name, {
        ...process.env,
        GATEWAY_DATA_BASE: undefined,
        NEXT_PUBLIC_GATEWAY_DATA_BASE: undefined,
        ...config,
        GATEWAY_ADMIN_BASE: stack.adminBase,
        PORT: String(listen),
        HOSTNAME: "127.0.0.1",
        NODE_ENV: "production",
      });
      servers.push(child);
      await until(
        async () => {
          try {
            return (await fetch(`${base}/api/bootstrap/status`)).ok;
          } catch {
            return false;
          }
        },
        child,
        name,
        30_000,
      );
      return base;
    };
    stack.uiBase = await startUi("ui", {
      GATEWAY_DATA_BASE: stack.dataBase,
      NEXT_PUBLIC_GATEWAY_DATA_BASE: "https://ignored.example.test",
    });
    stack.alternateDataBase = "https://alternate.example.test/gateway";
    stack.alternateUiBase = await startUi("ui-alternate", {
      NEXT_PUBLIC_GATEWAY_DATA_BASE: `${stack.alternateDataBase}/`,
    });
    stack.directory = directory;
    const handoff = path.join(directory, "browser.json");
    await writeFile(handoff, JSON.stringify(stack));
    process.env.MCP_UI_E2E_STATE = handoff;
    return cleanup;
  } catch (error) {
    await cleanup();
    throw error;
  }
}
