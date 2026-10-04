import { z } from "zod";
import type { AuthConfig } from "./tenantApi";

export const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] as const;
export const PARAM_LOCATIONS = ["path", "query", "header", "body"] as const;
export const SCHEMA_TYPES = ["string", "integer", "number", "boolean", "object", "array"] as const;
export const ARRAY_STYLES = ["form", "spaceDelimited", "pipeDelimited", "deepObject"] as const;
const record = z.record(z.string(), z.unknown());
const schema = z.union([record, z.boolean()]);
const authSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("none") }).passthrough(),
  z.object({ type: z.literal("bearer"), token: z.string() }).passthrough(),
  z.object({ type: z.literal("basic"), username: z.string(), password: z.string() }).passthrough(),
  z.object({ type: z.literal("header"), name: z.string(), value: z.string() }).passthrough(),
  z.object({ type: z.literal("query"), name: z.string(), value: z.string() }).passthrough(),
]);
const paramSchema = z
  .object({
    in: z.enum(PARAM_LOCATIONS),
    name: z.string().nullish(),
    required: z.boolean().nullish(),
    default: z.unknown().optional(),
    schema: schema.nullish(),
  })
  .passthrough();
const toolSchema = z
  .object({
    method: z.string(),
    path: z.string(),
    description: z.string().nullish(),
    params: z.record(z.string(), paramSchema).default({}),
    response: z
      .object({ mode: z.enum(["json", "text"]).default("json"), outputSchema: record.nullish() })
      .passthrough()
      .default({ mode: "json" }),
  })
  .passthrough();
const configSchema = z
  .object({
    baseUrl: z.string(),
    enabled: z.boolean().default(true),
    auth: authSchema.nullish(),
    defaults: z
      .object({
        timeout: z.number().int().nonnegative().nullish(),
        arrayStyle: z.enum(ARRAY_STYLES).nullish(),
        headers: z.record(z.string(), z.string()).default({}),
      })
      .passthrough()
      .default({ headers: {} }),
    tools: z.record(z.string(), toolSchema).default({}),
  })
  .passthrough();

type RawParam = z.infer<typeof paramSchema>;
type RawTool = z.infer<typeof toolSchema>;
type RawConfig = z.infer<typeof configSchema>;
export type PairDraft = { id: string; key: string; value: string };
export type HttpParamDraft = {
  id: string;
  original: RawParam;
  name: string;
  location: RawParam["in"];
  httpName: string;
  required: boolean;
  schema: string;
  defaultValue: string;
};
export type HttpToolDraft = {
  id: string;
  original: RawTool;
  name: string;
  method: string;
  path: string;
  description: string;
  params: HttpParamDraft[];
  responseMode: "json" | "text";
  outputSchema: string;
};
export type HttpSourceDraft = {
  original: RawConfig;
  enabled: boolean;
  baseUrl: string;
  auth: AuthConfig;
  timeout: string;
  arrayStyle: string;
  headers: PairDraft[];
  tools: HttpToolDraft[];
};
const jsonText = (value: unknown) => (value == null ? "" : JSON.stringify(value, null, 2));

export function readHttpSourceDraft(value: unknown): HttpSourceDraft {
  const parsed = configSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new Error(`${issue.path.join(".") || "Source"}: ${issue.message}`);
  }
  const config = parsed.data;
  return {
    original: structuredClone(config),
    enabled: config.enabled,
    baseUrl: config.baseUrl,
    auth: config.auth ?? { type: "none" },
    timeout: config.defaults.timeout?.toString() ?? "",
    arrayStyle: config.defaults.arrayStyle ?? "",
    headers: Object.entries(config.defaults.headers).map(([key, value], index) => ({
      id: `header-${index}`,
      key,
      value,
    })),
    tools: Object.entries(config.tools).map(([name, tool], index) => ({
      id: `tool-${index}`,
      original: structuredClone(tool),
      name,
      method: tool.method,
      path: tool.path,
      description: tool.description ?? "",
      responseMode: tool.response.mode,
      outputSchema: jsonText(tool.response.outputSchema),
      params: Object.entries(tool.params).map(([name, param], index) => ({
        id: `param-${index}`,
        original: structuredClone(param),
        name,
        location: param.in,
        httpName: param.name ?? "",
        required: param.required ?? param.in === "path",
        schema: jsonText(param.schema),
        defaultValue: jsonText(param.default),
      })),
    })),
  };
}

export function newHttpTool(): HttpToolDraft {
  const tool = readHttpSourceDraft({ baseUrl: "", tools: { "": { method: "GET", path: "/" } } })
    .tools[0];
  return { ...tool, id: crypto.randomUUID() };
}
export function newHttpParam(): HttpParamDraft {
  return {
    id: crypto.randomUUID(),
    original: { in: "query" },
    name: "",
    location: "query",
    httpName: "",
    required: false,
    schema: '{"type":"string"}',
    defaultValue: "",
  };
}

function optionalJson(text: string, label: string, kind: "schema" | "object" | "value"): unknown {
  if (!text.trim()) return undefined;
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error(`${label}: enter valid JSON.`);
  }
  const object = value !== null && typeof value === "object" && !Array.isArray(value);
  if (kind !== "value" && !object && !(kind === "schema" && typeof value === "boolean")) {
    throw new Error(
      `${label}: enter a JSON ${kind === "schema" ? "schema object or boolean" : "object"}.`,
    );
  }
  return value;
}

function uniqueName(raw: string, used: Set<string>, label: string): string {
  const name = raw.trim();
  if (!name) throw new Error(`${label}: a name is required.`);
  if (used.has(name)) throw new Error(`${label}: duplicate name "${name}".`);
  used.add(name);
  return name;
}
const HTTP_TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
function headerName(name: string, label: string) {
  if (!HTTP_TOKEN.test(name)) throw new Error(`${label}: enter a valid HTTP header name.`);
}

export function buildHttpSourceConfig(draft: HttpSourceDraft): Record<string, unknown> {
  const baseUrl = draft.baseUrl.trim();
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new Error("Base URL: enter a valid HTTP or HTTPS URL.");
  }
  if (
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.hash ||
    url.search
  ) {
    throw new Error(
      "Base URL: use HTTP or HTTPS without credentials, query parameters, or a fragment.",
    );
  }
  const timeout = draft.timeout.trim() === "" ? undefined : Number(draft.timeout);
  if (
    timeout !== undefined &&
    (!/^\d+$/.test(draft.timeout.trim()) || !Number.isSafeInteger(timeout) || timeout < 0)
  ) {
    throw new Error(
      "Timeout: enter a whole number of seconds, or leave blank for the default. Zero disables the timeout.",
    );
  }
  const auth = draft.auth;
  if (
    (auth.type === "bearer" && !auth.token.trim()) ||
    (auth.type === "basic" && !auth.username.trim()) ||
    ((auth.type === "header" || auth.type === "query") && (!auth.name.trim() || !auth.value.trim()))
  ) {
    throw new Error("Authentication: complete the selected authentication fields.");
  }
  if (auth.type === "header") headerName(auth.name, "Authentication");
  if (
    (auth.type === "bearer" && /[\r\n]/.test(auth.token)) ||
    (auth.type === "header" && /[\r\n]/.test(auth.value))
  )
    throw new Error("Authentication headers cannot contain line breaks.");
  const seenHeaders = new Set<string>();
  const headers = Object.fromEntries(
    draft.headers.map((row) => {
      const key = row.key.trim();
      uniqueName(key.toLowerCase(), seenHeaders, "Default headers");
      headerName(key, "Default headers");
      if (/[\r\n]/.test(row.value)) throw new Error("Header values cannot contain line breaks.");
      return [key, row.value];
    }),
  );
  const toolNames = new Set<string>();
  const tools = Object.fromEntries(
    draft.tools.map((tool) => {
      const name = uniqueName(tool.name, toolNames, "Tools");
      const label = `Tool "${name}"`;
      const method = tool.method.trim();
      if (!HTTP_TOKEN.test(method)) throw new Error(`${label}: enter a valid HTTP method.`);
      const path = tool.path.trim();
      if (!path) throw new Error(`${label}: a request path is required.`);
      const paramNames = new Set<string>();
      const httpNames = new Set<string>();
      const params = Object.fromEntries(
        tool.params.map((param) => {
          const key = uniqueName(param.name, paramNames, `${label} parameters`);
          const httpName = param.httpName.trim() || key;
          const identity = `${param.location}:${param.location === "header" ? httpName.toLowerCase() : httpName}`;
          uniqueName(identity, httpNames, `${label} HTTP parameter names`);
          if (param.location === "header") headerName(httpName, `${label} parameter "${key}"`);
          return [
            key,
            {
              ...param.original,
              in: param.location,
              name: param.httpName.trim() || undefined,
              required: param.required,
              schema: optionalJson(param.schema, `${label} parameter "${key}" schema`, "schema"),
              default: optionalJson(
                param.defaultValue,
                `${label} parameter "${key}" default`,
                "value",
              ),
            },
          ];
        }),
      );
      const pathParams = tool.params
        .filter((param) => param.location === "path")
        .map((param) => param.httpName.trim() || param.name.trim());
      for (const [, placeholder] of path.matchAll(/\{([^{}]+)\}/g)) {
        if (!pathParams.includes(placeholder))
          throw new Error(`${label}: add a path parameter for "${placeholder}".`);
      }
      for (const param of pathParams) {
        if (!path.includes(`{${param}}`))
          throw new Error(
            `${label}: path parameter "${param}" needs a matching {${param}} placeholder.`,
          );
      }
      const bodyParams = tool.params.filter((param) => param.location === "body");
      if (
        bodyParams.length > 1 &&
        bodyParams.some(
          (param) =>
            param.name.trim() === "body" &&
            (!param.httpName.trim() || param.httpName.trim() === "body"),
        )
      ) {
        throw new Error(`${label}: use either the whole "body" argument or separate body fields.`);
      }
      return [
        name,
        {
          ...tool.original,
          method,
          path,
          description: tool.description || undefined,
          params,
          response: {
            ...tool.original.response,
            mode: tool.responseMode,
            outputSchema: optionalJson(tool.outputSchema, `${label} output schema`, "object"),
          },
        },
      ];
    }),
  );
  return {
    ...draft.original,
    type: "http",
    enabled: draft.enabled,
    baseUrl,
    auth: auth.type === "none" ? null : auth,
    defaults: {
      ...draft.original.defaults,
      timeout,
      arrayStyle: draft.arrayStyle || undefined,
      headers,
    },
    tools,
  };
}

export function changeSchemaType(text: string, type: string): string {
  const value = optionalJson(text, "Schema", "schema");
  const current = value && typeof value === "object" ? (value as Record<string, unknown>) : {};
  return JSON.stringify(
    { ...current, type, ...(type === "array" && !current.items ? { items: {} } : {}) },
    null,
    2,
  );
}
