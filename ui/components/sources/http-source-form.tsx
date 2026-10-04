"use client";

import { Button, Input, SectionCard, Select, Textarea, Toggle } from "@/components/ui";
import { SourceAuthFields } from "./source-auth-fields";
import {
  ARRAY_STYLES,
  HTTP_METHODS,
  PARAM_LOCATIONS,
  SCHEMA_TYPES,
  changeSchemaType,
  newHttpParam,
  newHttpTool,
  type HttpParamDraft,
  type HttpSourceDraft,
  type HttpToolDraft,
} from "@/src/lib/http-source";

export function HttpSourceForm({
  draft,
  onChange,
  disabled,
}: {
  draft: HttpSourceDraft;
  onChange: (draft: HttpSourceDraft) => void;
  disabled: boolean;
}) {
  const patch = (change: Partial<HttpSourceDraft>) => onChange({ ...draft, ...change });
  return (
    <fieldset disabled={disabled} className="min-w-0 space-y-6">
      <SectionCard
        title="Connection"
        subtitle="The API shared by every tool in this source."
        bodyClassName="space-y-4"
      >
        <Toggle
          label="Source enabled"
          checked={draft.enabled}
          onChange={(enabled) => patch({ enabled })}
          description="Disabled sources stay configured but do not expose tools."
        />
        <Input
          label="Base URL"
          value={draft.baseUrl}
          onChange={(event) => patch({ baseUrl: event.target.value })}
          placeholder="https://api.example.com/v1"
          hint="Tool paths are appended to this URL."
        />
        <SourceAuthFields
          auth={draft.auth}
          onChange={(auth) => patch({ auth })}
          disabled={disabled}
        />
        <div className="grid gap-4 sm:grid-cols-2">
          <Input
            label="Timeout (seconds)"
            inputMode="numeric"
            value={draft.timeout}
            onChange={(event) => patch({ timeout: event.target.value })}
            hint="Blank uses the Gateway default. Zero disables the timeout."
          />
          <Select
            label="Default array style"
            value={draft.arrayStyle}
            onChange={(event) => patch({ arrayStyle: event.target.value })}
          >
            <option value="">Default</option>
            {ARRAY_STYLES.map((style) => (
              <option key={style} value={style}>
                {style}
              </option>
            ))}
          </Select>
        </div>
        <div className="space-y-3">
          <div className="flex items-center justify-between gap-3">
            <p className="text-sm font-medium text-fg">Default headers</p>
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={() =>
                patch({
                  headers: [...draft.headers, { id: crypto.randomUUID(), key: "", value: "" }],
                })
              }
            >
              Add header
            </Button>
          </div>
          {draft.headers.map((row, index) => (
            <div key={row.id} className="grid gap-3 sm:grid-cols-[1fr_1fr_auto]">
              <Input
                aria-label={`Header ${index + 1} name`}
                placeholder="X-Client"
                value={row.key}
                onChange={(event) =>
                  patch({
                    headers: draft.headers.map((current) =>
                      current.id === row.id ? { ...current, key: event.target.value } : current,
                    ),
                  })
                }
              />
              <Input
                aria-label={`Header ${index + 1} value`}
                placeholder="Header value or secret reference"
                value={row.value}
                onChange={(event) =>
                  patch({
                    headers: draft.headers.map((current) =>
                      current.id === row.id ? { ...current, value: event.target.value } : current,
                    ),
                  })
                }
              />
              <Button
                type="button"
                variant="ghost"
                size="sm"
                aria-label={`Remove header ${index + 1}`}
                onClick={() =>
                  patch({ headers: draft.headers.filter((current) => current.id !== row.id) })
                }
              >
                Remove
              </Button>
            </div>
          ))}
        </div>
      </SectionCard>
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-base font-semibold text-fg">
            Tools <span className="font-mono text-muted">({draft.tools.length})</span>
          </h2>
          <Button
            type="button"
            variant="secondary"
            onClick={() => patch({ tools: [...draft.tools, newHttpTool()] })}
          >
            Add tool
          </Button>
        </div>
        {draft.tools.length === 0 && (
          <p className="text-sm text-muted">No tools yet. Add a tool to define an API request.</p>
        )}
        {draft.tools.map((tool, index) => (
          <fieldset
            key={tool.id}
            aria-label={`Tool ${index + 1}`}
            className="min-w-0 rounded-lg border border-edge bg-surface p-4 sm:p-5 space-y-4"
          >
            <div className="flex items-center justify-between gap-3">
              <h3 className="break-all font-mono text-sm font-medium text-accent">
                {tool.name || `Tool ${index + 1}`}
              </h3>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() =>
                  patch({ tools: draft.tools.filter((current) => current.id !== tool.id) })
                }
              >
                Remove tool
              </Button>
            </div>
            <ToolFields
              tool={tool}
              onChange={(next) =>
                patch({
                  tools: draft.tools.map((current) => (current.id === tool.id ? next : current)),
                })
              }
            />
          </fieldset>
        ))}
      </div>
      <p className="text-xs text-faint">
        Advanced JSON provides query serialization and response transforms. Editing these fields
        preserves the other saved settings.
      </p>
    </fieldset>
  );
}

function ToolFields({
  tool,
  onChange,
}: {
  tool: HttpToolDraft;
  onChange: (tool: HttpToolDraft) => void;
}) {
  const patch = (change: Partial<HttpToolDraft>) => onChange({ ...tool, ...change });
  return (
    <>
      <Input
        label="Tool name"
        value={tool.name}
        onChange={(event) => patch({ name: event.target.value })}
        placeholder="get_customer"
      />
      <Textarea
        label="Description"
        value={tool.description}
        onChange={(event) => patch({ description: event.target.value })}
        rows={2}
        placeholder="Describe what this tool does."
      />
      <div className="grid gap-4 sm:grid-cols-[9rem_1fr]">
        <Input
          label="HTTP method"
          list="http-source-methods"
          value={tool.method}
          onChange={(event) => patch({ method: event.target.value })}
          hint="Common or custom method."
        />
        <Input
          label="Request path"
          value={tool.path}
          onChange={(event) => patch({ path: event.target.value })}
          placeholder="/customers/{id}"
          hint="Use {name} for a path parameter."
        />
      </div>
      <div className="space-y-3">
        <div className="flex items-center justify-between gap-3">
          <h4 className="text-sm font-medium text-fg">Parameters</h4>
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={() => patch({ params: [...tool.params, newHttpParam()] })}
          >
            Add parameter
          </Button>
        </div>
        {tool.params.map((param, index) => (
          <fieldset
            key={param.id}
            aria-label={`Parameter ${index + 1}`}
            className="min-w-0 rounded-md border border-edge bg-well p-4 space-y-3"
          >
            <ParamFields
              param={param}
              onChange={(next) =>
                patch({
                  params: tool.params.map((current) => (current.id === param.id ? next : current)),
                })
              }
            />
            <div className="flex justify-end">
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() =>
                  patch({ params: tool.params.filter((current) => current.id !== param.id) })
                }
              >
                Remove parameter
              </Button>
            </div>
          </fieldset>
        ))}
      </div>
      <div className="border-t border-edge pt-4 space-y-4">
        <Select
          label="Response format"
          value={tool.responseMode}
          onChange={(event) =>
            patch({ responseMode: event.target.value as HttpToolDraft["responseMode"] })
          }
        >
          <option value="json">JSON</option>
          <option value="text">Text</option>
        </Select>
        <details className="text-sm">
          <summary className="cursor-pointer text-muted">Output schema</summary>
          <div className="pt-3">
            <Textarea
              label="Output schema JSON"
              value={tool.outputSchema}
              onChange={(event) => patch({ outputSchema: event.target.value })}
              rows={5}
              hint="Optional JSON Schema object describing the response body. Blank removes the output schema."
              placeholder={'{"type":"object"}'}
            />
          </div>
        </details>
      </div>
    </>
  );
}

function ParamFields({
  param,
  onChange,
}: {
  param: HttpParamDraft;
  onChange: (param: HttpParamDraft) => void;
}) {
  const patch = (change: Partial<HttpParamDraft>) => onChange({ ...param, ...change });
  return (
    <>
      <div className="grid gap-3 sm:grid-cols-2">
        <Input
          label="Argument name"
          value={param.name}
          onChange={(event) => patch({ name: event.target.value })}
          hint="Name exposed to MCP clients."
        />
        <Select
          label="Send in"
          value={param.location}
          onChange={(event) => {
            const location = event.target.value as HttpParamDraft["location"];
            patch({ location, required: location === "path" ? true : param.required });
          }}
        >
          {PARAM_LOCATIONS.map((location) => (
            <option key={location} value={location}>
              {location === "body" ? "JSON body" : location[0].toUpperCase() + location.slice(1)}
            </option>
          ))}
        </Select>
        <Input
          label="HTTP name (optional)"
          value={param.httpName}
          onChange={(event) => patch({ httpName: event.target.value })}
          hint="Blank uses the argument name."
        />
        <SchemaField value={param.schema} onChange={(schema) => patch({ schema })} />
      </div>
      {param.location === "body" && (
        <p className="text-xs text-muted">
          Arguments become fields in a JSON object. An argument named body, with no HTTP name
          override, sends the whole request body.
        </p>
      )}
      <Toggle
        label="Required argument"
        checked={param.required}
        onChange={(required) => patch({ required })}
      />
      <details className="text-sm">
        <summary className="cursor-pointer text-muted">Default value</summary>
        <div className="pt-3">
          <Textarea
            label="Default value JSON"
            value={param.defaultValue}
            onChange={(event) => patch({ defaultValue: event.target.value })}
            rows={2}
            hint={'Optional JSON value, such as 10, true, or "active". Blank removes the default.'}
          />
        </div>
      </details>
    </>
  );
}

function SchemaField({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  let selected = "default";
  let invalid = false;
  if (value.trim()) {
    try {
      const parsed = JSON.parse(value);
      invalid = !(
        typeof parsed === "boolean" ||
        (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed))
      );
      selected = parsed && SCHEMA_TYPES.includes(parsed.type) ? parsed.type : "custom";
    } catch {
      selected = "custom";
      invalid = true;
    }
  }
  return (
    <div className="space-y-3">
      <Select
        label="Argument type"
        value={selected}
        disabled={invalid}
        onChange={(event) => {
          if (event.target.value === "default") onChange("");
          else if (event.target.value !== "custom")
            onChange(changeSchemaType(value, event.target.value));
        }}
      >
        <option value="default">Default (string)</option>
        {SCHEMA_TYPES.map((type) => (
          <option key={type} value={type}>
            {type[0].toUpperCase() + type.slice(1)}
          </option>
        ))}
        <option value="custom" disabled>
          Custom schema
        </option>
      </Select>
      <details className="text-sm">
        <summary className="cursor-pointer text-muted">Argument schema</summary>
        <div className="pt-3">
          <Textarea
            label="Argument schema JSON"
            value={value}
            onChange={(event) => onChange(event.target.value)}
            rows={5}
            hint="Optional JSON Schema. Existing constraints are preserved when selecting a type."
          />
        </div>
      </details>
    </div>
  );
}

export function HttpMethodOptions() {
  return (
    <datalist id="http-source-methods">
      {HTTP_METHODS.map((method) => (
        <option key={method} value={method} />
      ))}
    </datalist>
  );
}
