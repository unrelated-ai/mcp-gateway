# `servers.<name>: { type: http }` (manual HTTP tools)

This backend lets you define tools with a small HTTP DSL (no OpenAPI needed).

Source of truth:

- [`crates/http-tools/src/config.rs`](../../../crates/http-tools/src/config.rs) (`HttpServerConfig`, `HttpToolConfig`, `HttpParamConfig`, `HttpResponseConfig`)
- [`crates/http-tools/src/runtime.rs`](../../../crates/http-tools/src/runtime.rs) (execution + query serialization)
- [`crates/adapter/src/http_backend.rs`](../../../crates/adapter/src/http_backend.rs) (Adapter `Backend` integration)

## Example

```yaml
servers:
  billing_api:
    type: http
    baseUrl: http://billing-api:8080
    auth:
      type: bearer
      token: ${BILLING_TOKEN}
    defaults:
      timeout: 15
      headers:
        X-Caller: unrelated-mcp-adapter
    tools:
      create_invoice:
        method: POST
        path: /v1/invoices/{customerId}
        description: Create an invoice.
        params:
          customerId:
            in: path
            required: true
            schema: { type: string }
          q:
            in: query
            schema: { type: string }
          body:
            in: body
            required: true
            schema: { type: object }
        response:
          mode: json
          # Optional: enable structured outputs + advertise an output schema.
          # This schema describes the HTTP response body.
          outputSchema:
            type: object
```

## Server fields

### `baseUrl`

- **Type**: string
- **Required**: yes
- **Meaning**: base URL prepended to each tool `path`.

### `auth`

- **Type**: object (see [`AUTH.md`](AUTH.md))
- **Default**: none

### `defaults`

- **Type**: object (`EndpointDefaults`)
- **Fields**:
  - `timeout`: integer seconds (optional; `0` disables timeout for that backend)
  - `arrayStyle`: `form` | `spaceDelimited` | `pipeDelimited` | `deepObject` (default: `form`)
  - `headers`: map of string → string

### `responseTransforms`

- **Type**: array of response transforms (optional)
- **Default**: `[]`
- **Meaning**: a **global response shaping pipeline** applied to all tools in this source.

This is useful for:

- redacting secrets
- dropping noisy/null fields
- reducing token count

Example:

```yaml
responseTransforms:
  - type: dropNulls
  - type: redactKeys
    keys: ["token", "secret"]
```

### `tools`

- **Type**: map of `toolName` → tool config
- **Required**: yes (can be empty, but then the backend exposes no tools)

## Tool fields (`tools.<toolName>`)

### `method`

- **Type**: string (e.g. `GET`, `POST`)
- **Notes**:
  - The value is parsed as an HTTP method token (so **extension/custom methods** like `NOPE` can still be accepted).
  - If you provide a method value that is not a valid HTTP token (e.g. contains whitespace), startup fails during tool generation.
  - Upstreams may reject unknown methods (e.g. `405 Method Not Allowed`).

### `path`

- **Type**: string (e.g. `/v1/users/{id}`)
- **Notes**: `{param}` placeholders are substituted from `in: path` params.

### `description`

- **Type**: string (optional)

### `params`

- **Type**: map of `argName` → param config

Param config (`params.<argName>`):

- `in`: `path` | `query` | `header` | `body`
- `name`: override actual HTTP name/property (defaults to the map key)
- `required`: boolean (optional)
- `default`: JSON value (optional)
- `schema`: JSON Schema fragment (optional)
- Query serialization (when `in: query`):
  - `style`: `form` | `spaceDelimited` | `pipeDelimited` | `deepObject`
  - `explode`: boolean
  - `allowReserved`: boolean
  - `allowEmptyValue`: boolean

### `response.mode`

- **Type**: `json` | `text`
- **Default**: `json`

### Binary + image responses

- If the upstream returns `Content-Type: image/*`, the tool returns MCP **image content** (`type: "image"`, base64 `data`, and `mimeType`).
- If the upstream returns a non-UTF8 body (and it is not an image), the response is represented safely as a base64-wrapped JSON value (instead of failing with a UTF-8 decode error).

### `response.outputSchema`

- **Type**: JSON Schema object (optional)
- **Default**: none
- **Meaning**: when set, the tool will:
  - advertise `Tool.output_schema` (wrapped as `{ "type": "object", "required": ["body"], "properties": { "body": <outputSchema> } }` to satisfy MCP’s “root must be an object” requirement)
  - return `CallToolResult.structured_content` as `{ "body": <response> }` (and also return `Content::text(...)` for interoperability)

### `response.transforms`

- **Type**: response transform chain (optional)
- **Default**: none
- **Meaning**: tool-level response shaping, overriding the server-level `responseTransforms`.

Supported forms:

```yaml
response:
  transforms:
    - type: dropNulls
```

Or:

```yaml
response:
  transforms:
    mode: append # append | replace (default: replace)
    pipeline:
      - type: pickPointers
        pointers: ["/id", "/status"]
```

Supported transforms (v1):

- `dropNulls`
- `pickPointers` (top-level only; pointers like `"/id"`)
- `redactKeys`
- `truncateStrings`
- `limitArrays`

## Tool annotations

HTTP tools automatically set MCP `Tool.annotations` based on HTTP method semantics:

- `GET/HEAD/OPTIONS` → read-only + idempotent
- `DELETE` → destructive + idempotent
- `POST/PUT/PATCH` → write semantics (best-effort)

All HTTP tools set `openWorldHint: true`.

## Notes

- Query auth (`auth.type: query`) is applied while building the final URL.
- Default headers and per-tool-call headers are merged (defaults first).
