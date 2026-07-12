# `servers.<name>: { type: openapi }` (OpenAPI → MCP)

This backend turns an OpenAPI spec into MCP tools and forwards tool calls as HTTP requests.

Source of truth:

- [`crates/openapi-tools/src/config.rs`](../../../crates/openapi-tools/src/config.rs) (`ApiServerConfig`, `AutoDiscoverConfig`, `EndpointConfig`, `OpenApiOverridesConfig`)
- [`crates/openapi-tools/src/runtime.rs`](../../../crates/openapi-tools/src/runtime.rs) (discovery + execution)
- [`crates/adapter/src/openapi.rs`](../../../crates/adapter/src/openapi.rs) (Adapter `Backend` integration)

## Output schemas + structured results

- When possible, the adapter derives **`Tool.output_schema`** from **2xx JSON responses** in the OpenAPI spec (best-effort).
- When an output schema is available, tool calls also include **`structured_content`** shaped as:
  - `{ "body": <response> }`
- If the spec does not provide a JSON response schema for an operation, the output schema may be omitted (and `structured_content` will not be emitted).
  - You can still force structured outputs by providing an explicit schema:
    - via `responseOverrides[].outputSchema` (spec-derived tools), or
    - via `overrides.tools.*.request.response.outputSchema` (manual override tools).

## Binary + image responses

- If the upstream returns `Content-Type: image/*`, the tool returns MCP **image content** (`type: "image"`, base64 `data`, and `mimeType`).
- If the upstream returns a non-UTF8 body (and it is not an image), the response is represented safely as a base64-wrapped JSON value (instead of failing with a UTF-8 decode error).

## Minimal example

```yaml
servers:
  petstore:
    type: openapi
    spec: https://petstore3.swagger.io/api/v3/openapi.json
    baseUrl: https://petstore3.swagger.io/api/v3
    autoDiscover: true
```

## Server fields

### `spec`

- **Type**: string
- **Required**: yes
- **Meaning**: OpenAPI spec location (URL or file path).

### `specHash`

- **Type**: string (e.g. `sha256:<hex>`)
- **Default**: none
- **Meaning**: expected hash for the raw spec content.

### `specHashPolicy`

- **Type**: `warn` | `fail` | `ignore`
- **Default**: `warn`
- **Meaning**: what to do when `specHash` is set and the computed hash differs.

### `baseUrl`

- **Type**: string
- **Default**: none
- **Meaning**: override the base URL used for outgoing calls (instead of the spec’s server URL).

### `auth`

- **Type**: object (see [`AUTH.md`](AUTH.md))
- **Default**: none

### `autoDiscover`

- **Type**: boolean OR object
- **Default**: `true`

Forms:

```yaml
autoDiscover: true   # discover all operations
autoDiscover: false  # only expose explicitly mapped endpoints (endpoints:)
```

Or detailed filters:

```yaml
autoDiscover:
  include:
    - "GET /pet/{petId}"
    - "POST /pet"
  exclude:
    - "POST /pet"
```

Notes:

- Matching is done against strings like `"GET /pet/{petId}"`.
- **Exclude wins** over include.

### `endpoints` (explicit mapping)

- **Type**: map
- **Default**: `{}`

Shape:

```yaml
endpoints:
  /pet/{petId}:
    get:
      tool: get_pet
      description: Custom description
      params:
        petId:
          rename: id
          description: Pet id
          required: true
```

Meaning:

- Keys are **paths** from the spec.
- Method keys are lowercase (`get`, `post`, `put`, `delete`, `patch`).
- Lets you rename tools and tweak parameter names/required/default/description.

### `defaults`

Same as the HTTP backend: timeout, arrayStyle, headers.

See: [`SERVERS_HTTP.md`](SERVERS_HTTP.md) (`defaults` section).

### `responseTransforms`

- **Type**: array of response transforms (optional)
- **Default**: `[]`
- **Meaning**: a global response shaping pipeline applied to all tools derived from this spec (including manual overrides unless they explicitly replace it).

### `responseOverrides`

- **Type**: array (optional)
- **Default**: `[]`
- **Meaning**: per-operation overrides for:
  - response shaping (`transforms`)
  - output schema (`outputSchema`)

Shape:

```yaml
responseOverrides:
  - match:
      operationId: getPetById
    transforms:
      mode: append
      pipeline:
        - type: pickPointers
          pointers: ["/id", "/name"]
    outputSchema:
      type: object
      properties:
        id: { type: integer }
        name: { type: string }
```

### `overrides` (manual tool overrides)

Overrides let you replace a spec-derived tool with a manual definition (HTTP tool DSL).

Shape:

```yaml
overrides:
  tools:
    add_pet_override:
      match:
        operationId: addPet
      request:
        method: POST
        path: /pet
        params:
          body:
            in: body
            required: true
            schema: { type: object }
```

Notes:

- The override `request` supports the same HTTP DSL response settings as `type: http`.
  - For example, you can set `request.response.outputSchema` to enable structured outputs (see [`SERVERS_HTTP.md`](SERVERS_HTTP.md)).

Matching:

- `match.operationId`, or
- `match.method` + `match.path`, or
- any combination of those (must not be empty).

Behavior:

- Overrides take precedence: matching generated tool(s) are removed and replaced.
- Override tool names must not collide with existing tool names.

## Tool annotations

OpenAPI-derived tools automatically set MCP `Tool.annotations` based on the HTTP method:

- `GET/HEAD/OPTIONS` → read-only + idempotent
- `DELETE` → destructive + idempotent
- `POST/PUT/PATCH` → write semantics (best-effort)

All OpenAPI tools set `openWorldHint: true`.
