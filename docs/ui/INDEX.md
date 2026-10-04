# Web UI (beta)

The **Web UI** is a Next.js application used to manage Gateway tenants:

- profiles
- upstreams
- tool sources
- secrets
- API keys
- audit (events + tool-call analytics)
- managed MCP deployments (beta; requires a configured reconciler)
- profile MCP security controls
- tenant/profile transport limits

## Scope

- The Web UI is **tenant-scoped** (tenant self-service).
- **Gateway admin** provisioning and global configuration are intentionally out of scope for the UI today (use the Gateway admin CLI and deployment automation like `docker compose` / Helm).
- **Fresh install onboarding**: when the Gateway bootstrap endpoint is enabled and there are no tenants yet, the UI guides the user through creating the first tenant (via `/bootstrap/v1/tenant`) at `/onboarding`.

## Connection checks

**Profile → MCP endpoint URL → Check connections** tests each active MCP upstream
using its saved credentials and the profile's protocol mode. Results show the
negotiated MCP version or a connection failure. Checks run only on request and do
not call tools.

The check covers upstream connections, not client API keys or OAuth login.
HTTP/OpenAPI sources are marked **Not checked** because checking those credentials
would require making an API request.

## Audit

- Tenant defaults, the logging switch, and retention live under **Settings → Audit**.
- **Profile → Security → Profile audit** overrides the detail level for MCP activity and shows the inherited and effective settings. Configuration changes still follow tenant settings.
- Tenant audit events and analytics live under **Audit** (with profile filtering and deep-links from profile pages).
- **Load more** shows older events or additional analytics rows. **All retained events** covers the full retention window; **Refresh audit** includes newer activity.
- Outcome filtering applies to events. Analytics show both successful and failed tool calls.

See also:

- Gateway audit logging: [`docs/gateway/AUDIT.md`](../gateway/AUDIT.md)

## Security and transport controls

- **Profile → Security** includes MCP trust-policy controls (client capability shaping, proxied-request ID signing, and upstream server-to-client request filtering).
- **Settings → Transport limits** configures tenant defaults for MCP payload/transport safety.
- **Profile → Security → Transport limits** can override tenant defaults.
- **Profile → Security → Tool-call limits** configures per-key rate limits and initial quotas. Existing quota balances are not refilled by changing these settings.
- **Profile → MCP settings → Advanced MCP settings** configures notification filtering and legacy proxy identifiers.

## Sources and discovery

OpenAPI form saves preserve advanced configuration, including spec pins, endpoint mappings,
and response overrides. HTTP sources have a guided editor and an advanced JSON view.
Both source types support enabling or disabling a source and keep drafts through
background refreshes and failed saves. If another
editor changes the source, saving reports a conflict; **Reload source** discards the draft
and loads the saved configuration.

### HTTP sources

**Sources → Add source → HTTP** opens the guided editor. The same editor is available
for existing HTTP sources. Connection settings include the base URL, authentication,
timeout, array serialization, and default headers. Credentials can use tenant secret
references such as `${secret:API_TOKEN}`.

Each tool defines an HTTP method, path, description, parameters, and response format.
Path placeholders such as `{id}` must match a path parameter's HTTP name. Parameters can
be sent in the path, query string, headers, or JSON body. A body argument named `body`
with no HTTP name override sends the whole JSON body; other body arguments become individual object fields.
Argument schemas, defaults, and an optional response schema can be edited alongside
the form fields.

**Guided editor** and **Advanced JSON** share the same draft. Form saves preserve
response transforms, query serialization, and other settings that are not exposed in
individual controls. Incomplete JSON stays editable; switching back to the form requires
a supported configuration. Saving validates names, path bindings, headers, and JSON fields.
A name collision during creation preserves the existing source.

See [HTTP source configuration](../adapter/config/SERVERS_HTTP.md) for the full format.

### MCP discovery

Under **Profile → MCP settings → MCP surface**, run **Probe surface** to discover
resources, resource templates, and prompts. **Resource and prompt settings** controls
which entries are available in that profile:

- Resources and templates support display names, titles, and description overrides.
- Prompts support aliases, description overrides, argument aliases, and text defaults.
  A default makes an argument optional for clients; an explicitly supplied value takes precedence.
- **Client preview** shows the draft before saving. **Save catalog settings** applies it;
  **Discard changes** restores the loaded settings. Failed saves keep the draft for retry.

Overrides apply to one upstream entry. Disabling an entry hides it and blocks direct
access. Disabling a resource template blocks its URI family, including overlapping
templates and listed resources; template variables act as wildcards for this restriction.
Resource URIs and returned content keep their existing format.

Prompt aliases also apply to argument completion. Duplicate names from different
upstreams receive source prefixes. Conflicting aliases within one upstream are unavailable
until corrected. Disabled entries remain in the editor so they can be enabled again.

Edits in other profile panels preserve these settings. If another browser changes the
profile, saving reports a conflict. **Reload saved settings** discards the current draft
and loads the saved values.

Profile discovery uses the selected MCP protocol. Upstream discovery detects native or
legacy support. Results include tools, resources, resource templates, and prompts, with
search and pagination for long lists. Upstream failures and catalog safety limits appear
in the source status.

Task routing is available with native MCP and compatible clients/upstreams. Clients start,
inspect, and cancel tasks; the UI does not provide a task dashboard.

## Tenant access

**Validate token** checks the tenant token with the Gateway before offering access to the
dashboard. OAuth profile access also requires an operator-managed principal binding;
enabling OAuth alone does not authorize a login identity.

See also:

- Gateway MCP settings: [`docs/gateway/MCP_SETTINGS.md`](../gateway/MCP_SETTINGS.md)
- Gateway proxying/security behavior: [`docs/gateway/MCP_PROXYING.md`](../gateway/MCP_PROXYING.md)

## Docs

- Build, versioning, and releases: [`docs/CICD.md`](../CICD.md)

## Related docs

- Workspace docs index: [`docs/INDEX.md`](../INDEX.md)
- CI/CD: [`docs/CICD.md`](../CICD.md)
- Gateway docs: [`docs/gateway/INDEX.md`](../gateway/INDEX.md)
- Gateway admin CLI docs: [`docs/gateway-cli/INDEX.md`](../gateway-cli/INDEX.md)
