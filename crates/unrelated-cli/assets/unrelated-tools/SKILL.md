---
name: unrelated-tools
description: Search, inspect, and call tools exposed through an Unrelated MCP Gateway profile using the unrelated CLI. Use when a task may be handled by an authorized Gateway tool, when the exact tool name or input schema is unknown, or when a compact client-side alternative to loading a full MCP catalog is desired.
---

# Use Unrelated Gateway tools

1. Search before calling:
   ```bash
   unrelated --json tools search "describe the intended outcome"
   ```
2. Use the returned stable `toolRef`. Run `unrelated --json tools describe <toolRef>` only when the search result lacks required schema detail.
3. Call exactly one tool with JSON input:
   ```bash
   unrelated --json tools call <toolRef> --input '{"key":"value"}'
   ```
4. Inspect the complete JSON result before deciding the next action.

Never print, request, or place credentials in command arguments. Authentication belongs to `unrelated auth login` or `UNRELATED_TOKEN` in managed non-interactive environments.

Before a tool can delete, publish, send, purchase, or otherwise cause an external side effect, follow the host agent's confirmation policy and ask the user when approval is required. Do not bypass confirmation with `--yes`.

Do not invent tool references or parameters. Search again when a reference is missing or stale.
