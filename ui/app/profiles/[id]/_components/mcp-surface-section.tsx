"use client";

import type { ProfileSurface } from "@/src/lib/tenantApi";
import type { Profile } from "@/src/lib/types";
import { Button } from "@/components/ui";
import { McpSettingsCard } from "./mcp-settings-card";

export function McpSurfaceSection({
  profile,
  surface,
  surfaceError,
  probePending,
  onProbe,
}: {
  profile: Profile | null;
  surface: ProfileSurface | null;
  surfaceError: string | null;
  probePending: boolean;
  onProbe: () => void;
}) {
  return (
    <div className="space-y-6">
      <McpSettingsCard key={profile ? profile.id : "loading"} profile={profile} />

      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-lg font-semibold text-zinc-100">MCP Surface</div>
          <div className="text-sm text-zinc-500">
            Resources, prompts, and interactive flows proxied by the Gateway.
          </div>
        </div>
        <Button type="button" variant="secondary" onClick={onProbe} disabled={probePending}>
          {probePending ? "Probing…" : "Probe surface"}
        </Button>
      </div>

      {surfaceError ? (
        <div className="rounded-xl border border-red-500/20 bg-red-950/20 p-4 text-sm text-red-200">
          {surfaceError}
        </div>
      ) : null}

      {!surface ? (
        <div className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 p-5 text-sm text-zinc-400">
          Run a probe to list resources and prompts.
        </div>
      ) : (
        <div className="space-y-4">
          <div className="grid gap-6 lg:grid-cols-2">
            <div className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 p-5">
              <div className="flex items-center justify-between mb-3">
                <div className="text-sm font-semibold text-zinc-100">Resources</div>
                <div className="text-xs text-zinc-500">{surface.resources.length}</div>
              </div>
              {surface.resources.length === 0 ? (
                <div className="text-sm text-zinc-500">No resources discovered.</div>
              ) : (
                <div className="space-y-2">
                  {surface.resources.slice(0, 50).map((r) => (
                    <div
                      key={r.uri}
                      className="rounded-lg border border-zinc-800/60 bg-zinc-950/40 px-3 py-2"
                    >
                      <div className="font-mono text-xs text-zinc-200 break-all">{r.uri}</div>
                      {r.name ? <div className="text-xs text-zinc-500 mt-1">{r.name}</div> : null}
                    </div>
                  ))}
                  {surface.resources.length > 50 ? (
                    <div className="text-xs text-zinc-500">Showing first 50.</div>
                  ) : null}
                </div>
              )}
            </div>

            <div className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 p-5">
              <div className="flex items-center justify-between mb-3">
                <div className="text-sm font-semibold text-zinc-100">Prompts</div>
                <div className="text-xs text-zinc-500">{surface.prompts.length}</div>
              </div>
              {surface.prompts.length === 0 ? (
                <div className="text-sm text-zinc-500">No prompts discovered.</div>
              ) : (
                <div className="space-y-2">
                  {surface.prompts.slice(0, 50).map((p) => (
                    <div
                      key={p.name}
                      className="rounded-lg border border-zinc-800/60 bg-zinc-950/40 px-3 py-2"
                    >
                      <div className="font-mono text-xs text-zinc-200 break-all">{p.name}</div>
                      {p.description ? (
                        <div className="text-xs text-zinc-500 mt-1">{p.description}</div>
                      ) : null}
                    </div>
                  ))}
                  {surface.prompts.length > 50 ? (
                    <div className="text-xs text-zinc-500">Showing first 50.</div>
                  ) : null}
                </div>
              )}
            </div>
          </div>

          <div className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 p-5">
            <div className="text-sm font-semibold text-zinc-100 mb-2">Interactive flows</div>
            <div className="text-sm text-zinc-500">
              The Gateway can proxy upstream server → client requests by namespacing (and optionally
              signing) JSON-RPC IDs so replies are routed back correctly. Whether these requests are
              forwarded is controlled by the profile’s Security policy (per-upstream) and what
              client capabilities the Gateway advertises upstream during `initialize`.
            </div>
            <ul className="mt-3 space-y-1 text-sm text-zinc-300 font-mono">
              <li>sampling/createMessage</li>
              <li>roots/list</li>
              <li>elicitation/create</li>
            </ul>
            <div className="mt-3 text-xs text-zinc-500">
              Note: these are proxied from upstreams; the Gateway does not originate them. Tool
              transforms are currently tool-only; resource/prompt transforms and Tasks are planned
              for later.
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
