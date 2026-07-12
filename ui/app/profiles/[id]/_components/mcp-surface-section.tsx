"use client";

import type { ProfileSurface } from "@/src/lib/tenantApi";
import type { Profile } from "@/src/lib/types";
import { Button, Callout, SectionCard } from "@/components/ui";
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

      <SectionCard
        title="MCP surface"
        subtitle="Resources, prompts, and interactive flows proxied by the Gateway."
        right={
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={onProbe}
            loading={probePending}
          >
            Probe surface
          </Button>
        }
        bodyClassName="space-y-6"
      >
        {surfaceError ? (
          <Callout tone="danger" size="md">
            {surfaceError}
          </Callout>
        ) : null}

        {!surface ? (
          <p className="text-sm text-muted">Run a probe to list resources and prompts.</p>
        ) : (
          <>
            <div className="grid gap-6 lg:grid-cols-2">
              <div>
                <div className="mb-3 flex items-center justify-between">
                  <div className="eyebrow">Resources</div>
                  <div className="font-mono text-xs text-faint">{surface.resources.length}</div>
                </div>
                {surface.resources.length === 0 ? (
                  <div className="text-sm text-faint">No resources discovered.</div>
                ) : (
                  <div className="space-y-2">
                    {surface.resources.slice(0, 50).map((r) => (
                      <div key={r.uri} className="rounded-md border border-edge bg-well px-3 py-2">
                        <div className="break-all font-mono text-xs text-fg">{r.uri}</div>
                        {r.name ? <div className="mt-1 text-xs text-faint">{r.name}</div> : null}
                      </div>
                    ))}
                    {surface.resources.length > 50 ? (
                      <div className="text-xs text-faint">Showing first 50.</div>
                    ) : null}
                  </div>
                )}
              </div>

              <div>
                <div className="mb-3 flex items-center justify-between">
                  <div className="eyebrow">Prompts</div>
                  <div className="font-mono text-xs text-faint">{surface.prompts.length}</div>
                </div>
                {surface.prompts.length === 0 ? (
                  <div className="text-sm text-faint">No prompts discovered.</div>
                ) : (
                  <div className="space-y-2">
                    {surface.prompts.slice(0, 50).map((p) => (
                      <div key={p.name} className="rounded-md border border-edge bg-well px-3 py-2">
                        <div className="break-all font-mono text-xs text-fg">{p.name}</div>
                        {p.description ? (
                          <div className="mt-1 text-xs text-faint">{p.description}</div>
                        ) : null}
                      </div>
                    ))}
                    {surface.prompts.length > 50 ? (
                      <div className="text-xs text-faint">Showing first 50.</div>
                    ) : null}
                  </div>
                )}
              </div>
            </div>

            <div className="border-t border-edge pt-5">
              <div className="eyebrow mb-2">Interactive flows</div>
              <div className="text-sm text-muted">
                The Gateway can proxy upstream server → client requests by namespacing (and
                optionally signing) JSON-RPC IDs so replies are routed back correctly. Whether these
                requests are forwarded is controlled by the profile’s Security policy (per-upstream)
                and what client capabilities the Gateway advertises upstream during `initialize`.
              </div>
              <ul className="mt-3 space-y-1 font-mono text-sm text-fg">
                <li>sampling/createMessage</li>
                <li>roots/list</li>
                <li>elicitation/create</li>
              </ul>
              <div className="mt-3 text-xs text-faint">
                Note: these are proxied from upstreams; the Gateway does not originate them. Tool
                transforms are currently tool-only; resource/prompt transforms and Tasks are planned
                for later.
              </div>
            </div>
          </>
        )}
      </SectionCard>
    </div>
  );
}
