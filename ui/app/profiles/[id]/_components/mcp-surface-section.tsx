"use client";

import type { ProfileSurface } from "@/src/lib/tenantApi";
import type { Profile } from "@/src/lib/types";
import { Button, Callout, SectionCard } from "@/components/ui";
import { CatalogSection } from "@/components/sources/catalog-section";
import { CatalogTransformEditor } from "./catalog-transform-editor";
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

      <SectionCard title="Tasks">
        <p className="text-sm text-muted">
          {profile?.mcp?.modernProtocol
            ? "Native task routing is enabled for this profile."
            : "Enable native MCP above to use task routing."}{" "}
          Compatible clients can start long-running tool calls, follow their status, and cancel
          tasks. The client and upstream must support the Tasks extension; task execution stays with
          the upstream.
        </p>
      </SectionCard>
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
              <CatalogSection
                title="Resources"
                items={surface.resources.map((r) => ({ id: r.uri, description: r.name }))}
              />
              <CatalogSection
                title="Resource templates"
                items={(surface.resourceTemplates ?? []).map((r) => ({
                  id: r.uriTemplate,
                  description: r.description ?? r.name,
                }))}
              />
              <CatalogSection
                title="Prompts"
                items={surface.prompts.map((p) => ({ id: p.name, description: p.description }))}
              />
            </div>

            {profile && (
              <CatalogTransformEditor profile={profile} surface={surface} onSaved={onProbe} />
            )}

            <div className="border-t border-edge pt-5">
              <div className="eyebrow mb-2">Interactive flows</div>
              <div className="text-sm text-muted">
                Compatible clients can handle upstream requests for sampling, roots, and user input.
                Profile Security settings control which requests are allowed.
              </div>
              <ul className="mt-3 space-y-1 font-mono text-sm text-fg">
                <li>sampling/createMessage</li>
                <li>roots/list</li>
                <li>elicitation/create</li>
              </ul>
              <div className="mt-3 text-xs text-faint">
                These requests originate from upstreams. Profile Security settings control access.
              </div>
            </div>
          </>
        )}
      </SectionCard>
    </div>
  );
}
