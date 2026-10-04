"use client";

import { useMutation } from "@tanstack/react-query";
import { Badge, Button, Callout } from "@/components/ui";
import { checkProfileConnections } from "@/src/lib/tenantApi";

const statuses = {
  passed: { label: "Connected", tone: "ok" },
  failed: { label: "Failed", tone: "danger" },
  notChecked: { label: "Not checked", tone: "neutral" },
} as const;

export function ConnectionCheck({
  profileId,
  modernProtocol,
}: {
  profileId: string;
  modernProtocol: boolean;
}) {
  const check = useMutation({ mutationFn: () => checkProfileConnections(profileId) });
  return (
    <div className="border-t border-edge pt-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h3 className="eyebrow">Upstream connections</h3>
        <Button
          type="button"
          variant="secondary"
          size="sm"
          loading={check.isPending}
          onClick={() => check.mutate()}
        >
          Check connections
        </Button>
      </div>
      <p className="mt-2 text-xs text-faint">
        Checks active MCP endpoints using their saved credentials and{" "}
        {modernProtocol ? "native MCP" : "session-based MCP"}. No tools are called. Client API keys
        and OAuth login are not tested.
      </p>
      <div className="mt-3 space-y-2" role="status" aria-live="polite" aria-busy={check.isPending}>
        {check.isPending ? <p className="text-sm text-muted">Checking connections…</p> : null}
        {check.isError ? (
          <Callout tone="danger">
            {check.error instanceof Error
              ? check.error.message
              : "Connection check failed. Try again."}
          </Callout>
        ) : null}
        {check.isSuccess ? (
          <>
            <p className="text-xs text-faint">
              Last check. Run again after changing a source or profile.
            </p>
            {check.data.checks.length === 0 ? (
              <p className="text-sm text-muted">No sources are attached to this profile.</p>
            ) : null}
            {check.data.checks.map((result) => (
              <div
                key={JSON.stringify([result.sourceId, result.endpointId])}
                className="rounded-md border border-edge bg-well px-3 py-2"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="break-all font-mono text-xs text-fg">
                    {result.sourceId}
                    {result.endpointId ? ` / ${result.endpointId}` : ""}
                  </span>
                  <Badge tone={statuses[result.status].tone}>{statuses[result.status].label}</Badge>
                  {result.protocolVersion ? (
                    <span className="font-mono text-xs text-muted">
                      MCP {result.protocolVersion}
                    </span>
                  ) : null}
                </div>
                <p className="mt-1 text-xs text-muted">{result.message}</p>
              </div>
            ))}
          </>
        ) : null}
      </div>
    </div>
  );
}
