"use client";

import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button, SectionCard, Select, Textarea } from "@/components/ui";
import { SaveStatus } from "@/components/ui/save-status";
import { asMcpSettings, normalizeMcpSettings } from "@/src/lib/mcpSettings";
import { qk } from "@/src/lib/queryKeys";
import { updateProfile } from "@/src/lib/tenantApi";
import type { McpProfileSettings, Profile } from "@/src/lib/types";
import { useAutosave } from "@/src/lib/useAutosave";

type AdvancedSettings = Pick<McpProfileSettings, "notifications" | "namespacing">;

export function McpAdvancedCard({ profile }: { profile: Profile }) {
  const queryClient = useQueryClient();
  const initial = asMcpSettings(profile.mcp);
  const [allow, setAllow] = useState(initial.notifications.allow.join("\n"));
  const [deny, setDeny] = useState(initial.notifications.deny.join("\n"));
  const [namespacing, setNamespacing] = useState(initial.namespacing);
  const autosave = useAutosave<AdvancedSettings>(async (settings) => {
    await updateProfile(profile, (current) => ({
      mcp: normalizeMcpSettings({ ...asMcpSettings(current.mcp), ...settings }),
    }));
    await queryClient.invalidateQueries({ queryKey: qk.profile(profile.id) });
  });
  return (
    <SectionCard title="Advanced MCP settings" bodyClassName="space-y-4">
      <SaveStatus {...autosave} onRetry={autosave.retry} label="Advanced MCP settings" />
      <form
        onSubmit={(event) => {
          event.preventDefault();
          autosave.commit({
            notifications: { allow: allow.split("\n"), deny: deny.split("\n") },
            namespacing,
          });
        }}
      >
        <fieldset disabled={autosave.status === "saving"} className="space-y-4">
          <p className="text-sm text-muted">
            Filter upstream notifications by exact method name, one per line. A nonempty allow list
            takes precedence over the deny list. With an empty allow list, all methods except denied
            ones are permitted. Disabled capabilities still apply.
          </p>
          <Textarea
            label="Allowed notifications"
            value={allow}
            rows={3}
            placeholder="notifications/progress"
            onChange={(event) => {
              setAllow(event.target.value);
              autosave.edit();
            }}
          />
          <Textarea
            label="Denied notifications"
            value={deny}
            rows={3}
            placeholder="notifications/message"
            onChange={(event) => {
              setDeny(event.target.value);
              autosave.edit();
            }}
          />
          <p className="text-sm text-muted">
            Identifier formatting controls legacy MCP proxy traffic. Request signing is configured
            under Security.
          </p>
          <Select
            label="Proxied request IDs"
            value={namespacing.requestId}
            onChange={(event) => {
              setNamespacing({
                ...namespacing,
                requestId: event.target.value as typeof namespacing.requestId,
              });
              autosave.edit();
            }}
          >
            <option value="opaque">Opaque (encoded upstream ID)</option>
            <option value="readable">Readable upstream ID</option>
          </Select>
          <Select
            label="SSE event IDs"
            value={namespacing.sseEventId}
            onChange={(event) => {
              setNamespacing({
                ...namespacing,
                sseEventId: event.target.value as typeof namespacing.sseEventId,
              });
              autosave.edit();
            }}
          >
            <option value="upstream-slash">Prefix with upstream ID</option>
            <option value="none">Preserve upstream event ID</option>
          </Select>
          <Button
            type="submit"
            disabled={autosave.status === "idle" || autosave.status === "saved"}
            loading={autosave.status === "saving"}
          >
            Save advanced MCP settings
          </Button>
        </fieldset>
      </form>
    </SectionCard>
  );
}
