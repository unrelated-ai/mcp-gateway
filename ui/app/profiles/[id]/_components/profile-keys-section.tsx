"use client";

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Badge,
  Button,
  ConfirmModal,
  EndpointWell,
  Modal,
  ModalActions,
  SectionCard,
  Skeleton,
} from "@/components/ui";
import { InfoIconAlt } from "@/components/icons";
import * as tenantApi from "@/src/lib/tenantApi";
import { qk } from "@/src/lib/queryKeys";
import { useToastStore } from "@/src/lib/toast-store";
import { CreateApiKeyModal } from "@/components/api-keys/create-api-key-modal";
import { formatUnix, formatUnixRelative } from "@/src/lib/display";

const InfoIcon = InfoIconAlt;

export function ProfileKeysSection({
  profileId,
  mcpUrl,
  profileApiKeys,
  loading,
}: {
  profileId: string;
  mcpUrl: string;
  profileApiKeys: Array<{
    id: string;
    name: string;
    prefix: string;
    createdAtUnix: number;
    lastUsedAtUnix: number | null;
    totalRequestsAttempted: number;
  }>;
  loading: boolean;
}) {
  const queryClient = useQueryClient();
  const pushToast = useToastStore((s) => s.push);

  const [showCreateKeyModal, setShowCreateKeyModal] = useState(false);
  const [showRevokeKeyModal, setShowRevokeKeyModal] = useState<string | null>(null);
  const [showApiKeyHelp, setShowApiKeyHelp] = useState(false);

  const revokeKeyMutation = useMutation({
    mutationFn: (id: string) => tenantApi.revokeApiKey(id),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: qk.apiKeys() });
      pushToast({ variant: "success", message: "API key revoked" });
      setShowRevokeKeyModal(null);
    },
    onError: (e) => {
      pushToast({
        variant: "error",
        message: e instanceof Error ? e.message : "Failed to revoke key",
      });
      setShowRevokeKeyModal(null);
    },
  });

  return (
    <>
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted">
            API keys for authenticating requests to this profile&apos;s MCP endpoint.
          </p>
          <div className="flex items-center gap-2">
            <Button
              type="button"
              variant="ghost"
              onClick={() => setShowApiKeyHelp(true)}
              aria-label="API keys help"
            >
              <InfoIcon className="size-4" />
              Help
            </Button>
            <Button type="button" onClick={() => setShowCreateKeyModal(true)}>
              Create API key
            </Button>
          </div>
        </div>

        <SectionCard
          title="Profile keys"
          subtitle="Only keys scoped to this profile are shown here. Tenant-wide keys are listed on the API keys page."
          bodyClassName="p-0"
        >
          <div className="divide-y divide-edge">
            {loading ? (
              <div className="p-5">
                <Skeleton className="h-16 w-full" />
              </div>
            ) : profileApiKeys.length === 0 ? (
              <div className="p-5 text-sm text-faint">No profile-scoped API keys yet.</div>
            ) : (
              profileApiKeys.map((k) => (
                <div key={k.id} className="p-5 transition-colors duration-150 hover:bg-raised/50">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3">
                        <h3 className="text-sm font-semibold text-fg">{k.name}</h3>
                        <Badge tone="info">Profile-scoped</Badge>
                      </div>
                      <div className="mt-2 flex items-center gap-4 text-xs text-faint">
                        <span className="rounded border border-edge bg-well px-2 py-1 font-mono text-muted">
                          {k.prefix}••••••••
                        </span>
                      </div>
                      <div className="mt-3 flex items-center gap-4 text-xs text-faint">
                        <span>Created {formatUnix(k.createdAtUnix)}</span>
                        <span aria-hidden="true">·</span>
                        <span>Last used {formatUnixRelative(k.lastUsedAtUnix)}</span>
                        <span aria-hidden="true">·</span>
                        <span>{k.totalRequestsAttempted.toLocaleString()} requests</span>
                      </div>
                    </div>
                    <Button variant="danger" size="sm" onClick={() => setShowRevokeKeyModal(k.id)}>
                      Revoke
                    </Button>
                  </div>
                </div>
              ))
            )}
          </div>
        </SectionCard>
      </div>

      {showCreateKeyModal && (
        <CreateApiKeyModal
          onClose={() => setShowCreateKeyModal(false)}
          scope="profile"
          profileId={profileId}
        />
      )}

      <Modal
        open={showApiKeyHelp}
        onClose={() => setShowApiKeyHelp(false)}
        title="API keys help"
        description="Tenant-wide vs profile-scoped keys"
        size="lg"
      >
        <div className="space-y-4">
          <div className="text-sm text-muted">
            API keys control access to MCP endpoints. You can create keys in two scopes:
          </div>
          <div className="rounded-lg border border-edge bg-well p-4 space-y-2">
            <div className="eyebrow">Profile-scoped key</div>
            <div className="text-sm text-muted">
              Grants access to <span className="font-semibold text-fg">only this profile</span>.
            </div>
            <div className="text-xs text-faint">This exact endpoint:</div>
            <EndpointWell url={mcpUrl} showLed={false} />
          </div>
          <div className="rounded-lg border border-edge bg-well p-4 space-y-2">
            <div className="eyebrow">Tenant-wide key</div>
            <div className="text-sm text-muted">
              Grants access to <span className="font-semibold text-fg">all profiles</span> in this
              tenant (useful for shared clients/automation).
            </div>
            <div className="text-xs text-faint">
              Tenant-wide keys are created on the global{" "}
              <span className="font-semibold text-fg">API keys</span> page.
            </div>
          </div>
          <div className="rounded-lg border border-edge bg-well p-4 space-y-2">
            <div className="eyebrow">Future</div>
            <div className="text-sm text-muted">
              More granular keys (tenant-level keys restricted to a specific set of profiles) are
              planned for a future release.
            </div>
          </div>
        </div>
        <ModalActions>
          <Button type="button" variant="secondary" onClick={() => setShowApiKeyHelp(false)}>
            Close
          </Button>
        </ModalActions>
      </Modal>

      <ConfirmModal
        open={!!showRevokeKeyModal}
        onClose={() => setShowRevokeKeyModal(null)}
        onConfirm={() => {
          if (!showRevokeKeyModal) return;
          revokeKeyMutation.mutate(showRevokeKeyModal);
        }}
        title="Revoke API key?"
        description="This will immediately invalidate the key. Any applications using it will lose access. This action cannot be undone."
        confirmLabel="Revoke key"
        danger
        loading={revokeKeyMutation.isPending}
      />
    </>
  );
}
