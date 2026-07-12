"use client";

import { useMemo, useState } from "react";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import type { ApiKeyMetadata } from "@/src/lib/types";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Badge,
  Button,
  Callout,
  ConfirmModal,
  EmptyState,
  SkeletonRows,
  Stat,
} from "@/components/ui";
import { qk } from "@/src/lib/queryKeys";
import * as tenantApi from "@/src/lib/tenantApi";
import { useToastStore } from "@/src/lib/toast-store";
import { CreateApiKeyModal } from "@/components/api-keys/create-api-key-modal";
import { FolderIcon, KeyIcon, PlusIcon } from "@/components/icons";
import { useDisclosure } from "@/src/lib/useDisclosure";
import { formatUnix, formatUnixRelative } from "@/src/lib/display";

const EMPTY_API_KEYS: ApiKeyMetadata[] = [];

export default function ApiKeysPage() {
  const [showRevokeModal, setShowRevokeModal] = useState<string | null>(null);
  const createModal = useDisclosure(false);
  const queryClient = useQueryClient();
  const pushToast = useToastStore((s) => s.push);

  const apiKeysQuery = useQuery({
    queryKey: qk.apiKeys(),
    queryFn: tenantApi.listApiKeys,
  });
  const apiKeys: ApiKeyMetadata[] = apiKeysQuery.data ?? EMPTY_API_KEYS;

  const tenantWideCount = useMemo(() => apiKeys.filter((k) => !k.profileId).length, [apiKeys]);
  const totalRequests = useMemo(
    () => apiKeys.reduce((acc, k) => acc + (k.totalRequestsAttempted ?? 0), 0),
    [apiKeys],
  );
  const revokeMutation = useMutation({
    mutationFn: (id: string) => tenantApi.revokeApiKey(id),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: qk.apiKeys() });
      pushToast({ variant: "success", message: "API key revoked" });
      setShowRevokeModal(null);
    },
    onError: (e) => {
      pushToast({
        variant: "error",
        message: e instanceof Error ? e.message : "Failed to revoke key",
      });
      setShowRevokeModal(null);
    },
  });

  return (
    <AppShell>
      <PageHeader
        title="API keys"
        description="Manage authentication keys for MCP endpoints"
        actions={
          <Button onClick={createModal.onOpen}>
            <PlusIcon className="size-4" />
            Create API key
          </Button>
        }
      />

      <PageContent>
        {apiKeysQuery.error && (
          <Callout tone="danger" title="Failed to load API keys" size="md" className="mb-6">
            {apiKeysQuery.error instanceof Error
              ? apiKeysQuery.error.message
              : "Failed to load API keys"}
          </Callout>
        )}

        {/* Stats */}
        <div className="mb-6 grid grid-cols-3 gap-4">
          <Stat label="Total keys" value={apiKeys.length} />
          <Stat label="Tenant-wide" value={tenantWideCount} />
          <Stat label="Total requests" value={totalRequests.toLocaleString()} />
        </div>

        {/* Info banner */}
        <Callout tone="warn" title="Secret shown once" size="md" className="mb-6">
          API key secrets are only displayed at creation time. Make sure to copy and store them
          securely. You cannot retrieve the full secret later.
        </Callout>

        {apiKeysQuery.isPending && <SkeletonRows rows={3} />}
        {!apiKeysQuery.isPending && !apiKeysQuery.error && apiKeys.length === 0 && (
          <EmptyState
            icon={<KeyIcon className="size-5" />}
            title="No API keys yet"
            description="Create a key to authenticate agents against your MCP endpoints."
            action={{ label: "Create API key", onClick: createModal.onOpen }}
          />
        )}
        {!apiKeysQuery.isPending && !apiKeysQuery.error && apiKeys.length > 0 && (
          <div className="overflow-hidden rounded-lg border border-edge bg-surface">
            <div className="divide-y divide-edge">
              {apiKeys.map((key) => (
                <div key={key.id} className="p-5 transition-colors duration-150 hover:bg-raised/40">
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-3">
                        <h3 className="text-sm font-semibold text-fg">{key.name}</h3>
                        {key.profileId ? (
                          <Badge tone="info">Profile-scoped</Badge>
                        ) : (
                          <Badge tone="ok">Tenant-wide</Badge>
                        )}
                      </div>

                      <div className="mt-2 flex items-center gap-4 text-xs text-faint">
                        <span className="rounded bg-raised px-2 py-1 font-mono text-muted">
                          {key.prefix}••••••••
                        </span>
                        {key.profileId && (
                          <span className="flex items-center gap-1 font-mono">
                            <FolderIcon className="size-3.5" />
                            {key.profileId}
                          </span>
                        )}
                      </div>

                      <div className="mt-3 flex items-center gap-4 text-xs text-faint">
                        <span>Created {formatUnix(key.createdAtUnix)}</span>
                        <span className="size-1 rounded-full bg-edge-strong" />
                        <span>Last used {formatUnixRelative(key.lastUsedAtUnix)}</span>
                        <span className="size-1 rounded-full bg-edge-strong" />
                        <span>{key.totalRequestsAttempted.toLocaleString()} requests</span>
                      </div>
                    </div>

                    <Button variant="danger" size="sm" onClick={() => setShowRevokeModal(key.id)}>
                      Revoke
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </PageContent>

      {/* Create Key Modal */}
      {createModal.open && <CreateApiKeyModal onClose={createModal.onClose} scope="tenant" />}

      {/* Revoke Modal */}
      <ConfirmModal
        open={!!showRevokeModal}
        onClose={() => setShowRevokeModal(null)}
        onConfirm={() => {
          if (!showRevokeModal) return;
          revokeMutation.mutate(showRevokeModal);
        }}
        title="Revoke API key?"
        description="This will immediately invalidate the key. Any applications using it will lose access. This action cannot be undone."
        confirmLabel="Revoke key"
        danger
        loading={revokeMutation.isPending}
      />
    </AppShell>
  );
}
