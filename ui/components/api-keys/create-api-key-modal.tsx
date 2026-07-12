"use client";

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button, Callout, CopyBlock, Input, Modal, ModalActions } from "@/components/ui";
import { CheckCircleIcon } from "@/components/icons";
import { qk } from "@/src/lib/queryKeys";
import * as tenantApi from "@/src/lib/tenantApi";
import { useToastStore } from "@/src/lib/toast-store";

export function CreateApiKeyModal({
  onClose,
  scope,
  profileId,
}: {
  onClose: () => void;
  scope: "tenant" | "profile";
  profileId?: string;
}) {
  const queryClient = useQueryClient();
  const pushToast = useToastStore((s) => s.push);
  const [name, setName] = useState("");
  const [secret, setSecret] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fixedProfileId = scope === "profile" ? (profileId ?? "") : "";

  const createMutation = useMutation({
    mutationFn: async () => {
      if (scope === "profile" && !fixedProfileId) {
        throw new Error("Missing profile id");
      }
      const resp = await tenantApi.createApiKey({
        name: name.trim() ? name.trim() : undefined,
        profileId: scope === "profile" ? fixedProfileId : undefined,
      });
      return resp.secret;
    },
    onSuccess: async (s) => {
      await queryClient.invalidateQueries({ queryKey: qk.apiKeys() });
      setSecret(s);
      setError(null);
      pushToast({ variant: "success", message: "API key created" });
    },
    onError: (e) => {
      setError(e instanceof Error ? e.message : "Failed to create API key");
    },
  });

  const close = () => {
    setName("");
    setSecret(null);
    setError(null);
    onClose();
  };

  return (
    <Modal
      open
      onClose={close}
      title={secret ? "API key created" : "Create API key"}
      description="API key secrets are only displayed at creation time."
      size="lg"
    >
      {secret ? (
        <div>
          <div className="mb-4 flex items-center gap-2 text-sm font-medium text-ok">
            <CheckCircleIcon className="size-5" />
            Key created successfully
          </div>

          <CopyBlock label="API key secret" value={secret} />

          <Callout tone="warn" className="mt-4">
            Copy this key now. You won&apos;t be able to see it again after closing.
          </Callout>

          <div className="mt-6">
            <Button className="w-full" variant="secondary" onClick={close}>
              Done
            </Button>
          </div>
        </div>
      ) : (
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            createMutation.mutate();
          }}
        >
          {error && (
            <Callout tone="danger" size="sm">
              {error}
            </Callout>
          )}

          <Input
            label="Key name (optional)"
            placeholder={scope === "tenant" ? "e.g. Tenant-wide key" : "e.g. Profile key"}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />

          <div className="rounded-lg border border-edge bg-well p-4 text-sm">
            {scope === "tenant" ? (
              <>
                <div className="font-medium text-fg">Tenant-wide key</div>
                <div className="mt-1 text-xs text-faint">
                  Can be used to authenticate to any profile in this tenant.
                </div>
              </>
            ) : (
              <>
                <div className="font-medium text-fg">Profile-scoped key</div>
                <div className="mt-1 text-xs text-faint">Works only for the selected profile.</div>
                <div className="mt-3">
                  <Input label="Profile ID" value={fixedProfileId} disabled className="font-mono" />
                </div>
              </>
            )}
          </div>

          <ModalActions>
            <Button
              type="button"
              variant="ghost"
              onClick={close}
              disabled={createMutation.isPending}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              loading={createMutation.isPending}
              disabled={scope === "profile" && !fixedProfileId}
            >
              Create key
            </Button>
          </ModalActions>
        </form>
      )}
    </Modal>
  );
}
