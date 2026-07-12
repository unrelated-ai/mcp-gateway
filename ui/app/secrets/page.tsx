"use client";

import { useMemo, useState } from "react";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import {
  Badge,
  Button,
  Callout,
  ConfirmModal,
  CopyBlock,
  EmptyState,
  Input,
  Modal,
  ModalActions,
  SectionCard,
  SkeletonRows,
  Textarea,
} from "@/components/ui";
import { qk } from "@/src/lib/queryKeys";
import * as tenantApi from "@/src/lib/tenantApi";
import { useToastStore } from "@/src/lib/toast-store";
import { CheckCircleIcon, KeyIcon, PlusIcon, ShieldIcon } from "@/components/icons";
import { useDisclosure } from "@/src/lib/useDisclosure";

type SecretMeta = { name: string };

const EMPTY_SECRETS: SecretMeta[] = [];

export default function SecretsPage() {
  const createModal = useDisclosure(false);
  const [showUpdateModal, setShowUpdateModal] = useState<string | null>(null);
  const [showDeleteModal, setShowDeleteModal] = useState<string | null>(null);
  const queryClient = useQueryClient();
  const pushToast = useToastStore((s) => s.push);

  const secretsQuery = useQuery({
    queryKey: qk.secrets(),
    queryFn: tenantApi.listSecrets,
  });
  const secrets: SecretMeta[] = (secretsQuery.data?.secrets ?? EMPTY_SECRETS) as SecretMeta[];

  const sortedSecrets = useMemo(
    () => [...secrets].sort((a, b) => a.name.localeCompare(b.name)),
    [secrets],
  );
  const deleteMutation = useMutation({
    mutationFn: (name: string) => tenantApi.deleteSecret(name),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: qk.secrets() });
      pushToast({ variant: "success", message: "Secret deleted" });
      setShowDeleteModal(null);
    },
    onError: (e) => {
      pushToast({
        variant: "error",
        message: e instanceof Error ? e.message : "Failed to delete secret",
      });
      setShowDeleteModal(null);
    },
  });

  return (
    <AppShell>
      <PageHeader
        title="Secrets"
        description="Securely store sensitive values like API keys and tokens"
        actions={
          <Button onClick={createModal.onOpen}>
            <PlusIcon className="size-4" />
            Add secret
          </Button>
        }
      />

      <PageContent>
        {secretsQuery.error && (
          <Callout tone="danger" title="Failed to load secrets" size="md" className="mb-6">
            {secretsQuery.error instanceof Error
              ? secretsQuery.error.message
              : "Failed to load secrets"}
          </Callout>
        )}

        {/* Info banner */}
        <Callout tone="accent" title="Write-only secrets" size="md" className="mb-6">
          Secret values are encrypted and cannot be viewed after creation. You can only update or
          delete them. Use syntax like{" "}
          <code className="rounded bg-raised px-1.5 py-0.5 font-mono text-muted">
            ${"{secret:SECRET_NAME}"}
          </code>{" "}
          in tool sources to reference them.
        </Callout>

        {secretsQuery.isPending && <SkeletonRows rows={3} />}
        {!secretsQuery.isPending && !secretsQuery.error && sortedSecrets.length === 0 && (
          <EmptyState
            icon={<ShieldIcon className="size-5" />}
            title="No secrets yet"
            description="Add your first secret to get started."
            action={{ label: "Add secret", onClick: createModal.onOpen }}
          />
        )}
        {!secretsQuery.isPending && !secretsQuery.error && sortedSecrets.length > 0 && (
          <SectionCard className="overflow-hidden" bodyClassName="p-0">
            <div className="divide-y divide-edge">
              {sortedSecrets.map((secret) => (
                <div
                  key={secret.name}
                  className="p-5 transition-colors duration-150 hover:bg-raised/40"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-start gap-4">
                      <div className="flex size-10 items-center justify-center rounded-lg border border-edge bg-raised">
                        <KeyIcon className="size-5 text-muted" />
                      </div>
                      <div>
                        <div className="flex items-center gap-3">
                          <code className="font-mono text-sm font-semibold text-fg">
                            {secret.name}
                          </code>
                          <Badge>••••••••</Badge>
                        </div>
                        <div className="mt-2 text-xs text-faint">
                          Write-only secret value (not readable).
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setShowUpdateModal(secret.name)}
                      >
                        Update
                      </Button>
                      <Button
                        variant="danger"
                        size="sm"
                        onClick={() => setShowDeleteModal(secret.name)}
                      >
                        Delete
                      </Button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </SectionCard>
        )}
      </PageContent>

      {/* Create Modal */}
      {createModal.open && (
        <CreateSecretModal
          onClose={createModal.onClose}
          onCreated={() => {
            // query invalidation happens inside modal
          }}
        />
      )}

      {/* Update Modal */}
      {showUpdateModal && (
        <CreateSecretModal
          initialName={showUpdateModal}
          onClose={() => setShowUpdateModal(null)}
          onCreated={() => {
            // query invalidation happens inside modal
          }}
        />
      )}

      {/* Delete Modal */}
      <ConfirmModal
        open={!!showDeleteModal}
        onClose={() => setShowDeleteModal(null)}
        onConfirm={() => {
          if (!showDeleteModal) return;
          deleteMutation.mutate(showDeleteModal);
        }}
        title="Delete secret?"
        description={
          showDeleteModal
            ? `This will permanently delete "${showDeleteModal}". Any tool sources using this secret will fail.`
            : "This will permanently delete the secret."
        }
        confirmLabel="Delete secret"
        danger
        loading={deleteMutation.isPending}
      />
    </AppShell>
  );
}

const createSecretSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, "Secret name is required")
    .regex(/^[A-Z][A-Z0-9_]*$/, "Use SCREAMING_SNAKE_CASE (A-Z, 0-9, _)"),
  value: z.string().min(1, "Secret value is required"),
});

type CreateSecretForm = z.infer<typeof createSecretSchema>;

function CreateSecretModal({
  onClose,
  onCreated,
  initialName,
}: {
  onClose: () => void;
  onCreated: () => void;
  initialName?: string;
}) {
  const queryClient = useQueryClient();
  const pushToast = useToastStore((s) => s.push);
  const [createdName, setCreatedName] = useState<string | null>(null);
  const isUpdate = typeof initialName === "string" && initialName.trim().length > 0;

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<CreateSecretForm>({
    resolver: zodResolver(createSecretSchema),
    defaultValues: { name: initialName ?? "", value: "" },
  });

  const createMutation = useMutation({
    mutationFn: async (values: CreateSecretForm) => {
      await tenantApi.createSecret({ name: values.name.trim(), value: values.value });
      return values.name.trim();
    },
    onSuccess: async (name) => {
      await queryClient.invalidateQueries({ queryKey: qk.secrets() });
      setCreatedName(name);
      pushToast({
        variant: "success",
        message: isUpdate ? "Secret updated" : "Secret stored securely",
      });
      onCreated();
    },
    onError: (e) => {
      pushToast({
        variant: "error",
        message: e instanceof Error ? e.message : "Failed to save secret",
      });
    },
  });

  const close = () => {
    setCreatedName(null);
    reset();
    onClose();
  };

  return (
    <Modal
      open
      onClose={close}
      title={
        createdName
          ? isUpdate
            ? "Secret updated"
            : "Secret created"
          : isUpdate
            ? "Update secret"
            : "Add secret"
      }
      description={
        createdName
          ? "Your secret has been encrypted and stored. You can now reference it in tool sources."
          : isUpdate
            ? "Secret values are write-only. Updating will overwrite the stored value."
            : "Secret values are write-only and cannot be viewed after creation."
      }
      size="lg"
    >
      {createdName ? (
        <div>
          <div className="mb-4 flex items-center gap-2 text-sm font-medium text-ok">
            <CheckCircleIcon className="size-5" />
            {isUpdate ? "Secret updated" : "Secret stored securely"}
          </div>
          <p className="text-sm text-muted">Reference it in tool sources using:</p>
          <div className="mt-3">
            <CopyBlock value={`\${secret:${createdName}}`} />
          </div>
          <div className="mt-6">
            <Button className="w-full" variant="secondary" onClick={close}>
              Done
            </Button>
          </div>
        </div>
      ) : (
        <form
          className="space-y-4"
          onSubmit={handleSubmit((values) => createMutation.mutate(values))}
        >
          <Input
            label="Secret name"
            placeholder="e.g. API_KEY"
            {...register("name")}
            error={errors.name?.message}
            hint="Use SCREAMING_SNAKE_CASE for consistency."
            className="font-mono uppercase"
            disabled={isUpdate}
          />

          <Textarea
            label="Secret value"
            rows={3}
            placeholder="Enter the secret value…"
            {...register("value")}
            error={errors.value?.message}
            hint="This value will be encrypted and cannot be viewed again."
            className="font-mono"
          />

          <ModalActions>
            <Button type="button" variant="ghost" onClick={close} disabled={isSubmitting}>
              Cancel
            </Button>
            <Button type="submit" loading={createMutation.isPending}>
              Save secret
            </Button>
          </ModalActions>
        </form>
      )}
    </Modal>
  );
}
