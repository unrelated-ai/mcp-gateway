"use client";

import { useState } from "react";
import type { Profile } from "@/src/lib/types";
import { Button, Callout, Input, Modal, ModalActions, Textarea } from "@/components/ui";

export function EditProfilePanel({
  open,
  profile,
  saving,
  saveError,
  onSave,
  onClose,
}: {
  open: boolean;
  profile: Profile;
  saving: boolean;
  saveError: string | null;
  onSave: (next: { name: string; description: string }) => void;
  onClose: () => void;
}) {
  // Mount a fresh draft per open to make Cancel/outside-click discard automatically.
  if (!open) return null;
  return (
    <EditProfilePanelOpen
      profile={profile}
      saving={saving}
      saveError={saveError}
      onSave={onSave}
      onClose={onClose}
    />
  );
}

function EditProfilePanelOpen({
  profile,
  saving,
  saveError,
  onSave,
  onClose,
}: Omit<Parameters<typeof EditProfilePanel>[0], "open">) {
  const [draft, setDraft] = useState<{ name: string; description: string }>(() => ({
    name: profile.name ?? "",
    description: profile.description ?? "",
  }));

  return (
    <Modal
      open
      onClose={onClose}
      title="Edit profile"
      description="Update name and description without leaving the page."
      size="lg"
    >
      {saveError ? <Callout tone="danger">{saveError}</Callout> : null}

      <div className="mt-5 grid gap-4 md:grid-cols-2">
        <Input
          label="Name"
          value={draft.name}
          onChange={(e) => setDraft((p) => ({ ...p, name: e.target.value }))}
          placeholder="Profile name"
        />
        <Textarea
          label="Description"
          value={draft.description}
          onChange={(e) => setDraft((p) => ({ ...p, description: e.target.value }))}
          placeholder="Optional description"
          rows={3}
        />
      </div>

      <ModalActions>
        <Button type="button" variant="ghost" onClick={onClose} disabled={saving}>
          Cancel
        </Button>
        <Button type="button" variant="primary" onClick={() => onSave(draft)} loading={saving}>
          Save
        </Button>
      </ModalActions>
    </Modal>
  );
}
