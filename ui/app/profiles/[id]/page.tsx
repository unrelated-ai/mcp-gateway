"use client";

import { useMemo, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import type { Profile } from "@/src/lib/types";
import {
  authDraftFromSettings,
  authSettingsFromDraft,
  type AuthDraft,
} from "@/src/lib/data-plane-auth";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Button,
  Callout,
  ConfirmModal,
  IconButton,
  Input,
  Modal,
  ModalActions,
  Select,
  Spinner,
  Tabs,
  Toggle,
} from "@/components/ui";
import { qk } from "@/src/lib/queryKeys";
import * as tenantApi from "@/src/lib/tenantApi";
import type { ProfileSurface } from "@/src/lib/tenantApi";
import { useToastStore } from "@/src/lib/toast-store";
import { GATEWAY_DATA_BASE } from "@/src/lib/env";
import { invalidateProfile, invalidateProfiles } from "@/src/lib/queries/profileQueries";
import { PencilIcon } from "@/components/icons";
import { ToolsNewTab } from "./_components/tools-new-tab";
import { ConnectionInfoCard } from "./_components/connection-info-card";
import { EditProfilePanel } from "./_components/edit-profile-panel";
import { McpSurfaceSection } from "./_components/mcp-surface-section";
import { ProfileKeysSection } from "./_components/profile-keys-section";
import { SourcesTab } from "./_components/sources-tab";
import { SecurityTab } from "./_components/security-tab";

export default function ProfileDetailPage() {
  const params = useParams();
  const router = useRouter();
  const profileId = String(params.id ?? "");
  const [activeTab, setActiveTab] = useState<"tools" | "sources" | "keys" | "security" | "other">(
    "tools",
  );
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showMcpAuthHelp, setShowMcpAuthHelp] = useState(false);
  const [showAuthSettings, setShowAuthSettings] = useState(false);
  const [editingMeta, setEditingMeta] = useState(false);
  const [authDraft, setAuthDraft] = useState<AuthDraft | null>(null);
  const [confirmWeakAuthMode, setConfirmWeakAuthMode] = useState<AuthDraft | null>(null);
  const mcpUrl = `${GATEWAY_DATA_BASE}/${profileId}/mcp`;

  const queryClient = useQueryClient();
  const pushToast = useToastStore((s) => s.push);

  type GatewayStatusResponse =
    | {
        ok: true;
        status: {
          oauthConfigured?: boolean;
          oauthIssuer?: string;
          publicDataBaseUrl?: string;
        };
      }
    | { ok: false; error?: string; status?: number };

  const gatewayStatusQuery = useQuery({
    queryKey: qk.gatewayStatus(),
    queryFn: async () => {
      const res = await fetch("/api/gateway/status", { cache: "no-store" });
      if (!res.ok) {
        return { ok: false, status: res.status } as GatewayStatusResponse;
      }
      return (await res.json()) as GatewayStatusResponse;
    },
  });
  const oauthConfigured =
    gatewayStatusQuery.isPending || !gatewayStatusQuery.data
      ? null
      : gatewayStatusQuery.data.ok
        ? (gatewayStatusQuery.data.status.oauthConfigured ?? null)
        : null;
  const publicDataBaseUrl =
    gatewayStatusQuery.data?.ok === true
      ? gatewayStatusQuery.data.status.publicDataBaseUrl?.replace(/\/$/, "")
      : undefined;
  const protectedResourceMetadataUrl = publicDataBaseUrl
    ? `${publicDataBaseUrl}/.well-known/oauth-protected-resource/${profileId}/mcp`
    : null;

  const profileQuery = useQuery({
    queryKey: qk.profile(profileId),
    enabled: !!profileId,
    queryFn: () => tenantApi.getProfile(profileId),
  });
  const profile: Profile | null = profileQuery.data ?? null;
  const loading = profileQuery.isPending;
  const error =
    profileQuery.error instanceof Error
      ? profileQuery.error.message
      : profileQuery.error
        ? "Failed to load profile"
        : null;

  const clientKey = useMemo(() => {
    const n = profile?.name ?? "profile";
    return n.toLowerCase().replace(/\s+/g, "-");
  }, [profile?.name]);

  type SurfaceResponse = ProfileSurface;
  const DISABLE_ALL_TOOLS_SENTINEL = "__none__:__none__";
  const deleteRequireText = useMemo(() => {
    if (!profile) return undefined;
    const n = profile.name.trim();
    // If the name is very long, prefer an ID confirmation (still copy/paste friendly).
    return n && n.length <= 48 ? n : profile.id;
  }, [profile]);

  const [surfaceByProfileId, setSurfaceByProfileId] = useState<
    Record<string, SurfaceResponse | undefined>
  >({});
  const [surfaceErrorByProfileId, setSurfaceErrorByProfileId] = useState<
    Record<string, string | undefined>
  >({});

  const surface = profileId ? (surfaceByProfileId[profileId] ?? null) : null;
  const surfaceError = profileId ? (surfaceErrorByProfileId[profileId] ?? null) : null;

  const apiKeysQuery = useQuery({
    queryKey: qk.apiKeys(),
    queryFn: tenantApi.listApiKeys,
  });
  const profileApiKeys = useMemo(() => {
    const all = apiKeysQuery.data ?? [];
    return all.filter((k) => k.profileId === profileId);
  }, [apiKeysQuery.data, profileId]);

  const updateAuthMutation = useMutation({
    mutationFn: async (next: AuthDraft) => {
      if (!profile) throw new Error("Profile not loaded");
      await tenantApi.updateProfile(profile.id, { dataPlaneAuth: authSettingsFromDraft(next) });
      return next;
    },
    onSuccess: async (next) => {
      await invalidateProfile(queryClient, profileId);
      await invalidateProfiles(queryClient);
      setShowAuthSettings(false);
      setAuthDraft(next);
    },
    onError: (e) => {
      pushToast({
        variant: "error",
        message: e instanceof Error ? e.message : "Failed to update auth settings",
      });
    },
  });

  const authIsDirty = useMemo(() => {
    if (!profile || !authDraft) return false;
    return (
      JSON.stringify(authSettingsFromDraft(authDraft)) !== JSON.stringify(profile.dataPlaneAuth)
    );
  }, [authDraft, profile]);

  const toggleEnabledMutation = useMutation({
    mutationFn: async (enabled: boolean) => {
      if (!profile) throw new Error("Profile not loaded");
      await tenantApi.updateProfile(profile.id, { enabled });
      return enabled;
    },
    onMutate: async (enabled) => {
      await queryClient.cancelQueries({ queryKey: qk.profile(profileId) });
      await queryClient.cancelQueries({ queryKey: qk.profiles() });

      const prevProfile = queryClient.getQueryData<Profile>(qk.profile(profileId));
      const prevProfiles = queryClient.getQueryData<{ profiles: Profile[] }>(qk.profiles());

      queryClient.setQueryData(qk.profile(profileId), (old: Profile | undefined) => {
        if (!old) return old;
        return { ...old, enabled };
      });

      queryClient.setQueryData(qk.profiles(), (old: { profiles: Profile[] } | undefined) => {
        if (!old) return old;
        return {
          ...old,
          profiles: old.profiles.map((p) => (p.id === profileId ? { ...p, enabled } : p)),
        };
      });

      return { prevProfile, prevProfiles };
    },
    onError: (e, _enabled, ctx) => {
      if (ctx?.prevProfile) queryClient.setQueryData(qk.profile(profileId), ctx.prevProfile);
      if (ctx?.prevProfiles) queryClient.setQueryData(qk.profiles(), ctx.prevProfiles);
      pushToast({
        variant: "error",
        message: e instanceof Error ? e.message : "Failed to update profile",
      });
    },
    onSettled: async () => {
      await invalidateProfile(queryClient, profileId);
      await invalidateProfiles(queryClient);
    },
  });

  const updateMetaMutation = useMutation({
    mutationFn: async (next: { name: string; description: string }) => {
      if (!profile) throw new Error("Profile not loaded");
      await tenantApi.updateProfile(profile.id, {
        name: next.name.trim(),
        description: next.description.trim() ? next.description : null,
      });
      return next;
    },
    onSuccess: async (next) => {
      await invalidateProfile(queryClient, profileId);
      await invalidateProfiles(queryClient);
      queryClient.setQueryData(qk.profile(profileId), (old: Profile | undefined) => {
        if (!old) return old;
        return {
          ...old,
          name: next.name.trim(),
          description: next.description.trim() ? next.description : null,
        };
      });
      setMetaSaveError(null);
      setEditingMeta(false);
    },
    onError: (e) => {
      setMetaSaveError(e instanceof Error ? e.message : "Failed to update profile");
    },
  });

  const [metaSaveError, setMetaSaveError] = useState<string | null>(null);
  const saveMeta = (next: { name: string; description: string }) => {
    if (!profile) return;
    setMetaSaveError(null);
    updateMetaMutation.mutate(next);
  };

  const probeMutation = useMutation({
    mutationFn: async () => {
      return await tenantApi.probeProfileSurface(profileId);
    },
    onSuccess: (resp) => {
      setSurfaceByProfileId((prev) => ({ ...prev, [profileId]: resp }));
      setSurfaceErrorByProfileId((prev) => ({ ...prev, [profileId]: undefined }));
    },
    onError: (e) => {
      const msg = e instanceof Error ? e.message : "Failed to probe surface";
      setSurfaceErrorByProfileId((prev) => ({ ...prev, [profileId]: msg }));
    },
  });

  const updateEnabledToolsMutation = useMutation({
    mutationFn: async (nextTools: string[]) => {
      if (!profile) throw new Error("Profile not loaded");
      await tenantApi.updateProfile(profile.id, { tools: nextTools });
      return nextTools;
    },
    onMutate: async (nextTools) => {
      await queryClient.cancelQueries({ queryKey: qk.profile(profileId) });
      await queryClient.cancelQueries({ queryKey: qk.profiles() });

      const prevProfile = queryClient.getQueryData<Profile>(qk.profile(profileId));
      const prevProfiles = queryClient.getQueryData<{ profiles: Profile[] }>(qk.profiles());
      const prevSurface = profileId ? (surfaceByProfileId[profileId] ?? undefined) : undefined;

      queryClient.setQueryData(qk.profile(profileId), (old: Profile | undefined) => {
        if (!old) return old;
        return { ...old, tools: nextTools };
      });

      queryClient.setQueryData(qk.profiles(), (old: { profiles: Profile[] } | undefined) => {
        if (!old) return old;
        return {
          ...old,
          profiles: old.profiles.map((p) => (p.id === profileId ? { ...p, tools: nextTools } : p)),
        };
      });

      // Optimistically update the probed surface so the UI doesn't flash/flicker.
      setSurfaceByProfileId((prev) => {
        const s = prev[profileId];
        if (!s) return prev;

        const allowAll = nextTools.length === 0;
        const allowNone = nextTools.length === 1 && nextTools[0] === DISABLE_ALL_TOOLS_SENTINEL;
        const allowSet = new Set(nextTools);

        const nextAllTools = s.allTools.map((t) => {
          const ref = `${t.sourceId}:${t.originalName}`;
          const enabled = allowAll ? true : allowNone ? false : allowSet.has(ref);
          return { ...t, enabled };
        });

        const nextEnabledTools = nextAllTools
          .filter((t) => t.enabled)
          .map((t) => ({
            name: t.name,
            description: t.description ?? t.originalDescription ?? null,
          }));

        return { ...prev, [profileId]: { ...s, allTools: nextAllTools, tools: nextEnabledTools } };
      });

      return { prevProfile, prevProfiles, prevSurface };
    },
    onSuccess: async (nextTools) => {
      await invalidateProfile(queryClient, profileId);
      await invalidateProfiles(queryClient);
      queryClient.setQueryData(qk.profile(profileId), (old: Profile | undefined) => {
        if (!old) return old;
        return { ...old, tools: nextTools };
      });
    },
    onError: (e, _nextTools, ctx) => {
      if (ctx?.prevProfile) queryClient.setQueryData(qk.profile(profileId), ctx.prevProfile);
      if (ctx?.prevProfiles) queryClient.setQueryData(qk.profiles(), ctx.prevProfiles);
      if (ctx?.prevSurface !== undefined) {
        setSurfaceByProfileId((prev) => ({ ...prev, [profileId]: ctx.prevSurface }));
      }
      pushToast({
        variant: "error",
        message: e instanceof Error ? e.message : "Failed to update tools",
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async () => {
      await tenantApi.deleteProfile(profileId);
    },
    onSuccess: async () => {
      await invalidateProfiles(queryClient);
      pushToast({ variant: "success", message: "Profile deleted" });
      router.push("/profiles");
    },
    onError: (e) => {
      pushToast({
        variant: "error",
        message: e instanceof Error ? e.message : "Failed to delete profile",
      });
    },
  });

  const allToolRefs = useMemo(() => {
    if (!surface) return [];
    return surface.allTools.map((t) => `${t.sourceId}:${t.originalName}`);
  }, [surface]);

  const setToolEnabled = (toolRef: string, enabled: boolean) => {
    if (!profile) return;
    if (!surface) return;

    const allRefs = allToolRefs;
    const current = profile.tools ?? [];
    const isAllowAll = current.length === 0;
    const isAllowNone = current.length === 1 && current[0] === DISABLE_ALL_TOOLS_SENTINEL;

    // Semantics:
    // - [] => no allowlist configured (allow all tools)
    // - [DISABLE_ALL_TOOLS_SENTINEL] => allowlist configured, but matches nothing (allow none)
    if (isAllowAll) {
      if (enabled) return;
      const next = allRefs.filter((r) => r !== toolRef);
      updateEnabledToolsMutation.mutate(next.length === 0 ? [DISABLE_ALL_TOOLS_SENTINEL] : next);
      return;
    }
    if (isAllowNone) {
      if (!enabled) return;
      updateEnabledToolsMutation.mutate([toolRef]);
      return;
    }

    const currentSet = new Set(current);

    if (enabled) {
      currentSet.add(toolRef);
    } else {
      currentSet.delete(toolRef);
    }

    const next = Array.from(currentSet);
    const nextSet = new Set(next);
    const isAllEnabled = allRefs.length > 0 && allRefs.every((r) => nextSet.has(r));
    if (next.length === 0) {
      updateEnabledToolsMutation.mutate([DISABLE_ALL_TOOLS_SENTINEL]);
    } else {
      updateEnabledToolsMutation.mutate(isAllEnabled ? [] : next);
    }
  };

  return (
    <AppShell>
      <PageHeader
        title={
          loading ? (
            "Loading…"
          ) : (
            <div className="flex items-center gap-3">
              <span className="truncate">{profile?.name ?? "Profile"}</span>
              {profile && !editingMeta && (
                <IconButton
                  label="Edit profile name and description"
                  onClick={() => {
                    setMetaSaveError(null);
                    setEditingMeta(true);
                  }}
                >
                  <PencilIcon className="size-4" />
                </IconButton>
              )}
            </div>
          )
        }
        description={undefined}
        breadcrumb={[
          { label: "Profiles", href: "/profiles" },
          { label: profile?.name ?? profileId },
        ]}
        actions={
          <div className="flex items-center gap-2">
            <Button
              type="button"
              variant="ghost"
              onClick={() => router.push(`/audit?profileId=${encodeURIComponent(profileId)}`)}
            >
              Audit
            </Button>
            <Button variant="danger" onClick={() => setShowDeleteModal(true)}>
              Delete
            </Button>
          </div>
        }
      />

      <PageContent>
        {error && (
          <Callout tone="danger" size="md" className="mb-6">
            {error}
          </Callout>
        )}

        {profile ? (
          <EditProfilePanel
            open={editingMeta}
            profile={profile}
            saving={updateMetaMutation.isPending}
            saveError={metaSaveError}
            onSave={saveMeta}
            onClose={() => {
              setMetaSaveError(null);
              setEditingMeta(false);
            }}
          />
        ) : null}

        <ConnectionInfoCard
          profile={profile}
          mcpUrl={mcpUrl}
          clientKey={clientKey}
          toggleEnabledPending={toggleEnabledMutation.isPending}
          onToggleEnabled={() => {
            if (!profile) return;
            toggleEnabledMutation.mutate(!profile.enabled);
          }}
          onEditAuth={() => {
            if (profile) {
              setAuthDraft(authDraftFromSettings(profile.dataPlaneAuth));
            }
            setShowAuthSettings(true);
          }}
          onOpenAuthHelp={() => setShowMcpAuthHelp(true)}
          showAuthSettings={showAuthSettings}
          authDraft={authDraft}
        />

        {/* Tabs */}
        <Tabs
          className="mb-6"
          items={
            [
              { value: "tools", label: "Tools" },
              { value: "sources", label: "Sources" },
              { value: "keys", label: "API keys" },
              { value: "security", label: "Security" },
              { value: "other", label: "MCP settings" },
            ] as const
          }
          value={activeTab}
          onChange={setActiveTab}
        />

        {/* Tab Content */}
        {activeTab === "sources" && (
          <SourcesTab
            profile={profile}
            loading={loading}
            onSaved={async () => {
              await invalidateProfile(queryClient, profileId);
              await invalidateProfiles(queryClient);
            }}
          />
        )}

        {activeTab === "tools" && (
          <ToolsNewTab
            key={profile ? profile.id : "loading"}
            profile={profile}
            surface={surface}
            surfaceError={surfaceError}
            probePending={probeMutation.isPending}
            onProbe={() => probeMutation.mutate()}
            toolsPending={updateEnabledToolsMutation.isPending}
            onSetToolEnabled={setToolEnabled}
          />
        )}

        {activeTab === "other" && (
          <McpSurfaceSection
            profile={profile}
            surface={surface}
            surfaceError={surfaceError}
            probePending={probeMutation.isPending}
            onProbe={() => probeMutation.mutate()}
          />
        )}

        {activeTab === "security" && (
          <SecurityTab key={profile?.id ?? "loading"} profile={profile} />
        )}

        {/* `Transforms` and `Tool calls` tabs removed (merged into Tools). */}

        {activeTab === "keys" && (
          <ProfileKeysSection
            profileId={profileId}
            mcpUrl={mcpUrl}
            profileApiKeys={profileApiKeys}
            loading={apiKeysQuery.isPending}
          />
        )}
      </PageContent>

      <ConfirmModal
        open={showDeleteModal}
        onClose={() => setShowDeleteModal(false)}
        onConfirm={() => deleteMutation.mutate()}
        title="Delete profile?"
        description={`This will permanently delete "${profile?.name ?? profileId}". This action cannot be undone.`}
        requireText={deleteRequireText}
        confirmLabel="Delete profile"
        danger
        loading={deleteMutation.isPending}
      />

      <ConfirmModal
        open={!!confirmWeakAuthMode}
        onClose={() => setConfirmWeakAuthMode(null)}
        onConfirm={() => {
          if (!confirmWeakAuthMode) return;
          updateAuthMutation.mutate(confirmWeakAuthMode);
          setConfirmWeakAuthMode(null);
        }}
        title={
          confirmWeakAuthMode?.mode === "disabled"
            ? "Disable profile auth?"
            : "Change profile auth?"
        }
        description={
          confirmWeakAuthMode?.mode === "disabled"
            ? "This will expose your MCP endpoint without authentication. Only do this for local/dev or behind a trusted reverse proxy/network boundary."
            : "Confirm this authentication change."
        }
        requireText={confirmWeakAuthMode?.mode === "disabled" ? "disable auth" : undefined}
        confirmLabel={confirmWeakAuthMode?.mode === "disabled" ? "Disable auth" : "Apply"}
        danger={confirmWeakAuthMode?.mode === "disabled"}
        loading={updateAuthMutation.isPending}
      />

      <Modal
        open={showAuthSettings}
        onClose={() => {
          setShowAuthSettings(false);
          if (profile) {
            setAuthDraft(authDraftFromSettings(profile.dataPlaneAuth));
          }
        }}
        title="Profile auth"
        description="Controls authentication for this profile’s MCP endpoint."
        size="lg"
      >
        {!profile || !authDraft ? (
          <div className="flex items-center gap-2 text-sm text-muted">
            <Spinner size="sm" />
            Loading…
          </div>
        ) : (
          <div className="space-y-4">
            <div className="space-y-1.5">
              <Select
                label="Mode"
                value={authDraft.mode}
                disabled={updateAuthMutation.isPending}
                onChange={(e) => {
                  const nextMode = e.target.value as typeof authDraft.mode;
                  const next: AuthDraft = { ...authDraft, mode: nextMode };
                  setAuthDraft(next);
                }}
              >
                <option value="apiKey">API key</option>
                <option value="oauth" disabled={oauthConfigured === false}>
                  OAuth
                </option>
                <option value="disabled">Disabled (not recommended)</option>
              </Select>
              <div className="text-xs text-faint">
                API keys and OAuth access tokens are checked on every request. Compatible MCP
                clients discover and open the OAuth flow automatically.
              </div>
              {authDraft.mode === "oauth" && oauthConfigured === false ? (
                <Callout tone="info" className="mt-2">
                  OAuth is unavailable. Configure UNRELATED_GATEWAY_PUBLIC_DATA_BASE_URL and
                  UNRELATED_GATEWAY_OAUTH_ISSUER on the Gateway, or choose a different mode.
                </Callout>
              ) : null}

              {authDraft.mode === "disabled" ? (
                <Callout tone="danger" title="No auth (not recommended)" className="mt-2">
                  Anyone with the profile URL can call tools. Use only for local/dev or when the
                  data plane is protected by a trusted reverse proxy/network boundary.
                </Callout>
              ) : null}
            </div>

            {authDraft.mode === "apiKey" ? (
              <Toggle
                checked={authDraft.acceptXApiKey}
                disabled={updateAuthMutation.isPending}
                onChange={(checked) => {
                  setAuthDraft({ ...authDraft, acceptXApiKey: checked });
                }}
                label="Accept x-api-key header"
                description="Allows clients to use x-api-key instead of the preferred Authorization header."
              />
            ) : null}

            {authDraft.mode === "oauth" ? (
              <div className="space-y-2">
                <Input
                  label="Required scopes"
                  value={authDraft.requiredScopes.join(" ")}
                  onChange={(event) => {
                    const requiredScopes = event.target.value.split(/[\s,]+/).filter(Boolean);
                    setAuthDraft({ ...authDraft, requiredScopes });
                  }}
                  placeholder="mcp:access"
                  disabled={updateAuthMutation.isPending}
                />
                <p className="text-xs text-faint">
                  Every listed scope is required. Separate scopes with spaces or commas.
                </p>
              </div>
            ) : null}

            <ModalActions>
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  // Cancel/discard changes.
                  setShowAuthSettings(false);
                  if (profile) {
                    setAuthDraft(authDraftFromSettings(profile.dataPlaneAuth));
                  }
                }}
                disabled={updateAuthMutation.isPending}
              >
                Cancel
              </Button>
              <Button
                type="button"
                variant="primary"
                loading={updateAuthMutation.isPending}
                disabled={
                  updateAuthMutation.isPending ||
                  !authIsDirty ||
                  (authDraft.mode === "oauth" &&
                    (oauthConfigured === false || authDraft.requiredScopes.length === 0))
                }
                onClick={() => {
                  if (authDraft.mode === "oauth" && oauthConfigured === false) return;
                  const changingMode = authDraft.mode !== profile.dataPlaneAuth.mode;
                  const weak = authDraft.mode === "disabled";
                  if (changingMode && weak) {
                    setConfirmWeakAuthMode(authDraft);
                    return;
                  }
                  updateAuthMutation.mutate(authDraft);
                }}
              >
                Apply
              </Button>
            </ModalActions>
          </div>
        )}
      </Modal>

      <Modal
        open={showMcpAuthHelp}
        onClose={() => setShowMcpAuthHelp(false)}
        title="MCP client auth (how to connect)"
        description="How MCP clients authenticate to this profile’s MCP endpoint."
        size="lg"
      >
        <div className="space-y-4">
          <Callout tone="neutral" size="md" title="Where credentials go">
            If auth is enabled, your MCP client sends credentials as HTTP headers to{" "}
            <code className="rounded bg-raised px-1.5 py-0.5 font-mono text-xs text-fg">
              {mcpUrl}
            </code>
            . Most clients configure headers per{" "}
            <code className="rounded bg-raised px-1.5 py-0.5 font-mono text-xs text-fg">
              mcpServers
            </code>{" "}
            entry, so you can have multiple servers in one file with different auth.
          </Callout>

          <Callout tone="neutral" size="md" title="Recommended modes">
            Both <span className="font-medium text-fg">API key</span> and{" "}
            <span className="font-medium text-fg">OAuth</span> authenticate every request. Use OAuth
            for standards-based login and centrally issued access tokens; use API keys for simpler
            service credentials.
          </Callout>

          {profile?.dataPlaneAuth.mode === "apiKey" ? (
            <Callout tone="neutral" size="md" title="API key header">
              <div className="text-sm text-muted">
                Preferred:
                <div className="mt-2 rounded-md border border-edge bg-well p-3 font-mono text-xs text-fg">
                  Authorization: Bearer &lt;api_key_secret&gt;
                </div>
                {profile.dataPlaneAuth.acceptXApiKey ? (
                  <>
                    <div className="mt-3">Alternative (if enabled on this profile):</div>
                    <div className="mt-2 rounded-md border border-edge bg-well p-3 font-mono text-xs text-fg">
                      x-api-key: &lt;api_key_secret&gt;
                    </div>
                  </>
                ) : null}
              </div>
            </Callout>
          ) : profile?.dataPlaneAuth.mode === "oauth" ? (
            <Callout tone="neutral" size="md" title="OAuth discovery">
              <div className="mt-3 text-sm text-muted">
                Compatible MCP clients discover this protected resource and open the OAuth flow
                automatically. Do not add a manually supplied JWT header to the generated client
                configuration.
              </div>
              {protectedResourceMetadataUrl ? (
                <div className="mt-3 break-all rounded-md border border-edge bg-well p-3 font-mono text-xs text-fg">
                  {protectedResourceMetadataUrl}
                </div>
              ) : null}
              <p className="mt-3 text-sm text-muted">
                Required scopes: {profile.dataPlaneAuth.requiredScopes.join(" ")}
              </p>
            </Callout>
          ) : (
            <Callout tone="neutral" size="md" title="No auth">
              <p className="text-sm text-muted">
                This profile’s data-plane auth is disabled. No credentials are required.
              </p>
              <div className="mt-3 text-sm text-muted">
                If you need SSO, ask your administrator to configure OAuth for the Gateway.
              </div>
            </Callout>
          )}

          <Callout tone="neutral" size="md" title="Troubleshooting">
            Some MCP clients/tools may not support custom headers for streamable HTTP yet. If you
            see auth failures even with the right token/key, try another client or a newer version
            that supports per-server headers.
          </Callout>

          <ModalActions className="pt-0 border-t-0">
            <Button type="button" variant="primary" onClick={() => setShowMcpAuthHelp(false)}>
              Got it
            </Button>
          </ModalActions>
        </div>
      </Modal>
    </AppShell>
  );
}
