"use client";

import { useMemo, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import type { Profile } from "@/src/lib/types";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Callout, ConfirmModal, Modal, ModalActions, Toggle } from "@/components/ui";
import { qk } from "@/src/lib/queryKeys";
import * as tenantApi from "@/src/lib/tenantApi";
import type { ProfileSurface } from "@/src/lib/tenantApi";
import { useToastStore } from "@/src/lib/toast-store";
import { buildPutProfileBody } from "@/src/lib/profilePut";
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
  const [authDraft, setAuthDraft] = useState<{
    mode: "disabled" | "apiKeyInitializeOnly" | "apiKeyEveryRequest" | "jwtEveryRequest";
    acceptXApiKey: boolean;
  } | null>(null);
  const [confirmWeakAuthMode, setConfirmWeakAuthMode] = useState<{
    mode: "disabled" | "apiKeyInitializeOnly" | "apiKeyEveryRequest" | "jwtEveryRequest";
    acceptXApiKey: boolean;
  } | null>(null);
  const mcpUrl = `${GATEWAY_DATA_BASE}/${profileId}/mcp`;

  const queryClient = useQueryClient();
  const pushToast = useToastStore((s) => s.push);

  type GatewayStatusResponse =
    | {
        ok: true;
        status: {
          oidcConfigured?: boolean;
          oidcIssuer?: string;
        };
      }
    | { ok: false; error?: string; status?: number };

  const gatewayStatusQuery = useQuery({
    queryKey: qk.gatewayStatus(),
    queryFn: async () => {
      const res = await fetch("/api/gateway/status", { cache: "no-store" });
      return (await res.json()) as GatewayStatusResponse;
    },
  });
  const oidcConfigured =
    gatewayStatusQuery.isPending || !gatewayStatusQuery.data
      ? null
      : gatewayStatusQuery.data.ok
        ? (gatewayStatusQuery.data.status.oidcConfigured ?? null)
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
    mutationFn: async (next: {
      mode: Profile["dataPlaneAuth"]["mode"];
      acceptXApiKey: boolean;
    }) => {
      if (!profile) throw new Error("Profile not loaded");
      await tenantApi.putProfile(profile.id, buildPutProfileBody(profile, { dataPlaneAuth: next }));
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
      authDraft.mode !== profile.dataPlaneAuth.mode ||
      authDraft.acceptXApiKey !== profile.dataPlaneAuth.acceptXApiKey
    );
  }, [authDraft, profile]);

  const toggleEnabledMutation = useMutation({
    mutationFn: async (enabled: boolean) => {
      if (!profile) throw new Error("Profile not loaded");
      await tenantApi.putProfile(profile.id, buildPutProfileBody(profile, { enabled }));
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
      await tenantApi.putProfile(
        profile.id,
        buildPutProfileBody(profile, {
          name: next.name.trim(),
          description: next.description.trim() ? next.description : null,
        }),
      );
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
      await tenantApi.putProfile(profile.id, buildPutProfileBody(profile, { tools: nextTools }));
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
                <button
                  type="button"
                  onClick={() => {
                    setMetaSaveError(null);
                    setEditingMeta(true);
                  }}
                  className="inline-flex items-center justify-center w-8 h-8 rounded-lg text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60 transition-colors"
                  aria-label="Edit profile name and description"
                >
                  <PencilIcon className="w-4 h-4" />
                </button>
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
            <button
              type="button"
              onClick={() => router.push(`/audit?profileId=${encodeURIComponent(profileId)}`)}
              className="px-4 py-2 rounded-lg text-sm font-medium text-violet-300 hover:text-violet-200 hover:bg-violet-500/10 transition-colors"
            >
              Audit
            </button>
            <button
              onClick={() => setShowDeleteModal(true)}
              className="px-4 py-2 rounded-lg text-sm font-medium text-red-400 hover:text-red-300 hover:bg-red-500/10 transition-colors"
            >
              Delete
            </button>
          </div>
        }
      />

      <PageContent>
        {error && (
          <div className="mb-6 rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-200">
            {error}
          </div>
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
              setAuthDraft({
                mode: profile.dataPlaneAuth.mode,
                acceptXApiKey: profile.dataPlaneAuth.acceptXApiKey,
              });
            }
            setShowAuthSettings(true);
          }}
          onOpenAuthHelp={() => setShowMcpAuthHelp(true)}
          showAuthSettings={showAuthSettings}
          authDraft={authDraft}
        />

        {/* Tabs */}
        <div className="flex items-center gap-1 border-b border-zinc-800/60 mb-6">
          {(
            [
              { key: "tools", label: "Tools" },
              { key: "sources", label: "Sources" },
              { key: "keys", label: "API Keys" },
              { key: "security", label: "Security" },
              { key: "other", label: "MCP Settings" },
            ] as const
          ).map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`px-4 py-2.5 text-sm font-medium transition-colors relative ${
                activeTab === tab.key ? "text-white" : "text-zinc-500 hover:text-zinc-300"
              }`}
            >
              <span className="inline-flex items-center gap-2">{tab.label}</span>
              {activeTab === tab.key && (
                <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-violet-500 rounded-full" />
              )}
            </button>
          ))}
        </div>

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

        {activeTab === "security" && <SecurityTab profile={profile} />}

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
        confirmLabel="Delete Profile"
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
            : "Use API key (init only)?"
        }
        description={
          confirmWeakAuthMode?.mode === "disabled"
            ? "This will expose your MCP endpoint without authentication. Only do this for local/dev or behind a trusted reverse proxy/network boundary."
            : "This is a compatibility mode and is not recommended for internet-exposed deployments. After initialize, the session token can be replayed until it expires."
        }
        requireText={confirmWeakAuthMode?.mode === "disabled" ? "disable auth" : "init-only"}
        confirmLabel={confirmWeakAuthMode?.mode === "disabled" ? "Disable auth" : "Use init-only"}
        danger={confirmWeakAuthMode?.mode === "disabled"}
        loading={updateAuthMutation.isPending}
      />

      <Modal
        open={showAuthSettings}
        onClose={() => {
          setShowAuthSettings(false);
          if (profile) {
            setAuthDraft({
              mode: profile.dataPlaneAuth.mode,
              acceptXApiKey: profile.dataPlaneAuth.acceptXApiKey,
            });
          }
        }}
        title="Profile auth"
        description="Controls authentication for this profile’s MCP endpoint."
        size="lg"
      >
        {!profile || !authDraft ? (
          <div className="text-sm text-zinc-400">Loading…</div>
        ) : (
          <div className="space-y-4">
            <div className="space-y-1.5">
              <label className="block text-sm font-medium text-zinc-300">Mode</label>
              <select
                value={authDraft.mode}
                disabled={updateAuthMutation.isPending}
                onChange={(e) => {
                  const nextMode = e.target.value as typeof authDraft.mode;
                  const next = { ...authDraft, mode: nextMode };
                  setAuthDraft(next);
                }}
                className="w-full rounded-lg border border-zinc-700/80 bg-zinc-900/50 px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:ring-2 focus:ring-violet-500/50 focus:border-violet-500/50 hover:border-zinc-600/80"
              >
                <option value="apiKeyEveryRequest">API key (every request) — Recommended</option>
                <option value="jwtEveryRequest">JWT/OIDC (every request) — Recommended</option>
                <option value="apiKeyInitializeOnly">
                  API key (init only) — Compatibility (not recommended)
                </option>
                <option value="disabled">Disabled (not recommended)</option>
              </select>
              <div className="text-xs text-zinc-500">
                API key modes accept <span className="font-mono">Authorization: Bearer</span> and
                optionally <span className="font-mono">x-api-key</span>. JWT/OIDC requires a valid
                bearer token on every request.
              </div>
              {authDraft.mode === "jwtEveryRequest" && oidcConfigured === false ? (
                <div className="mt-2 rounded-lg border border-zinc-800/60 bg-zinc-950/30 p-3 text-xs text-zinc-400">
                  JWT/OIDC is unavailable because OIDC is not configured on the Gateway (missing
                  UNRELATED_GATEWAY_OIDC_ISSUER). Configure OIDC or choose a different mode.
                </div>
              ) : null}

              {authDraft.mode === "apiKeyInitializeOnly" ? (
                <Callout
                  tone="warning"
                  title="Compatibility mode (not recommended)"
                  className="mt-2 rounded-lg"
                >
                  After <span className="font-mono">initialize</span>, the{" "}
                  <span className="font-mono">Mcp-Session-Id</span> becomes sufficient for follow-up
                  requests. If that session token is leaked, it can be replayed until it expires.
                  Prefer “every request” modes for internet-exposed deployments.
                </Callout>
              ) : null}

              {authDraft.mode === "disabled" ? (
                <Callout
                  tone="danger"
                  title="No auth (not recommended)"
                  className="mt-2 rounded-lg"
                >
                  Anyone with the profile URL can call tools. Use only for local/dev or when the
                  data plane is protected by a trusted reverse proxy/network boundary.
                </Callout>
              ) : null}
            </div>

            <Toggle
              checked={authDraft.acceptXApiKey}
              disabled={updateAuthMutation.isPending}
              onChange={(checked) => {
                const next = { ...authDraft, acceptXApiKey: checked };
                setAuthDraft(next);
              }}
              label="Accept x-api-key header"
              description="Allows clients to send x-api-key instead of Authorization."
            />

            <ModalActions>
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  // Cancel/discard changes.
                  setShowAuthSettings(false);
                  if (profile) {
                    setAuthDraft({
                      mode: profile.dataPlaneAuth.mode,
                      acceptXApiKey: profile.dataPlaneAuth.acceptXApiKey,
                    });
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
                  (authDraft.mode === "jwtEveryRequest" && oidcConfigured === false)
                }
                onClick={() => {
                  if (authDraft.mode === "jwtEveryRequest" && oidcConfigured === false) return;
                  const changingMode = authDraft.mode !== profile.dataPlaneAuth.mode;
                  const weak =
                    authDraft.mode === "apiKeyInitializeOnly" || authDraft.mode === "disabled";
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
          <div className="rounded-xl border border-zinc-800/60 bg-zinc-950/40 p-4">
            <div className="text-sm font-semibold text-zinc-100">Where credentials go</div>
            <p className="mt-2 text-sm text-zinc-400">
              If auth is enabled, your MCP client sends credentials as HTTP headers to{" "}
              <code className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300">{mcpUrl}</code>.
              Most clients configure headers per{" "}
              <code className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300">mcpServers</code>{" "}
              entry, so you can have multiple servers in one file with different auth.
            </p>
          </div>

          <div className="rounded-xl border border-zinc-800/60 bg-zinc-950/40 p-4">
            <div className="text-sm font-semibold text-zinc-100">Recommended modes</div>
            <p className="mt-2 text-sm text-zinc-400">
              For production / internet-exposed profiles, prefer per-request authentication:
              <span className="ml-1 font-medium text-zinc-200">
                API key (every request)
              </span> or <span className="font-medium text-zinc-200">JWT/OIDC (every request)</span>
              . <span className="font-medium text-zinc-200">API key (init only)</span> is a
              compatibility mode and is not recommended.
            </p>
          </div>

          {profile?.dataPlaneAuth.mode.startsWith("apiKey") ? (
            <div className="rounded-xl border border-zinc-800/60 bg-zinc-950/40 p-4">
              <div className="text-sm font-semibold text-zinc-100">API key header</div>
              <div className="mt-2 text-sm text-zinc-400">
                Preferred:
                <div className="mt-2 rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 font-mono text-xs text-zinc-200">
                  Authorization: Bearer &lt;api_key_secret&gt;
                </div>
                {profile.dataPlaneAuth.acceptXApiKey ? (
                  <>
                    <div className="mt-3">Alternative (if enabled on this profile):</div>
                    <div className="mt-2 rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 font-mono text-xs text-zinc-200">
                      x-api-key: &lt;api_key_secret&gt;
                    </div>
                  </>
                ) : null}
              </div>
              {profile.dataPlaneAuth.mode === "apiKeyInitializeOnly" ? (
                <p className="mt-3 text-sm text-zinc-400">
                  Compatibility note: in “init only” mode the API key is required only for{" "}
                  <code className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300">
                    initialize
                  </code>
                  . After that, the client uses{" "}
                  <code className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300">
                    Mcp-Session-Id
                  </code>{" "}
                  for follow-up requests. This is less secure (session replay risk) and is not
                  recommended for internet-exposed deployments.
                </p>
              ) : null}
            </div>
          ) : profile?.dataPlaneAuth.mode.startsWith("jwt") ? (
            <div className="rounded-xl border border-zinc-800/60 bg-zinc-950/40 p-4">
              <div className="text-sm font-semibold text-zinc-100">JWT header</div>
              <div className="mt-2 rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 font-mono text-xs text-zinc-200">
                Authorization: Bearer &lt;jwt&gt;
              </div>
              <div className="mt-3 text-sm text-zinc-400">
                OIDC/JWT auth is available when configured on the Gateway. If you need SSO, contact
                your admin.
              </div>
            </div>
          ) : (
            <div className="rounded-xl border border-zinc-800/60 bg-zinc-950/40 p-4">
              <div className="text-sm font-semibold text-zinc-100">No auth</div>
              <p className="mt-2 text-sm text-zinc-400">
                This profile’s data-plane auth is disabled. No credentials are required.
              </p>
              <div className="mt-3 text-sm text-zinc-400">
                If you need SSO, the Gateway can support OIDC/JWT when configured (contact your
                admin).
              </div>
            </div>
          )}

          <div className="rounded-xl border border-zinc-800/60 bg-zinc-950/40 p-4">
            <div className="text-sm font-semibold text-zinc-100">Troubleshooting</div>
            <p className="mt-2 text-sm text-zinc-400">
              Some MCP clients/tools may not support custom headers for streamable HTTP yet. If you
              see auth failures even with the right token/key, try another client or a newer version
              that supports per-server headers.
            </p>
          </div>

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
