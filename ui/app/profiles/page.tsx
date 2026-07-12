"use client";

import { useMemo } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import {
  Badge,
  Button,
  Callout,
  EmptyState,
  EndpointWell,
  SkeletonRows,
  Stat,
  Toggle,
} from "@/components/ui";
import { ChevronRightIcon, GridIcon, PlusIcon } from "@/components/icons";
import type { Profile } from "@/src/lib/types";
import { qk } from "@/src/lib/queryKeys";
import * as tenantApi from "@/src/lib/tenantApi";
import { useToastStore } from "@/src/lib/toast-store";
import { authModeTone, formatDataPlaneAuthMode } from "@/src/lib/display";
import { buildPutProfileBody } from "@/src/lib/profilePut";
import { GATEWAY_DATA_BASE } from "@/src/lib/env";

const EMPTY_PROFILES: Profile[] = [];

export default function ProfilesPage() {
  const router = useRouter();
  const dataBase = GATEWAY_DATA_BASE;
  const profilesQuery = useQuery({
    queryKey: qk.profiles(),
    queryFn: tenantApi.listProfiles,
  });
  const profiles: Profile[] = (profilesQuery.data?.profiles ?? EMPTY_PROFILES) as Profile[];

  const stats = useMemo(() => {
    const total = profiles.length;
    const active = profiles.filter((p) => p.enabled).length;
    return { total, active };
  }, [profiles]);

  return (
    <AppShell>
      <PageHeader
        title="Profiles"
        description="Virtual MCP servers with their own endpoints, auth, and tool configurations"
        actions={
          <Button onClick={() => router.push("/profiles/new")}>
            <PlusIcon className="size-4" />
            Create profile
          </Button>
        }
      />

      <PageContent>
        {/* Stats row */}
        <div className="mb-6 grid grid-cols-2 gap-4">
          <Stat label="Profiles" value={stats.total} />
          <Stat label="Active" value={stats.active} tone={stats.active > 0 ? "ok" : "neutral"} />
        </div>

        {profilesQuery.isPending && <SkeletonRows rows={3} />}
        {profilesQuery.error && (
          <Callout tone="danger" title="Failed to load profiles" size="md">
            {profilesQuery.error instanceof Error ? profilesQuery.error.message : "Unknown error"}
          </Callout>
        )}
        {!profilesQuery.isPending && !profilesQuery.error && profiles.length === 0 && (
          <EmptyState
            icon={<GridIcon className="size-5" />}
            title="No profiles yet"
            description="Create a profile to get an MCP endpoint your agents can connect to."
            action={{ label: "Create profile", onClick: () => router.push("/profiles/new") }}
          />
        )}
        {!profilesQuery.isPending && !profilesQuery.error && profiles.length > 0 && (
          <div className="space-y-3">
            {profiles.map((profile) => (
              <ProfileCard
                key={profile.id}
                profile={profile}
                mcpUrl={`${dataBase}/${profile.id}/mcp`}
              />
            ))}
          </div>
        )}
      </PageContent>
    </AppShell>
  );
}

function ProfileCard({ profile, mcpUrl }: { profile: Profile; mcpUrl: string }) {
  const queryClient = useQueryClient();
  const pushToast = useToastStore((s) => s.push);

  const toggleEnabledMutation = useMutation({
    mutationFn: async (enabled: boolean) => {
      await tenantApi.putProfile(profile.id, buildPutProfileBody(profile, { enabled }));
      return enabled;
    },
    onMutate: async (enabled) => {
      await queryClient.cancelQueries({ queryKey: qk.profiles() });
      const prev = queryClient.getQueryData<{ profiles: Profile[] }>(qk.profiles());
      queryClient.setQueryData(qk.profiles(), (old: { profiles: Profile[] } | undefined) => {
        if (!old) return old;
        return {
          ...old,
          profiles: old.profiles.map((p) => (p.id === profile.id ? { ...p, enabled } : p)),
        };
      });
      return { prev };
    },
    onError: (e, _enabled, ctx) => {
      if (ctx?.prev) queryClient.setQueryData(qk.profiles(), ctx.prev);
      pushToast({
        variant: "error",
        message: e instanceof Error ? e.message : "Failed to update profile",
      });
    },
    onSettled: async () => {
      await queryClient.invalidateQueries({ queryKey: qk.profiles() });
    },
  });

  const enabled = profile.enabled;
  const sourcesCount = profile.sources.length + profile.upstreams.length;

  return (
    // Stretched-link card: the title Link covers the card via ::after, and the
    // interactive controls (toggle, copy) sit above it — no nested interactives.
    <div className="group relative rounded-lg border border-edge bg-surface p-5 transition-colors duration-150 hover:border-edge-strong">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-3">
            <Link
              href={`/profiles/${profile.id}`}
              className="text-base font-semibold text-fg after:absolute after:inset-0 after:rounded-lg focus-visible:outline-none focus-visible:after:ring-2 focus-visible:after:ring-accent"
            >
              {profile.name}
            </Link>
            <Badge tone={authModeTone(profile.dataPlaneAuth.mode)}>
              {formatDataPlaneAuthMode(profile.dataPlaneAuth.mode)}
            </Badge>

            <div className="relative z-10 ml-auto flex items-center gap-2">
              <Toggle
                checked={enabled}
                onChange={(next) => toggleEnabledMutation.mutate(next)}
                disabled={toggleEnabledMutation.isPending}
                label={enabled ? "Enabled" : "Disabled"}
                switchSide="right"
              />
            </div>
          </div>
          {profile.description && <p className="mt-1 text-sm text-muted">{profile.description}</p>}

          <div className="relative z-10 mt-3">
            <EndpointWell url={mcpUrl} live={enabled} />
          </div>
        </div>

        {/* Stats */}
        <div className="hidden items-center gap-5 self-center sm:flex">
          <div className="text-center">
            <div className="font-mono text-lg font-medium text-fg">{sourcesCount}</div>
            <div className="eyebrow">Sources</div>
          </div>
          <ChevronRightIcon className="size-5 text-faint transition-colors group-hover:text-muted" />
        </div>
      </div>
    </div>
  );
}
