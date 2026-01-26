"use client";

import { useMemo } from "react";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import type { Profile } from "@/src/lib/types";
import { useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { qk } from "@/src/lib/queryKeys";
import * as tenantApi from "@/src/lib/tenantApi";
import { useToastStore } from "@/src/lib/toast-store";
import { authModeTone, formatDataPlaneAuthMode } from "@/src/lib/display";
import { buildPutProfileBody } from "@/src/lib/profilePut";
import { GATEWAY_DATA_BASE } from "@/src/lib/env";
import { useCopyToClipboard } from "@/src/lib/useCopyToClipboard";
import { Toggle } from "@/components/ui";
import {
  CheckCircleIcon,
  CheckIcon,
  ChevronRightIcon,
  CopyIcon,
  GridIcon,
  PlusIcon,
} from "@/components/icons";

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
          <button
            onClick={() => router.push("/profiles/new")}
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-b from-violet-500 to-violet-600 text-white font-medium text-sm shadow-lg shadow-violet-500/25 hover:from-violet-400 hover:to-violet-500 transition-all duration-150"
          >
            <PlusIcon className="w-4 h-4" />
            Create Profile
          </button>
        }
      />

      <PageContent>
        {/* Stats row */}
        <div className="grid grid-cols-2 gap-4 mb-6">
          <StatCard
            label="Total Profiles"
            value={stats.total.toString()}
            icon={<GridIcon className="w-5 h-5" />}
          />
          <StatCard
            label="Active"
            value={stats.active.toString()}
            icon={<CheckCircleIcon className="w-5 h-5" />}
            color="emerald"
          />
        </div>

        {/* Profiles list */}
        {profilesQuery.isPending && <div className="text-sm text-zinc-400">Loading…</div>}
        {profilesQuery.error && (
          <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-200">
            {profilesQuery.error instanceof Error
              ? profilesQuery.error.message
              : "Failed to load profiles"}
          </div>
        )}
        {!profilesQuery.isPending && !profilesQuery.error && (
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

function StatCard({
  label,
  value,
  icon,
  color = "violet",
}: {
  label: string;
  value: string;
  icon: React.ReactNode;
  color?: "violet" | "emerald";
}) {
  const colorClasses = {
    violet: "text-violet-400 bg-violet-500/10",
    emerald: "text-emerald-400 bg-emerald-500/10",
  };

  return (
    <div className="rounded-xl border border-zinc-800/60 bg-zinc-900/40 p-4">
      <div className="flex items-center gap-3">
        <div className={`p-2 rounded-lg ${colorClasses[color]}`}>{icon}</div>
        <div>
          <div className="text-2xl font-bold text-white">{value}</div>
          <div className="text-xs text-zinc-500">{label}</div>
        </div>
      </div>
    </div>
  );
}

function ProfileCard({ profile, mcpUrl }: { profile: Profile; mcpUrl: string }) {
  const { copied, copy } = useCopyToClipboard(mcpUrl);
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

  const handleCopy = async () => {
    await copy();
  };

  const enabled = profile.enabled;
  const tone = authModeTone(profile.dataPlaneAuth.mode);
  const authLabel = formatDataPlaneAuthMode(profile.dataPlaneAuth.mode);
  const sourcesCount = profile.sources.length + profile.upstreams.length;

  const cardCls = enabled
    ? "border-emerald-500/20 bg-zinc-900/40 hover:border-emerald-500/30"
    : "border-zinc-800/60 bg-zinc-900/30 hover:border-zinc-700/80";

  const urlCls = enabled
    ? "bg-emerald-500/5 border-emerald-500/25"
    : "bg-zinc-950/40 border-zinc-800/60";

  return (
    <a
      href={`/profiles/${profile.id}`}
      className={`block rounded-xl border p-5 transition-all duration-150 group ${cardCls}`}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3">
            <h3 className="text-base font-semibold text-zinc-100 group-hover:text-white transition-colors">
              {profile.name}
            </h3>
            <span
              className={`px-2 py-0.5 rounded-full text-xs font-medium border ${
                tone === "violet"
                  ? "bg-violet-500/10 text-violet-400 border-violet-500/20"
                  : tone === "amber"
                    ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
                    : "bg-zinc-500/10 text-zinc-400 border-zinc-500/20"
              }`}
            >
              {authLabel}
            </span>

            <div className="ml-auto flex items-center gap-2">
              <div
                onClick={(e) => {
                  // Prevent the card link from navigating when toggling.
                  e.preventDefault();
                  e.stopPropagation();
                }}
              >
                <Toggle
                  checked={enabled}
                  onChange={(next) => toggleEnabledMutation.mutate(next)}
                  disabled={toggleEnabledMutation.isPending}
                  label={enabled ? "Enabled" : "Disabled"}
                  switchSide="right"
                />
              </div>
            </div>
          </div>
          {profile.description && (
            <p className="mt-1 text-sm text-zinc-500">{profile.description}</p>
          )}

          {/* MCP URL */}
          <div className="mt-3 flex items-center gap-2">
            <div className={`flex-1 min-w-0 px-4 py-2.5 rounded-lg border ${urlCls}`}>
              <code
                className={`text-sm font-mono truncate block ${
                  enabled ? "text-emerald-200" : "text-zinc-300"
                }`}
              >
                {mcpUrl}
              </code>
            </div>
            <button
              onClick={(e) => {
                e.preventDefault();
                handleCopy();
              }}
              className="shrink-0 px-3 py-2.5 rounded-lg bg-zinc-800 text-zinc-300 text-xs font-medium hover:bg-zinc-700 hover:text-white transition-colors"
            >
              {copied ? (
                <span className="flex items-center gap-1.5">
                  <CheckIcon className="w-3.5 h-3.5 text-emerald-400" />
                  Copied
                </span>
              ) : (
                <span className="flex items-center gap-1.5">
                  <CopyIcon className="w-3.5 h-3.5" />
                  Copy URL
                </span>
              )}
            </button>
          </div>
        </div>

        {/* Stats */}
        <div className="hidden sm:flex items-center gap-6 text-sm">
          <div className="text-center">
            <div className="text-lg font-semibold text-zinc-100">{sourcesCount}</div>
            <div className="text-xs text-zinc-500">Sources</div>
          </div>
          <ChevronRightIcon className="w-5 h-5 text-zinc-600 group-hover:text-zinc-400 transition-colors" />
        </div>
      </div>
    </a>
  );
}
