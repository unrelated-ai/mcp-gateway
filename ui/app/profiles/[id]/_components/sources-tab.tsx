"use client";

import Link from "next/link";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Callout, SectionCard, Skeleton, SkeletonRows, Toggle } from "@/components/ui";
import type { Profile } from "@/src/lib/types";
import * as tenantApi from "@/src/lib/tenantApi";
import { qk } from "@/src/lib/queryKeys";
import { useToastStore } from "@/src/lib/toast-store";

type UpstreamListItem = { id: string; owner: string; enabled: boolean };
type ToolSourceListItem = { id: string; type: string; enabled: boolean };

export function SourcesTab({
  profile,
  loading,
  onSaved,
}: {
  profile: Profile | null;
  loading: boolean;
  onSaved: () => Promise<void> | void;
}) {
  const queryClient = useQueryClient();
  const pushToast = useToastStore((s) => s.push);

  const upstreamsQuery = useQuery({
    queryKey: qk.upstreams(),
    queryFn: tenantApi.listUpstreams,
  });
  const toolSourcesQuery = useQuery({
    queryKey: qk.toolSources(),
    queryFn: tenantApi.listToolSources,
  });

  const upstreams: UpstreamListItem[] = (upstreamsQuery.data?.upstreams ?? []).map((u) => ({
    id: u.id,
    owner: u.owner,
    enabled: u.enabled,
  }));
  const sources: ToolSourceListItem[] = (toolSourcesQuery.data?.sources ?? []).map((s) => ({
    id: s.id,
    type: s.type,
    enabled: s.enabled,
  }));

  const [selectedUpstreams, setSelectedUpstreams] = useState<string[]>(
    () => profile?.upstreams ?? [],
  );
  const [selectedSources, setSelectedSources] = useState<string[]>(() => profile?.sources ?? []);
  const [allowPartialUpstreams, setAllowPartialUpstreams] = useState<boolean>(
    () => profile?.allowPartialUpstreams ?? true,
  );

  const toggleId = (list: string[], id: string) =>
    list.includes(id) ? list.filter((x) => x !== id) : [...list, id];

  const [saveError, setSaveError] = useState<string | null>(null);

  const saveMutation = useMutation({
    mutationFn: async (next: {
      allowPartialUpstreams: boolean;
      upstreams: string[];
      sources: string[];
    }) => {
      if (!profile) throw new Error("Profile not loaded");
      await tenantApi.updateProfile(profile.id, {
        allowPartialUpstreams: next.allowPartialUpstreams,
        upstreams: next.upstreams,
        sources: next.sources,
      });
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: qk.profile(profile?.id ?? "") });
      await queryClient.invalidateQueries({ queryKey: qk.profiles() });
      setSaveError(null);
      await onSaved();
    },
    onError: (e) => {
      setSaveError(e instanceof Error ? e.message : "Failed to update attachments");
      pushToast({
        variant: "error",
        message: e instanceof Error ? e.message : "Failed to update attachments",
      });
    },
  });

  if (loading || !profile) {
    return <SkeletonRows rows={2} />;
  }

  if (
    !upstreamsQuery.isPending &&
    !toolSourcesQuery.isPending &&
    upstreams.length === 0 &&
    sources.length === 0
  ) {
    return (
      <div className="rounded-lg border border-edge bg-surface p-6">
        <div className="text-sm font-semibold text-fg">No sources available yet</div>
        <div className="mt-2 text-sm text-muted">
          You must first define tenant-level sources, then attach them to profiles. Go to{" "}
          <Link href="/sources" className="text-accent underline hover:text-accent-hover">
            Sources
          </Link>
          .
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-4">
        <div>
          <div className="eyebrow">Attachments</div>
        </div>
      </div>

      {saveError ? <Callout tone="danger">{saveError}</Callout> : null}

      <div className="rounded-lg border border-edge bg-surface p-5">
        <div className="flex items-center justify-between gap-4">
          <div>
            <div className="text-sm font-semibold text-fg">Allow partial upstreams</div>
            <div className="mt-1 text-xs text-faint">
              If some upstream endpoints are down, still serve what’s available.
            </div>
          </div>
          <Toggle
            checked={allowPartialUpstreams}
            onChange={(checked) => {
              setAllowPartialUpstreams(checked);
              saveMutation.mutate({
                allowPartialUpstreams: checked,
                upstreams: selectedUpstreams,
                sources: selectedSources,
              });
            }}
          />
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <SectionCard
          title="Upstreams"
          subtitle="Streamable HTTP MCP servers."
          bodyClassName="space-y-2"
        >
          <>
            {upstreamsQuery.isPending ? (
              <Skeleton className="h-10 w-full" />
            ) : upstreamsQuery.error ? (
              <div className="text-sm text-danger">
                {upstreamsQuery.error instanceof Error
                  ? upstreamsQuery.error.message
                  : "Failed to load upstreams"}
              </div>
            ) : upstreams.length === 0 ? (
              <div className="text-sm text-faint">
                No upstreams defined. Create one on{" "}
                <Link href="/sources" className="text-accent underline hover:text-accent-hover">
                  Sources
                </Link>
                .
              </div>
            ) : (
              upstreams.map((u) => (
                <div key={`${u.owner}:${u.id}`} className="flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <div className="text-sm text-fg truncate font-mono">{u.id}</div>
                    <div className="text-xs text-faint">owner: {u.owner}</div>
                  </div>
                  <Toggle
                    checked={selectedUpstreams.includes(u.id)}
                    onChange={() => {
                      const nextUpstreams = toggleId(selectedUpstreams, u.id);
                      setSelectedUpstreams(nextUpstreams);
                      saveMutation.mutate({
                        allowPartialUpstreams,
                        upstreams: nextUpstreams,
                        sources: selectedSources,
                      });
                    }}
                  />
                </div>
              ))
            )}
          </>
        </SectionCard>

        <SectionCard
          title="Tool sources"
          subtitle="HTTP DSL and OpenAPI sources."
          bodyClassName="space-y-2"
        >
          <>
            {toolSourcesQuery.isPending ? (
              <Skeleton className="h-10 w-full" />
            ) : toolSourcesQuery.error ? (
              <div className="text-sm text-danger">
                {toolSourcesQuery.error instanceof Error
                  ? toolSourcesQuery.error.message
                  : "Failed to load tool sources"}
              </div>
            ) : sources.length === 0 ? (
              <div className="text-sm text-faint">
                No tool sources defined. Create one on{" "}
                <Link href="/sources" className="text-accent underline hover:text-accent-hover">
                  Sources
                </Link>
                .
              </div>
            ) : (
              sources.map((s) => (
                <div key={s.id} className="flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <div className="text-sm text-fg truncate font-mono">{s.id}</div>
                    <div className="text-xs text-faint">type: {s.type}</div>
                  </div>
                  <Toggle
                    checked={selectedSources.includes(s.id)}
                    onChange={() => {
                      const nextSources = toggleId(selectedSources, s.id);
                      setSelectedSources(nextSources);
                      saveMutation.mutate({
                        allowPartialUpstreams,
                        upstreams: selectedUpstreams,
                        sources: nextSources,
                      });
                    }}
                  />
                </div>
              ))
            )}
          </>
        </SectionCard>
      </div>
    </div>
  );
}
