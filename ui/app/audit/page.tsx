import { Suspense } from "react";
import { AuditClient } from "./_components/audit-client";

export const dynamic = "force-dynamic";

export default async function AuditPage({
  searchParams,
}: {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
}) {
  const profileIdParam = (await searchParams)?.profileId;
  const profileId =
    typeof profileIdParam === "string" && profileIdParam.trim() ? profileIdParam.trim() : undefined;

  return (
    <Suspense>
      <AuditClient initialProfileId={profileId} />
    </Suspense>
  );
}
