import { Suspense } from "react";
import { AuditClient } from "./_components/audit-client";

export const dynamic = "force-dynamic";

export default function AuditPage({
  searchParams,
}: {
  searchParams?: Record<string, string | string[] | undefined>;
}) {
  const profileIdParam = searchParams?.profileId;
  const profileId =
    typeof profileIdParam === "string" && profileIdParam.trim() ? profileIdParam.trim() : undefined;

  return (
    <Suspense>
      <AuditClient initialProfileId={profileId} />
    </Suspense>
  );
}
