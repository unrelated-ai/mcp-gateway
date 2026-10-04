"use client";

import { useState } from "react";
import { useIsMutating } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { AppShell, PageContent, PageHeader } from "@/components/layout";
import { Input } from "@/components/ui";
import { HttpSourceEditor } from "@/components/sources/http-source-editor";

export default function NewHttpSourcePage() {
  const [name, setName] = useState("");
  const saving = useIsMutating({ mutationKey: ["toolSourceSave", name] }) > 0;
  const router = useRouter();
  return (
    <AppShell>
      <PageHeader
        title="Add HTTP source"
        description="Turn API requests into MCP tools."
        breadcrumb={[{ label: "Sources", href: "/sources" }, { label: "New HTTP source" }]}
      />
      <PageContent width="5xl" className="space-y-6">
        <Input
          label="Source name"
          value={name}
          disabled={saving}
          onChange={(event) => setName(event.target.value)}
          placeholder="billing_api"
          hint="Letters, digits, underscores, and dashes. Used when attaching the source to profiles."
        />
        <HttpSourceEditor
          sourceId={name}
          onSaved={async () =>
            router.replace(`/sources/tool-sources/${encodeURIComponent(name.trim())}`)
          }
        />
      </PageContent>
    </AppShell>
  );
}
