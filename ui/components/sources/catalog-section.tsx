"use client";

import { useMemo, useState } from "react";
import { Button, Input, SectionCard } from "@/components/ui";

const PAGE_SIZE = 50;
export type CatalogEntry = { id: string; description?: string | null };

export function CatalogSection({ title, items }: { title: string; items: CatalogEntry[] }) {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    return items.filter((item) =>
      `${item.id} ${item.description ?? ""}`.toLowerCase().includes(query),
    );
  }, [items, search]);
  const lastPage = Math.max(0, Math.ceil(filtered.length / PAGE_SIZE) - 1);
  const currentPage = Math.min(page, lastPage);
  const visible = filtered.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);
  return (
    <SectionCard
      title={title}
      right={<span className="font-mono text-xs text-faint">{items.length}</span>}
      bodyClassName="space-y-3"
    >
      {items.length ? (
        <Input
          label={`Search ${title.toLowerCase()}`}
          value={search}
          onChange={(event) => {
            setSearch(event.target.value);
            setPage(0);
          }}
        />
      ) : null}
      {visible.length ? (
        visible.map((item) => (
          <div key={item.id} className="rounded-md border border-edge bg-well px-3 py-2">
            <div className="break-all font-mono text-xs text-fg">{item.id}</div>
            {item.description ? (
              <div className="mt-1 text-xs text-faint">{item.description}</div>
            ) : null}
          </div>
        ))
      ) : (
        <p className="text-sm text-faint">
          {items.length ? "No matching entries." : `No ${title.toLowerCase()} discovered.`}
        </p>
      )}
      {lastPage > 0 ? (
        <nav
          aria-label={`${title} pages`}
          className="flex flex-wrap items-center justify-between gap-2"
        >
          <Button
            variant="secondary"
            size="sm"
            disabled={currentPage === 0}
            onClick={() => setPage(currentPage - 1)}
          >
            Previous
          </Button>
          <span className="text-xs text-muted">
            Page {currentPage + 1} of {lastPage + 1} · {filtered.length} entries
          </span>
          <Button
            variant="secondary"
            size="sm"
            disabled={currentPage === lastPage}
            onClick={() => setPage(currentPage + 1)}
          >
            Next
          </Button>
        </nav>
      ) : null}
    </SectionCard>
  );
}
