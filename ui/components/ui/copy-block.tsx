"use client";

import { useMemo, type ReactNode } from "react";
import { useCopyToClipboard } from "@/src/lib/useCopyToClipboard";
import { CheckIcon, CopyIcon } from "@/components/icons";

interface CopyBlockProps {
  value: string;
  label?: string;
  language?: "url" | "json" | "bash" | "text";
  compact?: boolean;
}

/**
 * Lightweight highlighting rendered as React nodes (never raw HTML), so
 * arbitrary server-provided values are safe to display.
 */
function highlight(value: string, language: CopyBlockProps["language"]): ReactNode {
  if (language === "url") {
    const match = value.match(/^(https?:\/\/)?([^/\s]+)(\/\S*)?$/);
    if (match) {
      const [, protocol = "", host = "", path = ""] = match;
      return (
        <>
          <span className="text-faint">{protocol}</span>
          <span className="text-accent">{host}</span>
          <span className="text-ok">{path}</span>
        </>
      );
    }
    return value;
  }
  if (language === "json") {
    // Tokenize just quoted strings; keys (followed by ":") get accent color.
    const parts = value.split(/("[^"]*")/g);
    return parts.map((part, i) => {
      if (!part.startsWith('"')) return <span key={i}>{part}</span>;
      const isKey = /^\s*:/.test(parts.slice(i + 1).join(""));
      return (
        <span key={i} className={isKey ? "text-accent" : "text-ok"}>
          {part}
        </span>
      );
    });
  }
  if (language === "bash") {
    return value.split("\n").map((line, i) => {
      const m = line.match(/^(\$|>)\s*(.*)$/);
      return (
        <span key={i}>
          {i > 0 && "\n"}
          {m ? (
            <>
              <span className="text-faint">{m[1]} </span>
              {m[2]}
            </>
          ) : (
            line
          )}
        </span>
      );
    });
  }
  return value;
}

export function CopyBlock({ value, label, language = "text", compact = false }: CopyBlockProps) {
  const { copied, copy } = useCopyToClipboard(value);
  const rendered = useMemo(() => highlight(value, language), [value, language]);

  if (compact) {
    return (
      <div className="group flex items-center gap-2">
        <code className="min-w-0 flex-1 truncate font-mono text-sm text-fg">{value}</code>
        <button
          onClick={copy}
          type="button"
          aria-label={copied ? "Copied" : "Copy to clipboard"}
          className={`
            shrink-0 rounded-md p-1.5 transition-colors duration-150
            ${copied ? "bg-ok/15 text-ok" : "text-faint hover:bg-raised hover:text-fg"}
          `}
        >
          {copied ? <CheckIcon className="size-4" /> : <CopyIcon className="size-4" />}
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-1.5">
      {label && (
        <div className="flex items-center justify-between">
          <span className="eyebrow">{label}</span>
          <button
            onClick={copy}
            type="button"
            className={`
              flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-medium transition-colors duration-150
              ${copied ? "bg-ok/15 text-ok" : "text-faint hover:bg-raised hover:text-fg"}
            `}
          >
            {copied ? (
              <>
                <CheckIcon className="size-3.5" />
                Copied
              </>
            ) : (
              <>
                <CopyIcon className="size-3.5" />
                Copy
              </>
            )}
          </button>
        </div>
      )}
      <div className="group relative">
        <pre className="overflow-x-auto rounded-md border border-edge bg-well p-3">
          <code className="whitespace-pre-wrap break-all font-mono text-sm text-fg">
            {rendered}
          </code>
        </pre>
        {!label && (
          <button
            onClick={copy}
            type="button"
            aria-label={copied ? "Copied" : "Copy to clipboard"}
            className={`
              absolute right-2 top-2 rounded-md p-1.5 transition-colors duration-150
              ${copied ? "bg-ok/15 text-ok" : "bg-surface/80 text-faint hover:bg-raised hover:text-fg"}
            `}
          >
            {copied ? <CheckIcon className="size-4" /> : <CopyIcon className="size-4" />}
          </button>
        )}
      </div>
    </div>
  );
}
