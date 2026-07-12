"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useSyncExternalStore, type ReactNode } from "react";
import {
  ChartIcon,
  ChevronRightIcon,
  GridIcon,
  KeyIcon,
  LockIcon,
  ServerIconStack,
  SettingsCogIcon,
  ShieldIcon,
  SourcesDbIcon,
} from "@/components/icons";
import { getTenantIdFromCookies, lockTenantSession } from "@/src/lib/tenant-session";
import { UI_VERSION } from "@/src/lib/env";

interface AppShellProps {
  children: ReactNode;
}

type NavItem = {
  href: string;
  label: string;
  icon: typeof GridIcon;
  beta?: boolean;
  extraActivePrefixes?: string[];
  excludeActivePrefixes?: string[];
};

const navItems: NavItem[] = [
  { href: "/profiles", label: "Profiles", icon: GridIcon },
  {
    href: "/sources",
    label: "Sources",
    icon: SourcesDbIcon,
    excludeActivePrefixes: ["/sources/deployment"],
  },
  {
    href: "/sources/deployment",
    label: "Deployment",
    icon: ServerIconStack,
    beta: true,
    extraActivePrefixes: ["/sources/new/managed-mcp"],
  },
  { href: "/api-keys", label: "API keys", icon: KeyIcon },
  { href: "/secrets", label: "Secrets", icon: ShieldIcon },
  { href: "/audit", label: "Audit", icon: ChartIcon },
  { href: "/settings", label: "Settings", icon: SettingsCogIcon },
];

const noopSubscribe = () => () => {};

export function AppShell({ children }: AppShellProps) {
  const pathname = usePathname();
  // Read once per render on the client, null on the server (avoids a
  // hydration mismatch since the cookie is not available during SSR).
  const tenantId = useSyncExternalStore(
    noopSubscribe,
    () => getTenantIdFromCookies(),
    () => null,
  );

  return (
    <div className="flex h-full">
      {/* Sidebar */}
      <aside className="flex w-60 shrink-0 flex-col border-r border-edge bg-surface">
        {/* Brand */}
        <div className="border-b border-edge p-4">
          <Link
            href="/profiles"
            className="group flex items-center gap-3 rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <div className="flex size-8 items-center justify-center rounded-md bg-accent-strong">
              <span className="text-sm font-semibold leading-none text-white">U</span>
            </div>
            <div className="min-w-0">
              <div className="text-sm font-semibold text-fg">MCP Gateway</div>
              <div className="eyebrow mt-0.5">unrelated.ai</div>
            </div>
          </Link>
        </div>

        {/* Navigation */}
        <nav className="flex-1 space-y-0.5 overflow-y-auto p-2">
          {navItems.map((item) => {
            const matchesPrefix = pathname === item.href || pathname.startsWith(item.href + "/");
            const matchesExtra = (item.extraActivePrefixes ?? []).some(
              (prefix) => pathname === prefix || pathname.startsWith(prefix + "/"),
            );
            const isExcluded = (item.excludeActivePrefixes ?? []).some(
              (prefix) => pathname === prefix || pathname.startsWith(prefix + "/"),
            );
            const isActive = (matchesPrefix || matchesExtra) && !isExcluded;
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={isActive ? "page" : undefined}
                className={`
                  relative flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium
                  transition-colors duration-150
                  focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent
                  ${
                    isActive
                      ? "bg-raised text-fg before:absolute before:inset-y-1.5 before:left-0 before:w-0.5 before:rounded-full before:bg-accent"
                      : "text-muted hover:bg-raised/60 hover:text-fg"
                  }
                `}
              >
                <item.icon className={`size-4.5 ${isActive ? "text-accent" : "text-faint"}`} />
                <span className="flex items-center gap-2">
                  <span>{item.label}</span>
                  {item.beta ? <span className="eyebrow">beta</span> : null}
                </span>
              </Link>
            );
          })}
        </nav>

        {/* Tenant + lock */}
        <div className="space-y-2 border-t border-edge p-3">
          {tenantId && (
            <div className="flex items-center gap-2 px-3">
              <span aria-hidden="true" className="size-1.5 shrink-0 rounded-[1px] bg-ok" />
              <div className="min-w-0">
                <div className="eyebrow">Tenant</div>
                <div className="truncate font-mono text-xs text-muted" title={tenantId}>
                  {tenantId}
                </div>
              </div>
            </div>
          )}
          <button
            type="button"
            onClick={() => lockTenantSession("/unlock")}
            className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm font-medium text-muted transition-colors duration-150 hover:bg-raised/60 hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <LockIcon className="size-4.5 text-faint" />
            Lock / Switch tenant
          </button>
          <div className="eyebrow px-3 pb-1">{UI_VERSION}</div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto bg-bg">{children}</main>
    </div>
  );
}

interface PageHeaderProps {
  title: ReactNode;
  description?: string;
  actions?: ReactNode;
  breadcrumb?: { label: string; href?: string }[];
}

export function PageHeader({ title, description, actions, breadcrumb }: PageHeaderProps) {
  return (
    <div className="sticky top-0 z-10 border-b border-edge bg-bg/90 backdrop-blur-sm">
      <div className="px-6 py-5">
        <div className="max-w-5xl">
          {breadcrumb && breadcrumb.length > 0 && (
            <nav aria-label="Breadcrumb" className="mb-2 flex items-center gap-1.5">
              {breadcrumb.map((item, i) => (
                <span key={i} className="flex items-center gap-1.5">
                  {i > 0 && <ChevronRightIcon className="size-3.5 text-faint" />}
                  {item.href ? (
                    <Link href={item.href} className="eyebrow transition-colors hover:text-fg">
                      {item.label}
                    </Link>
                  ) : (
                    <span className="eyebrow">{item.label}</span>
                  )}
                </span>
              ))}
            </nav>
          )}
          <div className="flex items-center justify-between gap-4">
            <div>
              <h1 className="text-lg font-semibold text-fg">{title}</h1>
              {description && <p className="mt-1 text-sm text-muted">{description}</p>}
            </div>
            {actions && <div className="flex items-center gap-3">{actions}</div>}
          </div>
        </div>
      </div>
    </div>
  );
}

export function PageContent({
  children,
  className,
  width = "5xl",
}: {
  children: ReactNode;
  className?: string;
  width?: "5xl" | "4xl" | "2xl" | "full";
}) {
  const maxW =
    width === "full"
      ? "max-w-none"
      : width === "2xl"
        ? "max-w-2xl"
        : width === "4xl"
          ? "max-w-4xl"
          : "max-w-5xl";

  return (
    <div className="p-6">
      <div className={`${maxW} ${className ?? ""}`.trim()}>{children}</div>
    </div>
  );
}
