"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ChevronRightIcon,
  ChartIcon,
  GridIcon,
  KeyIcon,
  LockIcon,
  SettingsCogIcon,
  ShieldIcon,
  SourcesDbIcon,
} from "@/components/icons";
import { type ReactNode } from "react";
import { clearTenantSessionCookies } from "@/src/lib/tenant-session";

interface AppShellProps {
  children: ReactNode;
}

const navItems = [
  { href: "/profiles", label: "Profiles", icon: GridIcon },
  { href: "/sources", label: "Sources", icon: SourcesDbIcon },
  { href: "/api-keys", label: "API Keys", icon: KeyIcon },
  { href: "/secrets", label: "Secrets", icon: ShieldIcon },
  { href: "/audit", label: "Audit", icon: ChartIcon },
  { href: "/settings", label: "Settings", icon: SettingsCogIcon },
];

export function AppShell({ children }: AppShellProps) {
  const pathname = usePathname();

  return (
    <div className="flex h-full">
      {/* Sidebar */}
      <aside className="w-64 shrink-0 border-r border-zinc-800/80 bg-zinc-950/50 flex flex-col">
        {/* Logo / Brand */}
        <div className="p-4 border-b border-zinc-800/60">
          <Link href="/profiles" className="flex items-center gap-3 group">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-violet-500 to-violet-600 flex items-center justify-center shadow-lg shadow-violet-500/20">
              <span className="text-white font-black text-lg leading-none tracking-tight">U</span>
            </div>
            <div className="min-w-0">
              <div className="text-sm font-semibold text-zinc-100 group-hover:text-white transition-colors">
                MCP Gateway
              </div>
              <div className="text-xs text-zinc-500 truncate">by unrelated.ai</div>
            </div>
          </Link>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const isActive = pathname === item.href || pathname.startsWith(item.href + "/");
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`
                  flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium
                  transition-all duration-150
                  ${
                    isActive
                      ? "bg-violet-500/10 text-violet-400 shadow-sm"
                      : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60"
                  }
                `}
              >
                <item.icon
                  className={`w-5 h-5 ${isActive ? "text-violet-400" : "text-zinc-500"}`}
                />
                {item.label}
              </Link>
            );
          })}
        </nav>

        {/* Footer */}
        <div className="p-3 border-t border-zinc-800/60">
          <Link
            href="/unlock"
            onClick={() => {
              clearTenantSessionCookies();
            }}
            className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60 transition-all duration-150"
          >
            <LockIcon className="w-5 h-5 text-zinc-500" />
            Lock / Switch Tenant
          </Link>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto bg-zinc-950">{children}</main>
    </div>
  );
}

// Page header component for consistent styling
interface PageHeaderProps {
  title: ReactNode;
  description?: string;
  actions?: ReactNode;
  breadcrumb?: { label: string; href?: string }[];
}

export function PageHeader({ title, description, actions, breadcrumb }: PageHeaderProps) {
  return (
    <div className="border-b border-zinc-800/60 bg-zinc-950/80 backdrop-blur-sm sticky top-0 z-10">
      <div className="px-6 py-5">
        <div className="max-w-5xl">
          {breadcrumb && breadcrumb.length > 0 && (
            <nav className="flex items-center gap-2 text-sm mb-2">
              {breadcrumb.map((item, i) => (
                <span key={i} className="flex items-center gap-2">
                  {i > 0 && <ChevronRightIcon className="w-4 h-4 text-zinc-600" />}
                  {item.href ? (
                    <Link
                      href={item.href}
                      className="text-zinc-400 hover:text-zinc-200 transition-colors"
                    >
                      {item.label}
                    </Link>
                  ) : (
                    <span className="text-zinc-500">{item.label}</span>
                  )}
                </span>
              ))}
            </nav>
          )}
          <div className="flex items-center justify-between gap-4">
            <div>
              <h1 className="text-xl font-semibold text-zinc-100">{title}</h1>
              {description && <p className="mt-1 text-sm text-zinc-400">{description}</p>}
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
