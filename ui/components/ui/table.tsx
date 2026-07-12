"use client";

import { type ReactNode, type TdHTMLAttributes, type ThHTMLAttributes } from "react";

/**
 * Data table primitives. Header cells render as mono "silkscreen" labels.
 * Wrap in <Card> (or use the bordered variant) and keep wide tables inside
 * an overflow-x-auto container.
 */
export function Table({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`overflow-x-auto ${className}`}>
      <table className="w-full text-sm">{children}</table>
    </div>
  );
}

export function THead({ children }: { children: ReactNode }) {
  return <thead className="border-b border-edge">{children}</thead>;
}

export function TBody({ children }: { children: ReactNode }) {
  return <tbody className="divide-y divide-edge">{children}</tbody>;
}

export function TR({
  children,
  className = "",
  ...props
}: { children: ReactNode; className?: string } & React.HTMLAttributes<HTMLTableRowElement>) {
  return (
    <tr className={`transition-colors duration-100 hover:bg-raised/50 ${className}`} {...props}>
      {children}
    </tr>
  );
}

export function TH({
  children,
  className = "",
  ...props
}: { children?: ReactNode; className?: string } & ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th className={`eyebrow px-4 py-2.5 text-left ${className}`} {...props}>
      {children}
    </th>
  );
}

export function TD({
  children,
  className = "",
  ...props
}: { children?: ReactNode; className?: string } & TdHTMLAttributes<HTMLTableCellElement>) {
  return (
    <td className={`px-4 py-3 align-middle text-fg ${className}`} {...props}>
      {children}
    </td>
  );
}
