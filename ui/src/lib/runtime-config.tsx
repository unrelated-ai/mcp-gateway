"use client";

import { createContext, useContext, type ReactNode } from "react";

export type RuntimeConfig = { gatewayDataBase: string };
const RuntimeConfigContext = createContext<RuntimeConfig | null>(null);

export function RuntimeConfigProvider({
  value,
  children,
}: {
  value: RuntimeConfig;
  children: ReactNode;
}) {
  return <RuntimeConfigContext.Provider value={value}>{children}</RuntimeConfigContext.Provider>;
}

export function useRuntimeConfig(): RuntimeConfig {
  const config = useContext(RuntimeConfigContext);
  if (!config) throw new Error("Runtime configuration provider is missing");
  return config;
}
