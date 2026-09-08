import type { RuntimeConfig } from "../runtime-config";

// Read through the environment object at request time. A direct NEXT_PUBLIC_*
// expression would be replaced at build time, freezing the Docker image's URL.
export function readRuntimeConfig(
  env: Record<string, string | undefined> = process.env,
): RuntimeConfig {
  return {
    gatewayDataBase: (
      env.GATEWAY_DATA_BASE ??
      env.NEXT_PUBLIC_GATEWAY_DATA_BASE ??
      "http://localhost:27100"
    )
      .trim()
      .replace(/\/+$/, ""),
  };
}
