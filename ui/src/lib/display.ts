import type { Tone } from "@/components/ui";

export function formatDataPlaneAuthMode(mode: string | undefined | null): string {
  if (!mode) return "(unknown)";
  switch (mode) {
    case "disabled":
      return "No auth";
    case "apiKey":
      return "API key";
    case "oauth":
      return "OAuth";
    default:
      return mode;
  }
}

export function authModeTone(mode: string | undefined | null): Tone {
  if (!mode) return "neutral";
  if (mode === "apiKey") return "info";
  if (mode === "oauth") return "accent";
  if (mode === "disabled") return "warn";
  return "neutral";
}

export function formatUnix(unix: number): string {
  return new Date(unix * 1000).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

export function formatUnixRelative(unix: number | null): string {
  if (!unix) return "never";
  const diff = Date.now() - unix * 1000;
  const hours = Math.floor(diff / 3600000);
  if (hours < 1) return "just now";
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
