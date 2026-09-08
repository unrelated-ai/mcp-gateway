import type { Metadata } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import "./globals.css";
import { Providers } from "./providers";
import { connection } from "next/server";
import { readRuntimeConfig } from "@/src/lib/server/runtime-config";
import { RuntimeConfigProvider } from "@/src/lib/runtime-config";

const plexSans = IBM_Plex_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-plex-sans",
  display: "swap",
});

const plexMono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-plex-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "MCP Gateway",
  description: "Tenant onboarding and profile management for the unrelated.ai MCP Gateway.",
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  await connection();
  const config = readRuntimeConfig();
  return (
    <html lang="en" className="h-full">
      <body
        className={`${plexSans.variable} ${plexMono.variable} h-full bg-bg font-sans text-fg antialiased`}
      >
        <RuntimeConfigProvider value={config}>
          <Providers>{children}</Providers>
        </RuntimeConfigProvider>
      </body>
    </html>
  );
}
