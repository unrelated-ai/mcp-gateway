export const TENANT_TOKEN_COOKIE = "ugw_tenant_token";
export const TENANT_ID_COOKIE = "ugw_tenant_id";
export const TENANT_EXP_COOKIE = "ugw_tenant_exp_unix";

export type TenantTokenPayloadV1 = {
  tenant_id: string;
  exp_unix_secs: number;
};

type RawTenantTokenPayloadV1 =
  | { tenant_id: string; exp_unix_secs: number }
  | { tenantId: string; expUnixSecs: number };

function base64UrlToBase64(input: string): string {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (padded.length % 4)) % 4;
  return padded + "=".repeat(padLen);
}

export function decodeTenantTokenPayload(token: string): TenantTokenPayloadV1 {
  const raw = token.trim().startsWith("Bearer ")
    ? token.trim().slice("Bearer ".length).trim()
    : token.trim();

  const parts = raw.split(".");
  if (parts.length !== 3 || parts[0] !== "tv1") {
    throw new Error("Invalid token format (expected tv1.<payload_b64>.<sig_b64>)");
  }

  const payloadB64Url = parts[1];
  const payloadB64 = base64UrlToBase64(payloadB64Url);
  const json = atob(payloadB64);
  const payload = JSON.parse(json) as RawTenantTokenPayloadV1;

  const tenantId =
    typeof (payload as { tenant_id?: unknown }).tenant_id === "string"
      ? (payload as { tenant_id: string }).tenant_id
      : typeof (payload as { tenantId?: unknown }).tenantId === "string"
        ? (payload as { tenantId: string }).tenantId
        : null;

  const expUnixSecs =
    typeof (payload as { exp_unix_secs?: unknown }).exp_unix_secs === "number"
      ? (payload as { exp_unix_secs: number }).exp_unix_secs
      : typeof (payload as { expUnixSecs?: unknown }).expUnixSecs === "number"
        ? (payload as { expUnixSecs: number }).expUnixSecs
        : null;

  if (!tenantId) {
    throw new Error("Invalid token payload (missing tenantId)");
  }
  if (expUnixSecs == null || typeof expUnixSecs !== "number" || !Number.isFinite(expUnixSecs)) {
    throw new Error("Invalid token payload (missing expUnixSecs)");
  }
  return { tenant_id: tenantId, exp_unix_secs: expUnixSecs };
}

type UnlockSessionResponse = {
  ok: true;
  tenantId: string;
  expUnixSecs: number;
};

function parseErrorMessage(text: string): string {
  const t = text.trim();
  if (!t) return "Request failed";
  try {
    const v = JSON.parse(t) as unknown;
    if (v && typeof v === "object") {
      const o = v as Record<string, unknown>;
      if (typeof o.error === "string" && o.error.trim()) return o.error;
    }
  } catch {
    // ignore non-JSON
  }
  return t;
}

export async function establishTenantSession(token: string): Promise<TenantTokenPayloadV1> {
  const res = await fetch("/api/session/unlock", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: token.trim() }),
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(parseErrorMessage(text));
  }
  let body: UnlockSessionResponse;
  try {
    body = JSON.parse(text) as UnlockSessionResponse;
  } catch {
    throw new Error("Invalid unlock response");
  }
  if (!body.ok || !body.tenantId || !Number.isFinite(body.expUnixSecs)) {
    throw new Error("Invalid unlock response");
  }
  return {
    tenant_id: body.tenantId,
    exp_unix_secs: body.expUnixSecs,
  };
}

function buildUnlockPath(nextPath?: string): string {
  const next =
    nextPath ??
    (typeof window !== "undefined" ? `${window.location.pathname}${window.location.search}` : "/");
  return `/unlock?next=${encodeURIComponent(next)}`;
}

export function lockTenantSession(nextPath?: string): void {
  if (typeof window === "undefined") return;
  const unlockPath = buildUnlockPath(nextPath);
  window.location.href = `/api/session/logout?next=${encodeURIComponent(unlockPath)}`;
}

export function forceReunlock(nextPath?: string): void {
  lockTenantSession(nextPath);
}

export function readCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const cookie = document.cookie
    .split(";")
    .map((c) => c.trim())
    .find((c) => c.startsWith(`${name}=`));
  if (!cookie) return null;
  return decodeURIComponent(cookie.slice(name.length + 1));
}

export function getTenantIdFromCookies(): string | null {
  return readCookie(TENANT_ID_COOKIE);
}

export function getTenantExpFromCookies(): number | null {
  const raw = readCookie(TENANT_EXP_COOKIE);
  if (!raw) return null;
  const n = Number(raw);
  return Number.isFinite(n) ? n : null;
}
