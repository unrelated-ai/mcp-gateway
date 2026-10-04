export type ToolSourceDetail = {
  revision: number;
  type: string;
  enabled: boolean;
  spec: Record<string, unknown>;
};

/** A form edits only the fields it owns. Preserve advanced configuration and
 * send the revision that was loaded with the draft for an atomic conflict check.
 */
export function buildOpenApiSourceUpdate(
  source: ToolSourceDetail,
  edits: Record<string, unknown> & { defaults: Record<string, unknown>; enabled: boolean },
) {
  return {
    ...structuredClone(source.spec),
    ...edits,
    defaults: {
      ...((source.spec.defaults ?? {}) as Record<string, unknown>),
      ...edits.defaults,
    },
    type: "openapi",
    expectedRevision: source.revision,
  };
}

export function buildJsonSourceUpdate(source: ToolSourceDetail, text: string) {
  const value: unknown = JSON.parse(text);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Source configuration must be a JSON object.");
  }
  return { ...value, type: source.type, expectedRevision: source.revision };
}
