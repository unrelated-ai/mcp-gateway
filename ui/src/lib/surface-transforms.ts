export type ParamOverride = {
  rename?: string;
  default?: unknown;
  visible?: boolean;
  treatNullAsMissing?: boolean;
};
export type ToolOverride = {
  rename?: string;
  description?: string;
  params?: Record<string, ParamOverride>;
};
export type ResourceOverride = {
  enabled?: boolean;
  name?: string;
  title?: string;
  description?: string;
};
export type PromptParamOverride = { rename?: string; default?: string };
export type PromptOverride = {
  enabled?: boolean;
  rename?: string;
  description?: string;
  params?: Record<string, PromptParamOverride>;
};
export type TransformPipeline = {
  toolOverrides: Record<string, ToolOverride>;
  resourceOverrides: Record<string, Record<string, ResourceOverride>>;
  resourceTemplateOverrides: Record<string, Record<string, ResourceOverride>>;
  promptOverrides: Record<string, Record<string, PromptOverride>>;
  [key: string]: unknown;
};
export type CatalogKind = "resourceOverrides" | "resourceTemplateOverrides" | "promptOverrides";
export type CatalogItem = {
  name: string;
  title?: string | null;
  description?: string | null;
  uri?: string;
  uriTemplate?: string;
  arguments?: { name: string; description?: string | null; required?: boolean | null }[] | null;
};
export type CatalogEntry = {
  sourceId: string;
  original: CatalogItem;
  exposed: CatalogItem;
  enabled: boolean;
  error?: string | null;
};
const object = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
export function normalizePipeline(input: unknown): TransformPipeline {
  const value = object(input);
  return {
    ...value,
    toolOverrides: { ...object(value.toolOverrides) } as TransformPipeline["toolOverrides"],
    resourceOverrides: {
      ...object(value.resourceOverrides),
    } as TransformPipeline["resourceOverrides"],
    resourceTemplateOverrides: {
      ...object(value.resourceTemplateOverrides),
    } as TransformPipeline["resourceTemplateOverrides"],
    promptOverrides: { ...object(value.promptOverrides) } as TransformPipeline["promptOverrides"],
  };
}
export const catalogIdentity = (item: CatalogItem) => item.uri ?? item.uriTemplate ?? item.name;
export function replaceCatalogOverride(
  input: unknown,
  kind: CatalogKind,
  source: string,
  id: string,
  value: ResourceOverride | PromptOverride,
) {
  const pipeline = normalizePipeline(input);
  return {
    ...pipeline,
    [kind]: { ...pipeline[kind], [source]: { ...pipeline[kind][source], [id]: value } },
  };
}
export type CatalogDraft = {
  enabled: boolean;
  name: string;
  title: string;
  description: string;
  overrideDescription: boolean;
  params: { original: string; rename: string; useDefault: boolean; defaultValue: string }[];
};
export function catalogDraft(kind: CatalogKind, entry: CatalogEntry, input: unknown): CatalogDraft {
  const pipeline = normalizePipeline(input);
  const rule = pipeline[kind][entry.sourceId]?.[catalogIdentity(entry.original)] as
    (ResourceOverride & PromptOverride) | undefined;
  const names = new Set([
    ...(entry.original.arguments ?? []).map((p) => p.name),
    ...Object.keys(rule?.params ?? {}),
  ]);
  return {
    enabled: rule?.enabled !== false,
    name: (kind === "promptOverrides" ? rule?.rename : rule?.name) ?? "",
    title: rule?.title ?? "",
    description: rule?.description ?? entry.original.description ?? "",
    overrideDescription: rule?.description != null,
    params: [...names].map((original) => ({
      original,
      rename: rule?.params?.[original]?.rename ?? "",
      useDefault: typeof rule?.params?.[original]?.default === "string",
      defaultValue: rule?.params?.[original]?.default ?? "",
    })),
  };
}
export function buildCatalogOverride(
  kind: CatalogKind,
  draft: CatalogDraft,
): ResourceOverride | PromptOverride {
  const name = draft.name.trim();
  const common = {
    enabled: draft.enabled,
    description: draft.overrideDescription ? draft.description : undefined,
  };
  if (kind !== "promptOverrides")
    return { ...common, name: name || undefined, title: draft.title.trim() || undefined };
  if (name.includes(":")) throw new Error("Prompt aliases cannot contain ':'.");
  const names = new Set<string>();
  const params = Object.fromEntries(
    draft.params.map((param) => {
      const rename = param.rename.trim();
      const exposed = rename || param.original;
      if (names.has(exposed)) throw new Error(`Duplicate prompt argument: ${exposed}`);
      names.add(exposed);
      return [
        param.original,
        { rename: rename || undefined, default: param.useDefault ? param.defaultValue : undefined },
      ];
    }),
  );
  return { ...common, rename: name || undefined, params };
}
