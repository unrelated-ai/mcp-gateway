import assert from "node:assert/strict";
import test from "node:test";
import {
  buildCatalogOverride,
  catalogDraft,
  normalizePipeline,
  replaceCatalogOverride,
  type CatalogEntry,
} from "../src/lib/surface-transforms";

const entry: CatalogEntry = {
  sourceId: "catalog",
  original: {
    name: "review",
    arguments: [{ name: "topic", required: true }, { name: "audience" }],
  },
  exposed: { name: "review" },
  enabled: true,
};

test("catalog edits preserve tools, other sources, and unrelated catalog entries", () => {
  const original = {
    toolOverrides: { lookup: { rename: "search" } },
    futureField: true,
    promptOverrides: {
      other: { review: { enabled: false } },
      catalog: { retained: { description: "Keep" } },
    },
    resourceOverrides: { catalog: { "docs:///guide": { name: "Guide" } } },
  };
  const result = replaceCatalogOverride(original, "promptOverrides", "catalog", "review", {
    rename: "review_changes",
  });
  assert.deepEqual(result.toolOverrides, original.toolOverrides);
  assert.deepEqual(result.resourceOverrides, original.resourceOverrides);
  assert.deepEqual(result.promptOverrides.other, original.promptOverrides.other);
  assert.deepEqual(
    result.promptOverrides.catalog.retained,
    original.promptOverrides.catalog.retained,
  );
  assert.equal(result.futureField, true);
  assert.deepEqual(normalizePipeline(result), result);
  assert.equal("review" in original.promptOverrides.catalog, false);
});

test("prompt drafts support empty defaults, inherited descriptions and clearing aliases", () => {
  const pipeline = {
    promptOverrides: {
      catalog: {
        review: {
          rename: "review_changes",
          description: "",
          params: { topic: { rename: "subject", default: "" } },
        },
      },
    },
  };
  const draft = catalogDraft("promptOverrides", entry, pipeline);
  assert.equal(draft.overrideDescription, true);
  assert.equal(draft.params[0].useDefault, true);
  assert.equal(draft.params[0].defaultValue, "");
  draft.name = "";
  draft.overrideDescription = false;
  const value = JSON.parse(JSON.stringify(buildCatalogOverride("promptOverrides", draft)));
  assert.equal(value.rename, undefined);
  assert.equal(value.description, undefined);
  assert.equal(value.params.topic.default, "");
  draft.params[0].rename = "audience";
  assert.throws(() => buildCatalogOverride("promptOverrides", draft), /Duplicate/);
});
