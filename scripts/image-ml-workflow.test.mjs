import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

test("Image ML browser CI covers each UI surface that can change its rendering", () => {
  const workflow = readFileSync(
    new URL("../.github/workflows/image-ml.yml", import.meta.url),
    "utf8",
  );
  const paths = workflow.match(/[ ]{2}pull_request:\s*\n[ ]{4}paths:\s*\n\s*\[([\s\S]*?)\]/)?.[1];
  assert.ok(paths, "Expected the Image ML pull-request path list");
  const entries = [...paths.matchAll(/"([^"\n]+)"/g)].map((match) => match[1]);
  for (const path of [
    "src/components/image-vulnerability-panel.tsx",
    "src/components/image-ml-insights.tsx",
    "src/components/workbench/bytecode-tab.tsx",
    "src/components/workbench.tsx",
    "src/styles.css",
  ])
    assert.ok(entries.includes(path), `${path} must trigger Image ML browser CI`);
});
