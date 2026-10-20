import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const viewport = {
  status: 200,
  bodyTextLen: 100,
  horizontalOverflow: false,
  consoleErrors: [],
  pageErrors: [],
};
function run(change = {}, flag = "--require-baseline") {
  const directory = mkdtempSync(join(tmpdir(), "ci-verdict-"));
  try {
    const file = join(directory, "verdict.json");
    writeFileSync(
      file,
      JSON.stringify({
        viewports: { desktop: viewport, mobile: viewport },
        brandWarnings: [],
        authWarnings: [],
        divergesFromBaseline: false,
        ...change,
      }),
    );
    return spawnSync(process.execPath, ["scripts/ci-smoke-verdict.mjs", file, flag], {
      encoding: "utf8",
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("accepts clean desktop/mobile built verdict", () => {
  assert.equal(run().status, 0);
});
for (const [name, change] of Object.entries({
  "missing mobile": { viewports: { desktop: viewport } },
  blank: { viewports: { desktop: { ...viewport, bodyTextLen: 0 }, mobile: viewport } },
  overflow: { viewports: { desktop: viewport, mobile: { ...viewport, horizontalOverflow: true } } },
  "browser error": {
    viewports: { desktop: { ...viewport, pageErrors: ["crash"] }, mobile: viewport },
  },
  "brand warning": { brandWarnings: ["missing share card"] },
  "auth warning": { authWarnings: ["auth mismatch"] },
  "build divergence": { divergesFromBaseline: true, baselineReasons: ["text collapsed"] },
  "missing comparison": { divergesFromBaseline: undefined },
})) {
  test(`rejects ${name}`, () => {
    assert.equal(run(change).status, 1);
  });
}
