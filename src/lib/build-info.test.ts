import assert from "node:assert/strict";
import test from "node:test";
import { resolveBuildInfo } from "./build-info.ts";

/** Build stamp (#6): SHA from VERCEL_GIT_COMMIT_SHA, honest "dev" fallback
 *  anywhere Vercel did not provide one. */

test("resolveBuildInfo uses the Vercel commit SHA when present", () => {
  const info = resolveBuildInfo(
    { VERCEL_GIT_COMMIT_SHA: "a30ad85599c7e28bbab1c40f939fb8de113f8019" },
    "2026-10-21.1+deadbeefcafebabe",
  );
  assert.equal(info.sha, "a30ad85599c7e28bbab1c40f939fb8de113f8019");
  assert.equal(info.shortSha, "a30ad85");
  assert.equal(info.analyzerVersion, "2026-10-21.1+deadbeefcafebabe");
  assert.ok(!Number.isNaN(Date.parse(info.builtAt)), `builtAt was: ${info.builtAt}`);
});

test("resolveBuildInfo falls back to dev when the SHA is unset or blank", () => {
  for (const env of [{}, { VERCEL_GIT_COMMIT_SHA: "" }, { VERCEL_GIT_COMMIT_SHA: "   " }]) {
    const info = resolveBuildInfo(env);
    assert.equal(info.sha, "dev");
    assert.equal(info.shortSha, "dev");
    assert.equal(info.analyzerVersion, null);
  }
});
