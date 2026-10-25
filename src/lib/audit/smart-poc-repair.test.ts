import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { runPocWithRpcRetries } from "./foundry-backend.ts";

/**
 * SmartPoC compile repair against a REAL forge — the 2026-10-25 live
 * failure: an LLM-generated PoC died terminally on
 *   Error (9574): Type bytes32 is not implicitly convertible to
 *   expected type uint256.
 *   uint256 slot0 = vm.load(target, bytes32(0));
 * a one-token fix (`uint256(vm.load(...))`) that the bounded repair
 * exists for. The mock backend below is faithful to the real one's
 * response shapes (compile error → ok:true/passed:false with the
 * forge output as logs) but executes the submitted code with the
 * local forge instead of returning canned text, so "the repaired
 * PoC compiles and reaches a verdict" is proven, not asserted.
 * No fork is involved: the fixture reads a storage slot via the
 * vm.load cheatcode on the plain local EVM.
 */

const FORGE_CANDIDATES = [
  process.env.HOME ? path.join(process.env.HOME, ".foundry", "bin", "forge") : "",
  "forge",
].filter(Boolean);

function forgeBin(): string | null {
  for (const candidate of FORGE_CANDIDATES) {
    try {
      execFileSync(candidate, ["--version"], { stdio: "pipe", timeout: 15_000 });
      return candidate;
    } catch {
      // try the next candidate
    }
  }
  return null;
}

let scratchDir: string | null = null;
function scratchProject(): string {
  if (scratchDir) return scratchDir;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sk-smartpoc-repair-"));
  fs.mkdirSync(path.join(dir, "src"), { recursive: true });
  fs.mkdirSync(path.join(dir, "test"), { recursive: true });
  fs.writeFileSync(
    path.join(dir, "foundry.toml"),
    '[profile.default]\nsrc = "src"\ntest = "test"\nout = "out"\nsolc_version = "0.8.28"\n',
  );
  scratchDir = dir;
  return dir;
}

/** A /run-poc stand-in that really compiles+runs the submitted code. */
function installForgeBackend(forge: string) {
  const original = globalThis.fetch;
  const calls: Array<{ testCode: string }> = [];
  globalThis.fetch = (async (input: unknown, init?: { body?: unknown }) => {
    const url = String(input);
    if (!url.includes("/run-poc")) {
      throw new Error(`unexpected fetch in smart-poc-repair test: ${url}`);
    }
    const body = JSON.parse(String(init?.body ?? "{}")) as { testCode: string };
    calls.push({ testCode: body.testCode });
    const dir = scratchProject();
    fs.writeFileSync(path.join(dir, "test", "PoC.t.sol"), body.testCode);
    let output = "";
    let exitCode = 0;
    try {
      output = String(
        execFileSync(forge, ["test"], {
          cwd: dir,
          timeout: 120_000,
          env: {
            PATH: process.env.PATH ?? "",
            HOME: process.env.HOME ?? "",
            TMPDIR: os.tmpdir(),
          },
        }),
      );
    } catch (err) {
      const e = err as { stdout?: unknown; stderr?: unknown; status?: number };
      output = `${String(e.stdout ?? "")}\n${String(e.stderr ?? "")}`;
      exitCode = typeof e.status === "number" ? e.status : 1;
    }
    // The real backend's shapes (termux-backend/server.mjs): forge ran
    // to completion → ok:true, `passed` carries the verdict, and a
    // compile failure is passed:false with the compiler output as logs.
    const passed = exitCode === 0;
    return new Response(
      JSON.stringify({ ok: true, passed, logs: output, durationMs: 1 }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  }) as typeof fetch;
  return { calls, restore: () => { globalThis.fetch = original; } };
}

const TARGET_LINE_BROKEN = "uint256 slot0 = vm.load(target, bytes32(0));";
const TARGET_LINE_FIXED = "uint256 slot0 = uint256(vm.load(target, bytes32(0)));";

// The screenshot fixture: the LLM's draft, verbatim broken line and
// all (target = the StarkWare proxy from the screenshot, checksummed).
const BROKEN_POC = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface Vm {
    function load(address target, bytes32 slot) external returns (bytes32);
}

contract PoC {
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    address target = 0x45B79622C095ab834b9C8dC71013ed13B39F1B8D;

    function test_readSlot0() public {
        ${TARGET_LINE_BROKEN}
    }
}
`;

const ASSERTION_POC = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PoC {
    function test_assertion() public {
        uint256 x = 1;
        if (x != 2) revert("expected 2");
    }
}
`;

const ADDR = "0x45B79622C095ab834b9C8dC71013ed13B39F1B8D";

test("SmartPoC path: a bytes32→uint256 compile slip is repaired once and reaches a verdict", async (t) => {
  const forge = forgeBin();
  if (!forge) {
    t.skip("forge not available in this environment");
    return;
  }
  const backend = installForgeBackend(forge);
  let repairCalls = 0;
  try {
    const result = await runPocWithRpcRetries("http://localhost:8787", {
      address: ADDR,
      testCode: BROKEN_POC,
      skipZeroValue: false,
      // The mocked LLM: hands back the same draft with the one line
      // type-corrected — and only after seeing the real compiler text.
      repair: async (source: string, logs: string) => {
        repairCalls += 1;
        assert.match(logs, /Error \(9574\)/, "the repair must be fed the compiler output");
        assert.match(logs, /bytes32 is not implicitly convertible to expected type uint256/);
        return source.replace(TARGET_LINE_BROKEN, TARGET_LINE_FIXED);
      },
    });
    assert.equal(result.status, "passed", `expected a verdict, got ${result.status}:\n${result.logs}`);
    assert.equal(repairCalls, 1, "exactly one bounded repair attempt");
    assert.equal(backend.calls.length, 2, "broken draft + repaired draft, no more");
    assert.equal(backend.calls[0].testCode, BROKEN_POC);
    assert.ok(
      backend.calls[1].testCode.includes(TARGET_LINE_FIXED),
      "the repaired code is what gets re-run",
    );
    assert.equal(result.executedSource, backend.calls[1].testCode);
    assert.match(result.logs, /One compile repair attempted/);
    assert.equal(result.evidence?.testCount, 1);
  } finally { backend.restore(); }
});

test("SmartPoC path: an assertion failure is a verdict — never re-rolled through repair", async (t) => {
  const forge = forgeBin();
  if (!forge) {
    t.skip("forge not available in this environment");
    return;
  }
  const backend = installForgeBackend(forge);
  let repairCalls = 0;
  try {
    const result = await runPocWithRpcRetries("http://localhost:8787", {
      address: ADDR,
      testCode: ASSERTION_POC,
      skipZeroValue: false,
      repair: async () => {
        repairCalls += 1;
        return ASSERTION_POC;
      },
    });
    assert.equal(result.status, "failed");
    assert.equal(repairCalls, 0, "repair is for compile errors only");
    assert.equal(backend.calls.length, 1, "a verdict ends the run — no re-roll");
  } finally { backend.restore(); }
});

test("SmartPoC path: without a repair callback the same compile error stays terminal (the old gap)", async (t) => {
  const forge = forgeBin();
  if (!forge) {
    t.skip("forge not available in this environment");
    return;
  }
  const backend = installForgeBackend(forge);
  try {
    const result = await runPocWithRpcRetries("http://localhost:8787", {
      address: ADDR,
      testCode: BROKEN_POC,
      skipZeroValue: false,
    });
    assert.equal(result.status, "error");
    assert.match(result.logs, /Error \(9574\)/);
    assert.equal(backend.calls.length, 1);
  } finally { backend.restore(); }
});
