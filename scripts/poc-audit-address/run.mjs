#!/usr/bin/env node
/**
 * poc-audit-address — audit ONE deployed address end to end, headlessly.
 *
 *   1. fetch + analyze: bridge.ts `analyze` runs the app's own
 *      analyzeAddress (Sourcify verified source, else runtime bytecode)
 *      and picks the PoC target with the app's own pocAuditEligibility
 *      (highest severity first; presence-only excluded unless
 *      corroborated — the same rule the PoC feed applies).
 *   2. generate: bridge.ts `generate` runs the app's
 *      generateAiSecurityReview for that one finding (the split
 *      narrative + test-code calls). A reply that falls back to the
 *      structured template (source != "openrouter") means NO AI PoC was
 *      generated: the audit reports UNTESTED and stops — never a
 *      silent pass, never a fabricated failure.
 *   3. execute: the generated test is wrapped if needed (the app's
 *      poc-wrap, via bridge.ts `wrap`) and run EXACTLY like the app
 *      runs it — test/PoC.t.sol, `forge test --match-contract PoC`,
 *      POC_TARGET / POC_RPC_URL / POC_FORK_BLOCK in env, 120s cap.
 *      The templates create the fork themselves from POC_RPC_URL, so
 *      no anvil is needed; RPCs rotate through the chain's public list
 *      (src/lib/audit/address-fetcher.ts) on RPC/fork failures only.
 *      On a compile error the app's repair contract runs ONCE
 *      (bridge.ts `repair` -> repairPocCode) and the fixed PoC is
 *      re-run once. Zero matched tests = no_tests, never a pass.
 *
 * Usage:
 *   OPENROUTER_API_KEY=... node scripts/poc-audit-address/run.mjs \
 *     --address 0x... [--chain ethereum] [--block 19000000] \
 *     [--rpc https://...] [--out poc-audit-out] [--keep-work]
 *   node scripts/poc-audit-address/run.mjs --address 0x... --analyze-only
 *
 * --analyze-only stops after step 1 (no key needed) and writes the
 * analysis bundle — the no-secret smoke path.
 *
 * The key is only ever read by the app modules via bridge.ts; this
 * runner never prints or persists it.
 *
 * Output bundle (--out dir): report.json, source.sol, findings.json,
 * review.json, poc-generated.sol, PoC.t.sol (as executed), forge.log,
 * verdict.json. verdict.json is the machine-readable summary; the
 * same fields print on stdout.
 *
 * Exit codes:
 *   0  the audit ran to an end state (passed | failed | no_tests |
 *      error — error = the PoC did not compile after its one repair),
 *      or --analyze-only completed
 *   1  infrastructure error (fetch/RPC outage, forge harness failure)
 *   2  preflight: OPENROUTER_API_KEY is not configured (live mode)
 *   3  nothing to test (no code at the address, no findings, or no
 *      PoC-eligible finding)
 *   4  generation fell back to the template — type UNTESTED
 */
import { execFile, spawn } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileP = promisify(execFile);
const SUITE_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SUITE_DIR, "..", "..");
const FORGE = process.env.FORGE_BIN || "forge";
const FORGE_TIMEOUT_MS = 120_000; // mirrors termux-backend/server.mjs

// The bridge (bridge.ts) is TypeScript. It runs through tsx — the
// repo-local node_modules/.bin/tsx when present, else `npx -y tsx`,
// exactly like scripts/ai-poc-proof/run.mjs (distro Node builds can
// lack compiled-in TypeScript support).
const TSX_LOCAL = join(REPO_ROOT, "node_modules", ".bin", "tsx");
const bridge0 = existsSync(TSX_LOCAL)
  ? { cmd: TSX_LOCAL, prefix: [] }
  : { cmd: "npx", prefix: ["-y", "tsx"] };

function parseArgs(argv) {
  const args = { chain: "ethereum", out: "poc-audit-out", keepWork: false, analyzeOnly: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--address") args.address = argv[++i];
    else if (a === "--chain") args.chain = argv[++i];
    else if (a === "--block") args.block = argv[++i];
    else if (a === "--rpc") args.rpc = argv[++i];
    else if (a === "--out") args.out = argv[++i];
    else if (a === "--keep-work") args.keepWork = true;
    else if (a === "--analyze-only") args.analyzeOnly = true;
    else if (a === "--help" || a === "-h") args.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  return args;
}

async function run(cmd, argv, opts = {}) {
  try {
    const { stdout, stderr } = await execFileP(cmd, argv, {
      maxBuffer: 64 * 1024 * 1024,
      ...opts,
    });
    return { stdout, stderr, code: 0 };
  } catch (err) {
    return {
      stdout: err.stdout ?? "",
      stderr: err.stderr ?? String(err.message ?? err),
      code: typeof err.code === "number" ? err.code : 1,
      killed: Boolean(err.killed),
    };
  }
}

/** Call the bridge; returns the parsed JSON object it prints. */
async function bridge(cmd, payload) {
  const { stdout, stderr, code } = await run(
    bridge0.cmd,
    [...bridge0.prefix, join(SUITE_DIR, "bridge.ts"), cmd, JSON.stringify(payload)],
    { env: process.env, timeout: 660_000 },
  );
  const lines = stdout.trim().split("\n").filter(Boolean);
  const last = lines[lines.length - 1] ?? "";
  let parsed;
  try {
    parsed = JSON.parse(last);
  } catch {
    throw new Error(
      `bridge ${cmd} returned non-JSON: ${last.slice(0, 300)} (exit ${code}) ${stderr.slice(-300)}`,
    );
  }
  if (parsed.fatal) throw new Error(`bridge ${cmd} failed: ${parsed.fatal}`);
  return parsed;
}

/** Write test/PoC.t.sol and run forge exactly like the app backend does. */
async function runForge(work, rpc, target, block, code) {
  writeFileSync(join(work, "test", "PoC.t.sol"), code, "utf8");
  const env = {
    ...process.env,
    POC_TARGET: target,
    POC_RPC_URL: rpc,
    POC_FORK_BLOCK: block,
    ETH_RPC_URL: rpc,
  };
  const started = Date.now();
  const res = await run(FORGE, ["test", "--match-contract", "PoC", "-vv"], {
    cwd: work,
    env,
    timeout: FORGE_TIMEOUT_MS,
  });
  if (res.killed) {
    return {
      logs: `forge timed out after ${FORGE_TIMEOUT_MS}ms`,
      passed: 0,
      failed: 0,
      durationMs: Date.now() - started,
      timedOut: true,
    };
  }
  const logs = `${res.stdout}\n${res.stderr}`;
  const summary = logs.match(/(\d+) passed; (\d+) failed/);
  const passed = summary ? Number(summary[1]) : (logs.match(/\[PASS\]/g) ?? []).length;
  const failed = summary ? Number(summary[2]) : (logs.match(/\[FAIL/g) ?? []).length;
  return { logs, passed, failed, durationMs: Date.now() - started, timedOut: false };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || !args.address) {
    console.log("Usage: node scripts/poc-audit-address/run.mjs --address 0x... [--chain ethereum] [--block N] [--rpc URL] [--out DIR] [--analyze-only]");
    process.exit(args.help ? 0 : 2);
  }
  if (!/^0x[0-9a-fA-F]{40}$/.test(args.address)) {
    console.error(`invalid EVM address: ${args.address}`);
    process.exit(2);
  }
  const block = args.block ? String(args.block) : "0";
  if (!/^\d+$/.test(block)) {
    console.error(`--block must be a block number, got: ${args.block}`);
    process.exit(2);
  }
  const outDir = resolve(args.out);
  mkdirSync(outDir, { recursive: true });
  const verdict = {
    address: args.address,
    chain: args.chain,
    block: block === "0" ? "latest" : Number(block),
    status: "",
    detail: "",
    generatedAt: new Date().toISOString(),
  };
  const finish = (code) => {
    writeFileSync(join(outDir, "verdict.json"), JSON.stringify(verdict, null, 2), "utf8");
    console.log(JSON.stringify(verdict, null, 2));
    process.exit(code);
  };

  // Preflight (live mode only): fail fast, before any fetching, when
  // no key is configured. The runner used by the nightly proof makes
  // the same demand; --analyze-only is the key-free path.
  if (!args.analyzeOnly) {
    const config = await bridge("config", {});
    if (!config.hasKey) {
      console.error(
        "OPENROUTER_API_KEY is not configured — live audit cannot generate a PoC. " +
          "Set the repo secret OPENROUTER_API_KEY (Settings → Secrets and variables → Actions), " +
          "or run with --analyze-only for the key-free analysis bundle.",
      );
      verdict.status = "preflight-no-key";
      verdict.detail = "OPENROUTER_API_KEY is not configured";
      finish(2);
    }
    verdict.model = config.model;
  }

  // 1. Fetch + analyze + pick the eligible finding.
  const analysis = await bridge("analyze", {
    address: args.address,
    chain: args.chain,
    outDir,
  });
  Object.assign(verdict, {
    inputKind: analysis.inputKind,
    contract: analysis.contractName,
    label: analysis.label,
    riskScore: analysis.riskScore,
    findings: analysis.findings,
    chosen: analysis.chosen,
    exclusions: analysis.exclusions,
  });
  if (args.analyzeOnly) {
    verdict.status = "analyzed";
    verdict.detail = "analysis bundle written; generation not run (--analyze-only)";
    finish(0);
  }
  if (analysis.chosenIndex === null || analysis.chosenIndex === undefined) {
    verdict.status = "no-eligible-finding";
    verdict.detail =
      analysis.findings === 0
        ? "analysis produced no findings (no code at the address, or nothing detected)"
        : `no PoC-eligible finding (exclusions: ${JSON.stringify(analysis.exclusions)})`;
    finish(3);
  }

  // 2. Generate the review + PoC for the chosen finding.
  const gen = await bridge("generate", {
    contractName: analysis.contractName,
    findingIndex: analysis.chosenIndex,
    outDir,
  });
  if (gen.source !== "openrouter") {
    verdict.status = "untested-generation-fallback";
    verdict.detail =
      "AI review fell back to the structured template — no AI PoC was generated; this address is UNTESTED, not failed";
    finish(4);
  }
  let code = readFileSync(join(outDir, "poc-generated.sol"), "utf8");

  // Wrap a bare snippet the way the workbench does before a run.
  const wrapped = await bridge("wrap", { code });
  if (wrapped.testFile) code = wrapped.testFile;

  // 3. Execute on a fork. RPCs rotate through the chain's public list
  // on RPC/fork failures only — never on a verdict, never on a
  // compile error (the app's repair contract handles those, once).
  const rpcs = args.rpc || process.env.POC_RPC_URL ? [args.rpc || process.env.POC_RPC_URL] : analysis.rpcUrls;
  if (!rpcs || rpcs.length === 0) {
    console.error("no RPC URL available for the fork run");
    verdict.status = "infra-error";
    verdict.detail = "no RPC URL available";
    finish(1);
  }
  const work = mkdtempSync(join(tmpdir(), "poc-audit-address-"));
  try {
    mkdirSync(join(work, "test"), { recursive: true });
    mkdirSync(join(work, "src"), { recursive: true });
    cpSync(join(REPO_ROOT, "foundry", "foundry.toml"), join(work, "foundry.toml"));
    const forgeStdDest = join(work, "lib", "forge-std");
    const candidates = [
      process.env.FORGE_STD_PATH,
      join(REPO_ROOT, "foundry", "lib", "forge-std"),
    ].filter(Boolean);
    const found = candidates.find((p) => existsSync(join(p, "src", "Test.sol")));
    if (found) cpSync(found, forgeStdDest, { recursive: true });
    else {
      console.log("fetching forge-std into the work project...");
      const clone = await run(
        "git",
        ["clone", "--depth", "1", "-q", "https://github.com/foundry-rs/forge-std", forgeStdDest],
        { timeout: 120_000 },
      );
      if (clone.code !== 0) throw new Error(`forge-std clone failed: ${clone.stderr.slice(-300)}`);
    }

    let repairs = 0;
    let lastRun = null;
    let lastClass = null;
    for (let attempt = 0; attempt < rpcs.length; attempt++) {
      const rpc = rpcs[attempt];
      verdict.rpcUsed = rpc;
      lastRun = await runForge(work, rpc, args.address, block, code);
      writeFileSync(join(outDir, "forge.log"), lastRun.logs, "utf8");
      writeFileSync(join(outDir, "PoC.t.sol"), code, "utf8");
      lastClass = await bridge("classify", { logs: lastRun.logs });

      if (lastClass.rpcOrForkFailure && attempt < rpcs.length - 1) {
        console.log(`RPC/fork failure on ${rpc} — rotating to the next endpoint`);
        continue;
      }
      if (lastClass.compileError && repairs === 0) {
        // The app's repair contract: feed the compiler output back
        // once, re-run the fixed PoC once. No second repair.
        const repair = await bridge("repair", {
          contractName: analysis.contractName,
          code,
          logs: lastRun.logs,
          outDir,
        });
        if (repair.fixedCode) {
          repairs += 1;
          code = repair.fixedCode;
          lastRun = await runForge(work, rpc, args.address, block, code);
          writeFileSync(join(outDir, "forge.log"), lastRun.logs, "utf8");
          writeFileSync(join(outDir, "PoC.t.sol"), code, "utf8");
          lastClass = await bridge("classify", { logs: lastRun.logs });
        }
      }
      break;
    }

    verdict.repairs = repairs;
    verdict.testsPassed = lastRun.passed;
    verdict.testsFailed = lastRun.failed;
    verdict.durationMs = lastRun.durationMs;
    // Mirror src/lib/audit/poc-outcome.ts semantics: a pass means the
    // exploit reproduced on the fork only; ok-with-failures is a real
    // non-reproduction; zero matched tests is no_tests, never a pass.
    if (lastRun.timedOut || (lastClass.rpcOrForkFailure && lastRun.passed + lastRun.failed === 0)) {
      verdict.status = "infra-error";
      verdict.detail = lastRun.timedOut
        ? `forge timed out after ${FORGE_TIMEOUT_MS}ms`
        : "RPC/fork failure on every endpoint — no verdict was produced";
      finish(1);
    }
    if (lastClass.compileError) {
      verdict.status = "error";
      verdict.detail = "PoC did not compile (after the one allowed repair)";
      finish(0);
    }
    if (lastRun.passed + lastRun.failed === 0) {
      verdict.status = "no_tests";
      verdict.detail = "forge matched zero tests under --match-contract PoC";
      finish(0);
    }
    verdict.status = lastRun.failed === 0 ? "passed" : "failed";
    verdict.detail =
      lastRun.failed === 0
        ? "exploit reproduced on the fork (fork-only verdict — nothing real moved)"
        : "PoC ran and did not reproduce";
    finish(0);
  } finally {
    if (!args.keepWork) {
      try {
        rmSync(work, { recursive: true, force: true });
      } catch { /* best-effort cleanup */ }
    } else {
      console.log(`work dir kept: ${work}`);
    }
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
