#!/usr/bin/env node
/**
 * AI-PoC proof suite — one end-to-end proof per fallback-library type.
 *
 * For each type in foundry/poc-fallbacks/index.json (47 on current
 * main; the suite covers every type the index lists):
 *   1. deploy the type's vulnerable fixture (fixtures/*.sol, manifest.json)
 *      to a local anvil and run its setup steps;
 *   2. build the AI-review prompt through the app's REAL prompt path
 *      (prompt-path.ts -> src/lib/audit/ai-review.server.ts
 *      buildAiReviewPrompt + selectPocFallbacks);
 *   3. get a PoC for the finding:
 *        --dry-run: the type's fallback TEMPLATE from the app's own
 *          POC_FALLBACK_TEMPLATES map, with the manifest's TODO
 *          adaptations applied (what a human would fill in by hand).
 *          Statuses are labeled DRY-*; no LLM is called.
 *        live: generateAiSecurityReview() from the app (prompt ->
 *          OpenRouter -> JSON extraction). A reply that falls back to
 *          the template (source != "openrouter") is a generation
 *          FAILURE, never a silent pass.
 *   4. wrap a bare snippet via the app's poc-wrap (same rule the
 *      workbench uses: no `contract PoC is Test` -> wrap);
 *   5. run it exactly like the Termux backend does: test/PoC.t.sol,
 *      `forge test --match-contract PoC`, POC_TARGET / POC_RPC_URL /
 *      POC_FORK_BLOCK in env, 120s cap. Zero matched tests = FAILURE.
 *      PASSED means every matched test passed, including the
 *      template's observable-state exploit assertion -- never merely
 *      "the call returned".
 *   6. on a compile error in live mode, apply the app's repair
 *      contract once (deep-agent.server.ts repairPocCode: feed the
 *      compiler output back, re-run the fixed PoC once, no second
 *      repair -- foundry-backend.ts runSmartPoc).
 *
 * Usage:
 *   node scripts/ai-poc-proof/run.mjs --dry-run [--type 01] [--keep-work]
 *   OPENROUTER_API_KEY=... node scripts/ai-poc-proof/run.mjs [--type 01]
 *
 * Live mode REQUIRES the key (env OPENROUTER_API_KEY; OPENROUTER_MODEL
 * overrides the model, default = the repo's resolveOpenRouterConfig
 * default). Without a key, live mode exits before touching anything.
 * The key is only ever read by the app modules via prompt-path.ts;
 * this runner never prints or persists it.
 *
 * Output: a per-type table on stdout and results.json next to this
 * file. Exit code 0 only when every selected type PASSED.
 */
import { spawn, execFile } from "node:child_process";
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
const FORGE_TIMEOUT_MS = 120_000; // mirrors termux-backend/server.mjs

// Anvil's published default test accounts (local chain only, never real
// keys). acct2 is only ever an address (setup approves it; the template
// pranks it) so its key is not needed.
const ACCOUNTS = [
  {
    address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    key: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  },
  {
    address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    key: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  },
  { address: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", key: null },
];
// forge-std makeAddr("attacker") -- deterministic across forge versions;
// measured with forge 1.8.5. Used only as the type-36 Merkle claimant.
const MAKEADDR_ATTACKER = "0x9dF0C6b0066D5317aA5b38B36850548DaCCa6B4e";

// Compile-error detector mirrored from src/lib/audit/foundry-backend.ts
// isPocCompileError (the repairable class). Kept as a literal copy so
// the runner needs no browser-side module graph.
const COMPILE_ERROR_RE =
  /(compiler run failed|compilation failed|failed to compile|error\[\d+\]|error\s*\(\d+\)|parsererror|declarationerror|typeerror)/i;

function parseArgs(argv) {
  const args = { dryRun: false, type: null, keepWork: false, port: 18545, work: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--dry-run") args.dryRun = true;
    else if (a === "--keep-work") args.keepWork = true;
    else if (a === "--type") args.type = argv[++i];
    else if (a === "--port") args.port = Number(argv[++i]);
    else if (a === "--work") args.work = argv[++i];
    else if (a === "--help" || a === "-h") args.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  return args;
}

function findBin(name) {
  const home = process.env.HOME ?? "";
  const candidates = [join(home, ".foundry", "bin", name), name];
  return candidates[0] && existsSync(candidates[0]) ? candidates[0] : name;
}

// The bridge (prompt-path.ts) is TypeScript. It runs through tsx — the
// repo-local node_modules/.bin/tsx when present, else `npx -y tsx` (the
// same way the pipeline worker runs on the phone). Deliberately NOT
// `node --experimental-strip-types`: distro Node builds can ship without
// TypeScript support compiled in — observed on the S24 proot install
// (Node v22.22.1, ERR_NO_TYPESCRIPT) on 2026-10-22, where strip-types
// exits with empty stdout and the bridge call fails as "non-JSON".
const TSX_LOCAL = join(REPO_ROOT, "node_modules", ".bin", "tsx");
function bridgeCommand() {
  return existsSync(TSX_LOCAL)
    ? { cmd: TSX_LOCAL, prefix: [] }
    : { cmd: "npx", prefix: ["-y", "tsx"] };
}
const FORGE = findBin("forge");
const ANVIL = findBin("anvil");
const CAST = findBin("cast");

async function run(cmd, args, opts = {}) {
  const { stdout, stderr } = await execFileP(cmd, args, {
    timeout: opts.timeout ?? 60_000,
    maxBuffer: 16 * 1024 * 1024,
    cwd: opts.cwd,
    env: opts.env ?? process.env,
  }).catch((err) => {
    // execFile rejects on non-zero exit; forge test failing is a RESULT,
    // not a runner error, so hand the output back either way.
    if (err && typeof err.stdout === "string") {
      return { stdout: err.stdout, stderr: err.stderr ?? "", code: err.code ?? 1 };
    }
    throw err;
  });
  return { stdout, stderr, code: 0 };
}

/** Call the prompt-path bridge; returns the parsed JSON object it prints. */
async function harness(cmd, payload, timeout = 60_000) {
  const bridge = bridgeCommand();
  const { stdout, stderr } = await run(
    bridge.cmd,
    [...bridge.prefix, join(SUITE_DIR, "prompt-path.ts"), cmd, JSON.stringify(payload)],
    { cwd: REPO_ROOT, timeout },
  );
  const lines = stdout.trim().split("\n").filter(Boolean);
  const last = lines[lines.length - 1];
  try {
    return JSON.parse(last);
  } catch {
    // Surface the bridge's own error text — discarding stderr here once
    // reduced a precise ERR_NO_TYPESCRIPT to "non-JSON: undefined" and
    // cost a full diagnostic round-trip.
    const errTail = (stderr ?? "").trim().split("\n").slice(-6).join("\n").slice(0, 400);
    throw new Error(
      `prompt-path ${cmd} returned non-JSON: ${last?.slice(0, 300)}` +
        (errTail ? `\nbridge stderr (tail):\n${errTail}` : ""),
    );
  }
}

function resolvePlaceholders(text, ctx) {
  return text
    .replaceAll("{{target}}", ctx.target ?? "")
    .replaceAll("{{acct0}}", ACCOUNTS[0].address)
    .replaceAll("{{acct1}}", ACCOUNTS[1].address)
    .replaceAll("{{acct2}}", ACCOUNTS[2].address)
    .replaceAll("{{merkleRoot}}", ctx.merkleRoot ?? "")
    .replaceAll("{{tsPlus12h}}", ctx.tsPlus12h ?? "")
    .replace(/\{\{addr:([a-zA-Z0-9_]+)\}\}/g, (_, name) => {
      const addr = ctx.addrs[name];
      if (!addr) throw new Error(`unknown deployment placeholder: ${name}`);
      return addr;
    });
}

/** keccak256(abi.encodePacked(makeAddr("attacker"), 1 ether)) via cast. */
async function merkleRootFor36() {
  const packed =
    MAKEADDR_ATTACKER.slice(2).toLowerCase() +
    (10n ** 18n).toString(16).padStart(64, "0");
  const { stdout } = await run(CAST, ["keccak", `0x${packed}`]);
  return stdout.trim();
}

async function deployOne(work, rpc, fixtureFile, contract, args) {
  const argv = [
    "create",
    "--rpc-url",
    rpc,
    "--private-key",
    ACCOUNTS[0].key,
    "--broadcast",
    `${fixtureFile}:${contract}`,
  ];
  if (args && args.length > 0) argv.push("--constructor-args", ...args);
  const { stdout, stderr } = await run(FORGE, argv, { cwd: work, timeout: 90_000 });
  const m = (stdout + stderr).match(/Deployed to: (0x[0-9a-fA-F]{40})/);
  if (!m) {
    throw new Error(
      `forge create ${contract} failed: ${(stdout + stderr).slice(-600)}`,
    );
  }
  return m[1];
}

async function setupStep(rpc, step, ctx) {
  const to = resolvePlaceholders(step.to, ctx);
  const argv = ["send", "--rpc-url", rpc, "--private-key", ACCOUNTS[step.from ?? 0].key, to];
  if (step.sig) {
    argv.push(step.sig);
    for (const a of step.args ?? []) argv.push(resolvePlaceholders(String(a), ctx));
  }
  if (step.value) argv.push("--value", step.value);
  const { stdout, stderr } = await run(CAST, argv, { timeout: 60_000 });
  if (!/status\s+1/.test(stdout) && !stdout.includes("transactionHash")) {
    throw new Error(`setup step failed (${step.sig ?? "fund"} -> ${to}): ${(stdout + stderr).slice(-400)}`);
  }
}

/** Write test/PoC.t.sol and run forge exactly like the backend does. */
async function runForge(work, rpc, target, code) {
  writeFileSync(join(work, "test", "PoC.t.sol"), code, "utf8");
  const env = {
    ...process.env,
    POC_TARGET: target,
    POC_RPC_URL: rpc,
    POC_FORK_BLOCK: "0",
    ETH_RPC_URL: rpc,
  };
  const started = Date.now();
  const { stdout, stderr } = await run(
    FORGE,
    ["test", "--match-contract", "PoC", "-vv"],
    { cwd: work, env, timeout: FORGE_TIMEOUT_MS },
  ).catch((err) => {
    if (err && err.killed) {
      return { stdout: "", stderr: `forge timed out after ${FORGE_TIMEOUT_MS}ms`, code: -1 };
    }
    throw err;
  });
  const logs = `${stdout}\n${stderr}`;
  const summary = logs.match(/(\d+) passed; (\d+) failed/);
  const passed = summary ? Number(summary[1]) : (logs.match(/\[PASS\]/g) ?? []).length;
  const failed = summary ? Number(summary[2]) : (logs.match(/\[FAIL/g) ?? []).length;
  return { logs, passed, failed, durationMs: Date.now() - started };
}

function classify(runRes) {
  if (COMPILE_ERROR_RE.test(runRes.logs)) return { category: "compile" };
  if (runRes.passed + runRes.failed === 0) return { category: "no-tests" };
  if (runRes.failed === 0 && runRes.passed > 0) return { category: "passed" };
  return { category: "assertion" };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log("Usage: node scripts/ai-poc-proof/run.mjs --dry-run [--type 01]");
    console.log("       OPENROUTER_API_KEY=... node scripts/ai-poc-proof/run.mjs [--type 01]");
    return;
  }
  const mode = args.dryRun ? "dry" : "live";
  const manifest = JSON.parse(readFileSync(join(SUITE_DIR, "manifest.json"), "utf8"));
  const index = JSON.parse(
    readFileSync(join(REPO_ROOT, "foundry", "poc-fallbacks", "index.json"), "utf8"),
  );
  if (index.fallbacks.length !== manifest.types.length) {
    console.warn(
      `warning: index.json lists ${index.fallbacks.length} types, manifest has ${manifest.types.length}`,
    );
  }
  const types = manifest.types.filter(
    (t) => !args.type || t.id.startsWith(args.type) || t.file.startsWith(args.type),
  );
  if (types.length === 0) {
    console.error(`no types match --type ${args.type}`);
    process.exit(2);
  }

  // Live-mode preflight FIRST: no key -> exit before doing anything.
  // (In dry-run the config call doubles as a bridge health check.)
  const config = await harness("config", {});
  if (config.fatal) throw new Error(`prompt-path bridge failed: ${config.fatal}`);
  if (!args.dryRun && !config.hasKey) {
    console.error(
      "LIVE mode needs OPENROUTER_API_KEY in the environment (the repo's own " +
        "resolveOpenRouterConfig found no usable key). Nothing was run.\n" +
        "For a key-free harness check use: node scripts/ai-poc-proof/run.mjs --dry-run",
    );
    process.exit(2);
  }
  console.log(
    `mode: ${mode}${args.dryRun ? " (template stand-in, no LLM calls)" : ""} | model: ${config.model} | types: ${types.length}`,
  );

  // Verify the anvil account keys match the expected addresses.
  for (const acct of ACCOUNTS) {
    if (!acct.key) continue;
    const { stdout } = await run(CAST, ["wallet", "address", "--private-key", acct.key]);
    if (stdout.trim().toLowerCase() !== acct.address.toLowerCase()) {
      throw new Error(`anvil key/address mismatch for ${acct.address}`);
    }
  }

  // Scaffold the foundry work project (mirrors the backend: the repo's
  // foundry.toml + lib/forge-std; fixtures in src/, PoC in test/).
  const work = args.work ?? mkdtempSync(join(tmpdir(), "ai-poc-proof-"));
  mkdirSync(join(work, "src"), { recursive: true });
  mkdirSync(join(work, "test"), { recursive: true });
  mkdirSync(join(work, "lib"), { recursive: true });
  writeFileSync(
    join(work, "foundry.toml"),
    readFileSync(join(REPO_ROOT, "foundry", "foundry.toml"), "utf8"),
  );
  const forgeStdDest = join(work, "lib", "forge-std");
  if (!existsSync(forgeStdDest)) {
    const candidates = [
      process.env.FORGE_STD_PATH,
      join(REPO_ROOT, "foundry", "lib", "forge-std"),
    ].filter(Boolean);
    const found = candidates.find((p) => existsSync(join(p, "src", "Test.sol")));
    if (found) cpSync(found, forgeStdDest, { recursive: true });
    else {
      console.log("fetching forge-std into the work project...");
      await run(
        "git",
        ["clone", "--depth", "1", "-q", "https://github.com/foundry-rs/forge-std", forgeStdDest],
        { timeout: 120_000 },
      );
    }
  }
  for (const t of manifest.types) {
    cpSync(join(SUITE_DIR, "fixtures", t.fixture), join(work, "src", t.fixture));
  }
  console.log("compiling fixtures...");
  const build = await run(FORGE, ["build"], { cwd: work, timeout: 300_000 });
  if (build.code !== 0) {
    console.error((build.stdout + build.stderr).slice(-3000));
    throw new Error("fixture compilation failed -- harness bug, aborting");
  }

  // One local anvil for the whole suite.
  const rpc = `http://127.0.0.1:${args.port}`;
  const anvil = spawn(ANVIL, ["--port", String(args.port), "--silent"], {
    stdio: "ignore",
  });
  const cleanup = () => {
    try {
      anvil.kill("SIGKILL");
    } catch {}
    if (!args.keepWork && !args.work) {
      try {
        rmSync(work, { recursive: true, force: true });
      } catch {}
    }
  };
  process.on("SIGINT", () => {
    cleanup();
    process.exit(130);
  });
  try {
    let ready = false;
    for (let i = 0; i < 60 && !ready; i++) {
      try {
        const bn = await run(CAST, ["block-number", "--rpc-url", rpc], { timeout: 5_000 });
        // run() hands back output even on non-zero exit, so readiness is
        // only real when a block number actually came back.
        ready = /^\d+$/.test(bn.stdout.trim());
      } catch {
        ready = false;
      }
      if (!ready) await new Promise((r) => setTimeout(r, 500));
    }
    if (!ready) throw new Error("anvil did not become ready");

    const merkleRoot = await merkleRootFor36();
    const results = [];

    for (const t of types) {
      const startedAt = Date.now();
      const row = {
        id: t.id,
        file: t.file,
        detector: t.detector,
        scenario: t.scenario,
        status: "",
        category: "",
        detail: "",
        repairs: 0,
        testsPassed: 0,
        testsFailed: 0,
        target: "",
        durationMs: 0,
      };
      const fail = (category, detail) => {
        row.category = category;
        row.detail = detail;
        row.status = args.dryRun ? "DRY-FAIL" : "FAIL";
      };
      try {
        // 1. Deploy the fixture chain + setup on anvil.
        const ctx = {
          addrs: {},
          merkleRoot,
          target: "",
          tsPlus12h: String(Math.floor(Date.now() / 1000) + 12 * 3600),
        };
        const fixtureFile = `src/${t.fixture}`;
        for (const d of t.deployments) {
          const dargs = (d.args ?? []).map((a) => {
            const s = String(a);
            if (s.startsWith("$")) {
              const ref = ctx.addrs[s.slice(1)];
              if (!ref) throw new Error(`deployment ${t.id}: unknown $ref ${s}`);
              return ref;
            }
            return resolvePlaceholders(s, ctx);
          });
          ctx.addrs[d.name] = await deployOne(work, rpc, fixtureFile, d.contract, dargs);
        }
        ctx.target = ctx.addrs[t.target];
        row.target = ctx.target;
        for (const step of t.setup ?? []) await setupStep(rpc, step, ctx);

        const fixtureSource = readFileSync(join(SUITE_DIR, "fixtures", t.fixture), "utf8");
        const finding = {
          detector: t.detector,
          severity: "critical",
          title: t.scenario,
          summary: t.flaw,
        };

        // 2. The app's real prompt path (also proves template selection).
        const promptInfo = await harness("prompt", {
          contractName: t.contractName,
          body: fixtureSource,
          finding,
        });
        if (promptInfo.fatal) throw new Error(`prompt build failed: ${promptInfo.fatal}`);

        // 3. Obtain the PoC.
        let code;
        if (args.dryRun) {
          const tpl = await harness("template", { file: t.file, finding });
          if (tpl.fatal) throw new Error(`template fetch failed: ${tpl.fatal}`);
          code = tpl.source;
          for (const ad of t.adapt ?? []) {
            const find = ad.find;
            if (!code.includes(find)) {
              throw new Error(`adaptation anchor not found in ${t.file}: ${find.slice(0, 80)}`);
            }
            code = code.replace(find, resolvePlaceholders(ad.replace, ctx));
          }
          row.detail = `template ${t.file}; selector top pick: ${tpl.selectorTopPick ?? "none"}`;
        } else {
          const gen = await harness(
            "generate",
            { contractName: t.contractName, body: fixtureSource, finding },
            420_000,
          );
          if (gen.fatal) throw new Error(`generation crashed: ${gen.fatal}`);
          if (gen.source !== "openrouter") {
            fail(
              "generation",
              "AI review fell back to the template (source != openrouter) -- no AI PoC was generated",
            );
            results.push(row);
            continue;
          }
          code = gen.foundryTestCode;
        }

        // 4. Wrap a bare snippet via the app's poc-wrap (workbench rule).
        if (!/contract\s+PoC\s+is\s+Test/.test(code)) {
          const w = await harness("wrap", { code });
          if (w.wrapped && w.testFile) {
            code = w.testFile;
            row.detail += ` | wrapped bare snippet (${w.note ?? "poc-wrap"})`;
          } else {
            row.detail += ` | wrap failed (${w.reason ?? "unknown"}), ran raw`;
          }
        }

        // 5. Run it, backend-style.
        let runRes = await runForge(work, rpc, ctx.target, code);
        row.testsPassed = runRes.passed;
        row.testsFailed = runRes.failed;
        let cls = classify(runRes);

        // 6. One compile repair in live mode (the app's contract).
        if (cls.category === "compile" && !args.dryRun) {
          const rep = await harness(
            "repair",
            { contractName: t.contractName, code, logs: runRes.logs.slice(-8000), body: fixtureSource },
            300_000,
          );
          if (rep.fixedCode) {
            row.repairs = 1;
            code = rep.fixedCode;
            if (!/contract\s+PoC\s+is\s+Test/.test(code)) {
              const w = await harness("wrap", { code });
              if (w.wrapped && w.testFile) code = w.testFile;
            }
            runRes = await runForge(work, rpc, ctx.target, code);
            row.testsPassed = runRes.passed;
            row.testsFailed = runRes.failed;
            cls = classify(runRes);
            row.detail += " | repaired once";
          } else {
            row.detail += ` | repair failed: ${rep.error ?? "unknown"}`;
          }
        }

        if (cls.category === "passed") {
          row.status = args.dryRun ? "DRY-PASS" : "PASS";
          row.category = "passed";
          row.detail += ` | ${runRes.passed} test(s) passed`;
        } else if (cls.category === "compile") {
          fail("compile", `solc failed${row.repairs ? " even after 1 repair" : ""}: ${runRes.logs.slice(-300)}`);
        } else if (cls.category === "no-tests") {
          fail("no-tests", "forge matched zero tests under --match-contract PoC (never a pass)");
        } else {
          fail(
            "assertion",
            `exploit did not reproduce: ${runRes.failed} test(s) failed. ${runRes.logs.slice(-300)}`,
          );
        }
      } catch (err) {
        fail("infra", err instanceof Error ? err.message.slice(0, 400) : String(err));
      }
      row.durationMs = Date.now() - startedAt;
      results.push(row);
      console.log(
        `${row.status.padEnd(8)} ${row.id.padEnd(38)} ${row.category.padEnd(10)} ${row.detail.replace(/\s*\n\s*/g, " ").slice(0, 140)}`,
      );
      // OpenRouter budget: 60 req/min. Generation + a possible repair
      // are the only calls; a modest pause keeps a full live run polite.
      if (!args.dryRun) await new Promise((r) => setTimeout(r, 1100));
    }

    // Report.
    const passCount = results.filter((r) => r.category === "passed").length;
    console.log("\n===== AI-PoC proof results =====");
    console.log("type | status | category | detail");
    for (const r of results) {
      console.log(
        `${r.id} | ${r.status} | ${r.category} | ${r.detail.replace(/\s*\n\s*/g, " ").slice(0, 200)}`,
      );
    }
    console.log(`\n${passCount}/${results.length} types reproduced (${mode} mode)`);
    writeFileSync(
      join(SUITE_DIR, "results.json"),
      JSON.stringify(
        {
          generatedAt: new Date().toISOString(),
          mode,
          model: config.model,
          rpc,
          note: args.dryRun
            ? "DRY RUN: the fallback template (with manifest TODO adaptations) stood in for the AI-generated PoC. No LLM was called."
            : "LIVE run: PoCs generated by the app's generateAiSecurityReview via OpenRouter.",
          results,
        },
        null,
        1,
      ),
    );
    console.log(`results written to ${join(SUITE_DIR, "results.json")}`);
    if (passCount !== results.length) process.exitCode = 1;
  } finally {
    cleanup();
  }
}

main().catch((err) => {
  console.error(`runner aborted: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(2);
});
