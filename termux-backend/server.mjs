// termux-backend/server.mjs
// Zero-dependency local backend for SmartKontrakt's Foundry fork PoC.
// Runs on Jer's phone under Termux. The Vercel app (same device, browser)
// talks to it at http://127.0.0.1:8787. Binds loopback ONLY — never exposed.
//
// The Vercel app can never shell out to forge (serverless). This server
// runs on Jer's own device and shells out to HIS forge binary, HIS code,
// HIS RPC. Fork-only: `forge test --fork-url` executes against an in-memory
// copy of chain state. No broadcast, no keys, no --ffi, ever.
//
// Safety properties (enforced, not just documented):
// - Binds 127.0.0.1 only. No LAN, no public exposure.
// - Never passes --ffi; the scaffold's foundry.toml also sets ffi = false,
//   so test code cannot shell out from inside the EVM.
// - Child env is scrubbed: only PATH/HOME/TMPDIR + the POC_* vars + the
//   RPC URL. vm.envOr inside a test can never see the parent's secrets.
// - One run at a time (409 "busy" otherwise) — forge is heavy on a phone.
// - 120s forge timeout, SIGKILL on expiry. Temp dir always cleaned up.
// - testCode capped at 200KB; forge output capped at 50KB (tail).

import http from "node:http";
import { spawn, execFile } from "node:child_process";
import fs from "node:fs/promises";
import fsSync from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PORT = Number.parseInt(process.env.PORT ?? "8787", 10) || 8787;
const HOST = "127.0.0.1";
const FORGE_TIMEOUT_MS = 120_000;
const INSTALL_TIMEOUT_MS = 60_000;
const LOG_CAP = 50 * 1024; // chars kept from forge output (tail — the summary is at the end)
const COLLECT_CAP = 256 * 1024; // chars collected in memory, hard bound
const MAX_TEST_CODE = 200 * 1024; // chars
const MAX_BODY = 1024 * 1024; // bytes
// RPC provider rotation order — same as the workbench/worker
// (address-fetcher.ts): PublicNode, drpc, 1rpc.io first; Cloudflare and
// llamrpc last. eth.llamarpc.com is currently dead (HTTP 525) but stays
// in the list in case it comes back.
const RPC_PROVIDERS = [
  "https://ethereum.publicnode.com",
  "https://eth.drpc.org",
  "https://1rpc.io/eth",
  "https://cloudflare-eth.com",
  "https://eth.llamarpc.com",
  "https://arb1.arbitrum.io/rpc",
  "https://arbitrum.llamarpc.com",
  "https://arbitrum-one.publicnode.com",
  "https://1rpc.io/arb",
  "https://mainnet.base.org",
  "https://base.llamarpc.com",
  "https://base.publicnode.com",
  "https://mainnet.optimism.io",
  "https://polygon-rpc.com",
  "https://bsc-dataseed.binance.org",
];
// Repo layout: termux-backend/ and foundry/ are siblings at the repo root.
const SCAFFOLD_DIR =
  process.env.FOUNDRY_DIR ??
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "foundry");

let busy = false;

function sendJson(res, status, obj) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(obj));
}

function commandAvailable(cmd) {
  return new Promise((resolve) => {
    execFile(cmd, ["--version"], { timeout: 5000 }, (err) => resolve(!err));
  });
}

/** Spawn a command, collect combined stdout+stderr, enforce a timeout. Never throws. */
function runWithTimeout(cmd, args, { cwd, timeoutMs, env }) {
  return new Promise((resolve) => {
    let output = "";
    let truncated = false;
    let timedOut = false;
    let settled = false;
    let timer;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve(result);
    };
    let child;
    try {
      child = spawn(cmd, args, { cwd, env });
    } catch (err) {
      finish({ output: `spawn failed: ${err?.message ?? err}`, timedOut: false, spawnError: true, code: null });
      return;
    }
    timer = setTimeout(() => {
      timedOut = true;
      try {
        child.kill("SIGKILL");
      } catch {
        // already gone — close handler will finish
      }
    }, timeoutMs);
    const onData = (chunk) => {
      if (truncated) return;
      const s = chunk.toString("utf8");
      if (output.length + s.length > COLLECT_CAP) {
        output += s.slice(0, COLLECT_CAP - output.length);
        truncated = true;
      } else {
        output += s;
      }
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.on("error", (err) =>
      finish({ output: `${output}\n[spawn failed: ${err.message}]`, timedOut: false, spawnError: true, code: null }),
    );
    child.on("close", (code, signal) =>
      finish({ output, timedOut, spawnError: false, code, signal }),
    );
  });
}

function tailCap(text) {
  if (text.length <= LOG_CAP) return text;
  return "[…output truncated, showing last 50KB]\n" + text.slice(-LOG_CAP);
}

/** Candidate RPCs: the caller's pinned URL first, then user list, then the provider list (deduped). */
function candidateRpcs(preferred, userList) {
  const out = [];
  const supplied = [preferred, ...(Array.isArray(userList) ? userList : [])].filter(Boolean);
  const list = supplied.length ? supplied : RPC_PROVIDERS;
  for (const u of list) {
    if (typeof u === "string") {
      const trimmed = u.trim();
      if (trimmed.length > 0 && !out.includes(trimmed)) {
        out.push(trimmed);
      }
    }
  }
  if (out.length === 0) {
    out.push("https://ethereum.publicnode.com");
  }
  return out;
}

/** Strong signals of an RPC/transport/fork-setup failure in forge output. */
const RPC_ERROR_RE =
  /invalid rpc url|vm\.createSelectFork|vm\.createFork|createSelectFork|createFork|HTTP error|failed to (fetch|get).*chain|failed to fetch|error sending request|connection (refused|reset|aborted|timed? ?out)|connect timed? ?out|request timed? ?out|operation timed? ?out|rate ?limit|too many requests|\b429\b|\b502\b|\b503\b|\b504\b|\b525\b|failed to (instantiate|create|setup).*fork|fork.*(instantiation|creation) failed|Failed to get (chain|block)|eth_chainId|JSON-RPC.*error|could not resolve host|DNS.*lookup failed|transport error/i;

/**
 * Should a failed forge run be retried on the next RPC provider?
 * Never retry on a compile error (another RPC won't fix Solidity syntax).
 * Retry when forge failed due to an RPC, transport, or fork-setup failure
 * (even if Forge reported a failing test during setUp()), so all candidate
 * providers in the list are tested before giving up.
 */
function shouldRetryRpc(output) {
  if (!output) return false;
  // Compile errors should not be retried with a different RPC
  if (/Compiler run failed|compilation failed|failed to compile|error\[\d+\]|ParserError|DeclarationError|TypeError/i.test(output)) {
    return false;
  }
  // Strong RPC/fork setup failure: always retry on next provider!
  if (RPC_ERROR_RE.test(output)) {
    return true;
  }
  // If tests ran to completion without any RPC failure, verdict is final
  if (/Ran \d+ test/i.test(output)) {
    return false;
  }
  return false;
}

function validateRun(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return "body must be a JSON object";
  if (typeof body.address !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(body.address)) {
    return "address must be 0x + 40 hex chars";
  }
  if (typeof body.testCode !== "string" || body.testCode.length === 0) {
    return "testCode must be a non-empty string";
  }
  if (body.testCode.length > MAX_TEST_CODE) return "testCode exceeds 200KB cap";
  if (
    body.blockNumber !== undefined &&
    (!Number.isInteger(body.blockNumber) || body.blockNumber < 0)
  ) {
    return "blockNumber must be a non-negative integer";
  }
  if (body.rpcUrl !== undefined) {
    if (typeof body.rpcUrl !== "string") return "rpcUrl must be a string";
    try {
      const u = new URL(body.rpcUrl);
      if (u.protocol !== "http:" && u.protocol !== "https:") return "rpcUrl must be http(s)";
    } catch {
      return "rpcUrl is not a valid URL";
    }
  }
  if (body.rpcUrls !== undefined) {
    if (!Array.isArray(body.rpcUrls)) return "rpcUrls must be an array of strings";
  }
  return null;
}

async function runForgeTest({ address, testCode, blockNumber, rpcUrl, rpcUrls }) {
  const started = Date.now();
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "sk-poc-"));
  try {
    // Scaffold: foundry.toml + src/ + lib/ (forge-std) from the repo copy.
    // If foundry.toml is missing the server was started outside the repo.
    try {
      await fs.cp(path.join(SCAFFOLD_DIR, "foundry.toml"), path.join(tmp, "foundry.toml"));
    } catch {
      throw new Error(
        `foundry scaffold not found at ${SCAFFOLD_DIR} — start the server from the repo root (see termux-backend/README.md)`,
      );
    }
    const srcDir = path.join(SCAFFOLD_DIR, "src");
    if (fsSync.existsSync(srcDir)) await fs.cp(srcDir, path.join(tmp, "src"), { recursive: true });
    const libDir = path.join(SCAFFOLD_DIR, "lib");
    if (fsSync.existsSync(path.join(libDir, "forge-std"))) {
      await fs.cp(libDir, path.join(tmp, "lib"), { recursive: true });
    } else {
      // Fresh clone without forge-std: fetch it into the temp project.
      const inst = await runWithTimeout("forge", ["install", "foundry-rs/forge-std"], {
        cwd: tmp,
        timeoutMs: INSTALL_TIMEOUT_MS,
        env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "" },
      });
      if (inst.spawnError || inst.code !== 0) {
        throw new Error(
          "forge-std is missing and `forge install foundry-rs/forge-std` failed — run it once in foundry/ (see scripts/termux-setup.sh), then retry",
        );
      }
    }
    await fs.mkdir(path.join(tmp, "test"), { recursive: true });

    // Rotate RPC providers on transport/fork-setup failure. A test verdict
    // (tests ran, pass or fail) is final — only a pre-test RPC failure
    // retries on the next provider. Timeouts and missing forge binaries
    // never retry (another provider won't fix those).
    let lastOutput = "";
    let lastRpc = null;
    const candidates = candidateRpcs(rpcUrl, rpcUrls);
    for (const candidate of candidates) {
      lastRpc = candidate;
      const args = ["test", "--fork-url", candidate];
      if (blockNumber !== undefined) args.push("--fork-block-number", String(blockNumber));
      
      // Auto-detect test contract name (e.g. PoC, CrowdsaleExploitTest, etc.)
      const contractMatch = testCode.match(/contract\s+([A-Za-z0-9_]+)\s+is\s+[^{]*\bTest\b/);
      if (contractMatch && contractMatch[1]) {
        args.push("--match-contract", contractMatch[1]);
      } else {
        args.push("--match-contract", "PoC");
      }
      args.push("-vvv");

      // Auto-substitute candidate RPC into createSelectFork / createFork if empty string
      let candidateTestCode = testCode;
      if (/vm\.(createSelectFork|createFork)\(\s*["']\s*["']\s*([,)])/.test(candidateTestCode)) {
        candidateTestCode = candidateTestCode.replace(
          /vm\.(createSelectFork|createFork)\(\s*["']\s*["']\s*([,)])/g,
          `vm.$1("${candidate}"$2`
        );
      }
      await fs.writeFile(path.join(tmp, "test", "PoC.t.sol"), candidateTestCode, "utf8");

      // Scrubbed child env: a test's vm.envOr must never see the parent's secrets.
      const childEnv = {
        PATH: process.env.PATH ?? "",
        HOME: process.env.HOME ?? "",
        TMPDIR: process.env.TMPDIR ?? os.tmpdir(),
        ETH_RPC_URL: candidate, // resolves the [rpc_endpoints] mainnet alias in foundry.toml
        POC_TARGET: address,
        POC_FORK_BLOCK: String(blockNumber ?? 0),
        POC_RPC_URL: candidate,
        RPC_URL: candidate,
        MAINNET_RPC_URL: candidate,
        ARBITRUM_RPC_URL: candidate,
        BASE_RPC_URL: candidate,
        OPTIMISM_RPC_URL: candidate,
        POLYGON_RPC_URL: candidate,
        BSC_RPC_URL: candidate,
      };
      const result = await runWithTimeout("forge", args, {
        cwd: tmp,
        timeoutMs: FORGE_TIMEOUT_MS,
        env: childEnv,
      });
      const durationMs = Date.now() - started;
      if (result.spawnError) {
        return {
          ok: false,
          passed: false,
          logs: tailCap(result.output),
          durationMs,
          rpcUrl: candidate,
          error: "forge failed to start — is Foundry installed? Run scripts/termux-setup.sh in Termux.",
        };
      }
      if (result.timedOut) {
        return {
          ok: false,
          passed: false,
          logs: tailCap(result.output),
          durationMs,
          rpcUrl: candidate,
          error: "forge test timed out after 120s",
        };
      }
      if (result.code === 0) {
        return {
          ok: true, // forge ran to completion; passed says whether the PoC reproduced
          passed: true,
          logs: tailCap(result.output),
          durationMs,
          rpcUrl: candidate,
        };
      }
      lastOutput = result.output;
      if (!shouldRetryRpc(result.output)) {
        // Tests ran and failed (a real verdict), or a compile error.
        return {
          ok: true,
          passed: false,
          logs: tailCap(result.output),
          durationMs,
          rpcUrl: candidate,
        };
      }
      // RPC-looking failure — fall through to the next provider.
      console.log(
        `[${new Date().toISOString()}] /run-poc RPC ${candidate} failed (transport/fork) — rotating to next provider`,
      );
    }
    // Every provider failed with RPC-looking errors.
    return {
      ok: false,
      passed: false,
      logs: tailCap(lastOutput),
      durationMs: Date.now() - started,
      rpcUrl: lastRpc,
      error: `All RPC providers failed (tried ${candidates.length}) — last: ${lastRpc}`,
    };
  } finally {
    await fs.rm(tmp, { recursive: true, force: true }).catch(() => {});
  }
}

const server = http.createServer((req, res) => {
  // Localhost-only backend; permissive CORS is fine here.
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? HOST}`);

  if (req.method === "GET" && url.pathname === "/health") {
    Promise.all([commandAvailable("forge"), commandAvailable("anvil")]).then(([forge, anvil]) => {
      sendJson(res, 200, { ok: true, forge, anvil });
    });
    return;
  }

  if (req.method === "POST" && url.pathname === "/run-poc") {
    const chunks = [];
    let bodyBytes = 0;
    let tooBig = false;
    req.on("data", (chunk) => {
      bodyBytes += chunk.length;
      if (bodyBytes > MAX_BODY) {
        tooBig = true;
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("close", () => {
      if (tooBig) {
        sendJson(res, 413, { error: "request body exceeds 1MB cap" });
        return;
      }
    });
    req.on("end", async () => {
      let body;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        sendJson(res, 400, { error: "body must be valid JSON" });
        return;
      }
      const problem = validateRun(body);
      if (problem) {
        sendJson(res, 400, { error: problem });
        return;
      }
      if (busy) {
        sendJson(res, 409, { error: "busy — a PoC run is already in flight" });
        return;
      }
      busy = true;
      // No pinned RPC → candidateRpcs starts with the provider list
      // (PublicNode first). A pinned RPC is tried first, then rotates.
      const rpcUrl = body.rpcUrl ?? process.env.ETH_RPC_URL;
      try {
        const result = await runForgeTest({
          address: body.address,
          testCode: body.testCode,
          blockNumber: body.blockNumber,
          rpcUrl,
          rpcUrls: body.rpcUrls,
        });
        console.log(
          `[${new Date().toISOString()}] /run-poc address=${body.address} passed=${result.passed} ok=${result.ok} durationMs=${result.durationMs} rpc=${result.rpcUrl ?? "-"}${result.error ? ` error=${result.error}` : ""}`,
        );
        sendJson(res, result.ok ? 200 : 500, result);
      } catch (err) {
        console.log(
          `[${new Date().toISOString()}] /run-poc address=${body.address} error=${err?.message ?? err}`,
        );
        sendJson(res, 500, { ok: false, passed: false, logs: "", durationMs: 0, error: String(err?.message ?? err) });
      } finally {
        busy = false;
      }
    });
    return;
  }

  sendJson(res, 404, { error: "not found" });
});

server.listen(PORT, HOST, () => {
  console.log(`SmartKontrakt Foundry backend listening on http://${HOST}:${PORT} (loopback only)`);
  console.log(`Scaffold: ${SCAFFOLD_DIR}`);
});

// Exported for unit tests (the rotation helpers); importing this module
// still starts the server, so tests must close it when done.
export { candidateRpcs, shouldRetryRpc, server };

