#!/usr/bin/env node
// poc/probe-rpc.mjs
//
// Probe an RPC endpoint the way this tool actually reads, instead of the way a status
// page would. A plain eth_blockNumber answers happily on endpoints that refuse
// eth_getLogs outright — which is how an endpoint gets graded "healthy" and then
// produces an empty result that reads as "no bets".
//
// For each endpoint it runs, in order:
//   1. eth_blockNumber                     — is the host alive at all?
//   2. eth_getLogs, 1 block at the head    — does it serve this method at all?
//   3. eth_getLogs at <deploy block>       — does it have archive depth?
//   4. eth_getLogs, 2,000 blocks at head   — how wide a window will it take?
// with the REAL filter (your contract address + Commit topic), so a result cap
// shows up as a result cap.
//
//   node poc/probe-rpc.mjs 0x6eb0…5f0be --deploy 10455555
//   RPC_URLS="https://a,https://b" RPC_HEADERS="Authorization: Bearer …" node poc/probe-rpc.mjs 0x…
//
// No key is ever written to disk or to a commit; read it from the environment.

import http from "node:http";
import https from "node:https";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { keccak256 } = require("js-sha3");

const COMMIT_TOPIC = "0x" + keccak256("Commit(uint256)");

const argv = process.argv.slice(2);
const address = argv.find((a) => a.startsWith("0x") && a.length === 42);
const deployIdx = argv.indexOf("--deploy");
const deployBlock = deployIdx >= 0 ? Number(argv[deployIdx + 1]) : null;
if (!address) {
  console.error("usage: node poc/probe-rpc.mjs <address> [--deploy <block>]");
  process.exit(2);
}

const ENDPOINTS = (process.env.RPC_URLS ?? process.env.RPC_URL ?? "https://rpc.mevblocker.io,https://ethereum-rpc.publicnode.com,https://eth.drpc.org")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

function headers() {
  const out = { "content-type": "application/json" };
  for (const part of (process.env.RPC_HEADERS ?? "").split(",")) {
    const i = part.indexOf(":");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

let id = 0;
function call(endpoint, method, params, timeoutMs = 25_000) {
  const url = new URL(endpoint);
  const lib = url.protocol === "https:" ? https : http;
  const body = JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params });
  return new Promise((resolve) => {
    const started = Date.now();
    const req = lib.request(
      {
        hostname: url.hostname,
        port: url.port || undefined,
        path: url.pathname + url.search,
        method: "POST",
        timeout: timeoutMs,
        headers: { ...headers(), "content-length": Buffer.byteLength(body) },
      },
      (res) => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (text += c));
        res.on("end", () => {
          let json = null;
          try {
            json = JSON.parse(text);
          } catch {
            /* keep null */
          }
          resolve({
            http: res.statusCode,
            ms: Date.now() - started,
            result: json?.result,
            error: json?.error,
            raw: json ? null : text.slice(0, 120),
          });
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", (err) => resolve({ http: 0, ms: Date.now() - started, error: { message: String(err.message ?? err) } }));
    req.write(body);
    req.end();
  });
}

const describe = (r) => {
  if (r.error) return `refused: ${String(r.error.message ?? JSON.stringify(r.error)).slice(0, 90)}`;
  if (r.raw) return `non-JSON: ${r.raw}`;
  if (Array.isArray(r.result)) return `ok — ${r.result.length} logs`;
  if (typeof r.result === "string") return `ok — ${r.result}`;
  return "ok";
};

const logs = (endpoint, from, to) =>
  call(endpoint, "eth_getLogs", [
    { address, fromBlock: "0x" + from.toString(16), toBlock: "0x" + to.toString(16), topics: [COMMIT_TOPIC] },
  ]);

async function main() {
  console.log(`address   ${address}`);
  console.log(`topic     ${COMMIT_TOPIC}  (Commit(uint256))`);
  console.log(`headers   ${Object.keys(headers()).join(", ")}`);
  console.log("");
  for (const endpoint of ENDPOINTS) {
    console.log(endpoint);
    const blockNumber = await call(endpoint, "eth_blockNumber", []);
    console.log(`  eth_blockNumber              ${describe(blockNumber)}  (${blockNumber.ms}ms, http ${blockNumber.http})`);
    if (blockNumber.error || typeof blockNumber.result !== "string") {
      console.log(`  -> host or method problem; nothing else will work here
`);
      continue;
    }
    const head = Number(BigInt(blockNumber.result));

    const atHead = await logs(endpoint, head - 1, head);
    console.log(`  getLogs 1 block @ head       ${describe(atHead)}  (${atHead.ms}ms, http ${atHead.http})`);

    if (deployBlock) {
      const atDeploy = await logs(endpoint, deployBlock, deployBlock + 1);
      console.log(`  getLogs 1 block @ deploy     ${describe(atDeploy)}  (${atDeploy.ms}ms, http ${atDeploy.http})`);
      if (atDeploy.error) console.log(`  -> no archive depth: cannot read this contract's history here`);
    }

    const wide = await logs(endpoint, Math.max(0, head - 2000), head);
    console.log(`  getLogs 2000 blocks @ head   ${describe(wide)}  (${wide.ms}ms, http ${wide.http})`);
    console.log("");
  }
  console.log("Read the table, not the status code: several endpoints answer 200 with an");
  console.log("error object, and a client that takes result ?? [] reads that as 'no logs'.");
}

main().catch((err) => {
  console.error(String(err?.message ?? err));
  process.exit(1);
});
