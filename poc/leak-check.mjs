#!/usr/bin/env node
// poc/leak-check.mjs
//
// Did a failed settleBet leak a reveal while the bet was still claimable?
//
// A reverted transaction still publishes its calldata. settleBet(reveal, blockHash)
// carries the reveal in the clear, so a settlement that FAILS hands the preimage to
// anyone reading the chain — while the bet may still be inside its 250-block window.
// That would be the real vulnerability: the gambler gets the operator's option.
//
// But a failed settle is usually a retry against a bet that is already settled,
// already refunded, or expired — in which case the reveal is worthless. So this
// classifies each failed call instead of assuming:
//
//   never placed        the reveal matches no bet (a typo, or a reveal for a bet
//                       whose commit was never placed)
//   already processed   totalAmount == 0: settled or refunded before this attempt
//   expired             past placeBlock + 250 at the moment of the failure
//   LIVE                inside the window and still unprocessed -> the reveal leaked
//                       while the bet could still be settled by anyone
//
// Usage:
//   node poc/leak-check.mjs --address 0x… --rpc https://api.blockscout.com/1/json-rpc \
//     --txs 0xaaa,0xbbb,…            [--headers "Authorization: Bearer …"]
//   node poc/leak-check.mjs --address 0x… --rpc … --txlist   # fetch failed txs from blockscout
//
// Read-only.

import http from "node:http";
import https from "node:https";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { keccak256 } = require("js-sha3");

const SETTLE_SEL = "0x" + keccak256("settleBet(uint256,bytes32)").slice(0, 8);
const GETBET_SEL = "0x" + keccak256("getBet(uint256)").slice(0, 8);
const EXPIRATION = 250;
const BLOCKSCOUT = process.env.BLOCKSCOUT_URL ?? "https://eth.blockscout.com";

const argv = process.argv.slice(2);
const arg = (name, dflt = null) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : dflt;
};
const ADDRESS = arg("--address");
const RPC = arg("--rpc");
const TXS = arg("--txs");
const TXLIST = argv.includes("--txlist");
const HEADERS = arg("--headers");
if (!ADDRESS || !RPC || (!TXS && !TXLIST)) {
  console.error(`usage: node poc/leak-check.mjs --address 0x… --rpc URL (--txs 0x…,0x… | --txlist)
       [--headers "Authorization: Bearer …"]`);
  process.exit(2);
}

const strip0x = (h) => (h.startsWith("0x") ? h.slice(2) : h);
const word = (data, i) => strip0x(data).slice(i * 64, i * 64 + 64);
const toBig = (hexWord) => BigInt("0x" + (hexWord || "0"));
const toHexWord = (n) => BigInt(n).toString(16).padStart(64, "0");
const commitOf = (reveal) => "0x" + keccak256(Buffer.from(toHexWord(reveal), "hex"));

function headers() {
  const out = { "content-type": "application/json" };
  for (const part of (HEADERS ?? process.env.RPC_HEADERS ?? "").split(",")) {
    const i = part.indexOf(":");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

function getJson(url) {
  const u = new URL(url);
  const lib = u.protocol === "https:" ? https : http;
  return new Promise((resolve, reject) => {
    const req = lib.get(
      { hostname: u.hostname, port: u.port || undefined, path: u.pathname + u.search, timeout: 30_000, headers: headers() },
      (res) => {
        let t = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (t += c));
        res.on("end", () => {
          try {
            resolve(JSON.parse(t));
          } catch {
            reject(new Error(`non-JSON from ${u.pathname}`));
          }
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
  });
}

let id = 0;
function rpc(method, params) {
  const u = new URL(RPC);
  const lib = u.protocol === "https:" ? https : http;
  const body = JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params });
  return new Promise((resolve, reject) => {
    const req = lib.request(
      {
        hostname: u.hostname,
        port: u.port || undefined,
        path: u.pathname + u.search,
        method: "POST",
        timeout: 30_000,
        headers: { ...headers(), "content-length": Buffer.byteLength(body) },
      },
      (res) => {
        let t = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (t += c));
        res.on("end", () => {
          let j;
          try {
            j = JSON.parse(t);
          } catch {
            return reject(new Error(`non-JSON reply (${res.statusCode})`));
          }
          if (j.error) return reject(new Error(`${method}: ${j.error.message ?? JSON.stringify(j.error)}`));
          resolve(j.result);
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

async function failedSettleTxs() {
  if (TXS) return TXS.split(",").map((s) => s.trim()).filter(Boolean);
  const body = await getJson(
    `${BLOCKSCOUT}/api?module=account&action=txlist&address=${ADDRESS}&sort=asc&page=1&offset=1000`,
  );
  const rows = Array.isArray(body.result) ? body.result : [];
  return rows
    .filter((r) => String(r.isError) === "1" && String(r.input ?? "").toLowerCase().startsWith(SETTLE_SEL))
    .map((r) => r.hash);
}

async function classify(txHash) {
  const tx = await rpc("eth_getTransactionByHash", [txHash]);
  if (!tx || !tx.input || !tx.input.toLowerCase().startsWith(SETTLE_SEL)) {
    return { tx: txHash, verdict: "not a settleBet" };
  }
  // Drop the 4-byte selector before indexing words: `word()` counts 32-byte slots
  // from the start of the buffer, and the selector is 8 hex chars, so reading
  // word(input, 1) off the raw input lands 8 characters into the reveal and decodes
  // garbage. (Same mistake I made with the ABI encoder earlier.)
  const callData = strip0x(tx.input).slice(8);
  const reveal = toBig(word(callData, 0));
  const failedAt = Number(BigInt(tx.blockNumber ?? "0x0"));
  const commit = commitOf(reveal);

  const raw = await rpc("eth_call", [{ to: ADDRESS, data: GETBET_SEL + toHexWord(commit) }, "latest"]);
  const d = strip0x(raw);
  // getBet returns (uint numberOfBets, uint[] amount, uint totalAmount, uint8 modulo,
  //                  uint40 placeBlockNumber, uint40[] mask, uint8 gameId, address gambler)
  // numberOfBets at slot 0; totalAmount and placeBlockNumber are behind dynamic arrays,
  // so read the offsets.
  // Head slots, in declaration order: 0 numberOfBets, 1 offset(amount[]),
  // 2 totalAmount, 3 modulo, 4 placeBlockNumber, 5 offset(mask[]), 6 gameId, 7 gambler.
  // totalAmount and placeBlockNumber are STATIC, so they sit in the head — reading
  // them from behind the amount[] offset (as I first did) reads array data instead.
  const numberOfBets = Number(toBig(word(d, 0)));
  const totalAmount = toBig(word(d, 2));
  const placeBlock = Number(toBig(word(d, 4)));

  const base = { tx: txHash, commit, reveal: reveal.toString(), failedAt, placeBlock, numberOfBets };
  if (placeBlock === 0) return { ...base, verdict: "never placed" };
  if (totalAmount === 0n) return { ...base, verdict: "already processed" };
  if (failedAt > placeBlock + EXPIRATION) return { ...base, verdict: "expired" };
  return { ...base, verdict: "LIVE", intoWindow: failedAt - placeBlock };
}

async function main() {
  const txs = await failedSettleTxs();
  console.log(`contract      ${ADDRESS}`);
  console.log(`failed settle ${txs.length} transaction(s)`);
  console.log("");
  const rows = [];
  for (const tx of txs) {
    try {
      rows.push(await classify(tx));
    } catch (err) {
      rows.push({ tx, verdict: `error: ${err instanceof Error ? err.message : String(err)}` });
    }
  }
  for (const r of rows) {
    const extra = r.verdict === "LIVE" ? `  +${r.intoWindow} blocks into the window` : "";
    console.log(`${r.verdict.padEnd(17)} ${r.tx}${extra}`);
    if (r.commit) console.log(`  commit ${r.commit}  reveal ${r.reveal}  placed ${r.placeBlock}  failed ${r.failedAt}`);
  }
  const live = rows.filter((r) => r.verdict === "LIVE");
  console.log("");
  if (live.length > 0) {
    console.log(`${live.length} settlement(s) FAILED WHILE THE BET WAS STILL LIVE.`);
    console.log("Those reveals were public and the bets were still settleable by anyone who read");
    console.log("the failed transaction — the operator's option, handed to the gambler.");
  } else {
    console.log("No reveal leaked while a bet was live. Every failed settle was against a bet");
    console.log("that was already processed, expired, or never placed — so those reveals were");
    console.log("worthless and this is not an exploit path.");
  }
}

main().catch((err) => {
  console.error(`failed: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
