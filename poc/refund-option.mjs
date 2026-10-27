#!/usr/bin/env node
// poc/refund-option.mjs
//
// PoC: the settlement option in BlockChainCasino (dice2.win derivative).
//
// NO FOUNDRY, NO EVM EXECUTION. This proves the finding from the chain's own data
// and the contract's own arithmetic, using JSON-RPC reads only:
//
//   The only function that pays a WIN is settleBet(reveal, blockHash), and it needs
//   `reveal` — the preimage of the commit that secretSigner signed. Only the
//   operator knows it. refundBet(commit) is permissionless but pays exactly
//   bet.totalAmount: the stake. So on any bet the house would lose, the operator
//   simply never settles, the bet expires after BET_EXPIRATION_BLOCKS (250), and
//   the gambler is refunded their own money. The gambler's upside is capped at zero
//   and the house cannot lose.
//
// What this script does:
//   1. Reconstructs every placed bet from placeBet calldata (commit, stake, masks).
//   2. Reconstructs every settlement from Game(reveal, ...) events — the reveal is
//      in the event, so commit = keccak256(abi.encodePacked(uint256 reveal)).
//   3. Classifies each bet: settled, or expired-unsettled (the operator's option
//      being exercised), and totals the value in each bucket.
//   4. Audits the reveals themselves: if they are small, sequential or repeated,
//      the gambler can brute-force the preimage and settle their own wins — the
//      operator's option, inverted, and the only way this game is winnable.
//
// Usage:
//   node poc/refund-option.mjs --address 0x… --rpc https://… [--from 0] [--to latest]
//        [--json out.json] [--max-txs 400]
//
// Read-only: no transactions are signed or sent.

import http from "node:http";
import https from "node:https";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { keccak256 } = require("js-sha3");

// ------------------------------------------------------------------ args ----
function parseArgs(argv) {
  const out = { from: 0, to: "latest", maxTxs: 400, json: null, address: null, rpc: null };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--address") out.address = argv[++i];
    else if (a === "--rpc") out.rpc = argv[++i];
    else if (a === "--from") out.from = Number(argv[++i]);
    else if (a === "--to") out.to = argv[++i];
    else if (a === "--json") out.json = argv[++i];
    else if (a === "--max-txs") out.maxTxs = Number(argv[++i]);
    else if (a === "--help" || a === "-h") out.help = true;
  }
  return out;
}

const args = parseArgs(process.argv);
if (args.help || !args.address || !args.rpc) {
  console.log(`usage: node poc/refund-option.mjs --address 0x… --rpc https://… [--from N] [--to latest] [--json out.json]`);
  process.exit(args.help ? 0 : 2);
}

// -------------------------------------------------------------- json-rpc ----
let rpcId = 0;
function rpc(method, params) {
  const url = new URL(args.rpc);
  const body = JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method, params });
  const lib = url.protocol === "https:" ? https : http;
  return new Promise((resolve, reject) => {
    const req = lib.request(
      {
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: url.pathname + url.search,
        method: "POST",
        timeout: 30_000,
        headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) },
      },
      (res) => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (text += c));
        res.on("end", () => {
          let json;
          try {
            json = JSON.parse(text);
          } catch {
            return reject(new Error(`non-JSON reply (${res.statusCode}): ${text.slice(0, 200)}`));
          }
          if (json.error) return reject(new Error(`${method}: ${json.error.message ?? JSON.stringify(json.error)}`));
          resolve(json.result);
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error(`${method}: timeout`)));
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

// ------------------------------------------------------------------ abi -----
const strip0x = (h) => (h.startsWith("0x") ? h.slice(2) : h);
const word = (data, i) => strip0x(data).slice(i * 64, i * 64 + 64);
const toBig = (hexWord) => BigInt("0x" + (hexWord || "0"));
const toNum = (hexWord) => Number(toBig(hexWord));
const toHex = (n) => "0x" + BigInt(n).toString(16).padStart(64, "0");

/** topic0 for an event signature, e.g. "Commit(uint256)". */
const topic = (sig) => "0x" + keccak256(sig);

/** commit = keccak256(abi.encodePacked(uint256 reveal)) — as the contract does. */
const commitOf = (reveal) => "0x" + keccak256(Buffer.from(toHex(reveal).slice(2), "hex"));

const TOPICS = {
  commit: topic("Commit(uint256)"),
  game: topic("Game(uint256,uint256[10],uint256,uint256)"),
  payment: topic("Payment(address,uint256)"),
  failed: topic("FailedPayment(address,uint256)"),
};

/**
 * Decode placeBet(uint8,uint256[],uint256[],uint8,uint256,uint256,uint8,bytes32,bytes32).
 * Only the parts this PoC needs: commit, the stake, and the bet count.
 */
function decodePlaceBet(input) {
  const data = strip0x(input);
  if (data.length < 8) return null;
  const selector = data.slice(0, 8);
  if (selector !== "0x" && `0x${selector}` !== PLACE_BET_SELECTOR) return null;
  const body = data.slice(8);
  // head: [gameId, offBetMask, offAmount, modulo, commitLastBlock, commit, v, r, s]
  const gameId = toNum(word(body, 0));
  const offBetMask = toNum(word(body, 1)) * 2; // bytes -> hex chars
  const offAmount = toNum(word(body, 2)) * 2;
  const modulo = toNum(word(body, 3));
  const commitLastBlock = toNum(word(body, 4));
  const commit = "0x" + word(body, 5);
  const readUintArray = (offsetChars) => {
    const len = toNum(body.slice(offsetChars, offsetChars + 64));
    const items = [];
    for (let i = 0; i < len; i++) {
      items.push(toBig(body.slice(offsetChars + 64 + i * 64, offsetChars + 64 + (i + 1) * 64)));
    }
    return items;
  };
  const amounts = readUintArray(offAmount);
  const masks = readUintArray(offBetMask);
  const stake = amounts.reduce((a, b) => a + b, 0n);
  return { gameId, modulo, commitLastBlock, commit, amounts, masks, stake, betCount: amounts.length };
}

const PLACE_BET_SELECTOR =
  "0x" +
  keccak256(
    "placeBet(uint8,uint256[],uint256[],uint8,uint256,uint256,uint8,bytes32,bytes32)",
  ).slice(0, 8);

// ------------------------------------------------------------------ main ----
async function main() {
  const address = args.address;
  const toBlock = args.to === "latest" ? Number(await rpc("eth_blockNumber", [])) : Number(args.to);
  const code = await rpc("eth_getCode", [address, "latest"]);
  if (!code || code === "0x") {
    console.error(`no code at ${address} — an EOA or a wrong address`);
    process.exit(3);
  }

  // Bets are placed via placeBet; the Commit event marks each one.
  const commits = await rpc("eth_getLogs", [
    { address, fromBlock: "0x" + args.from.toString(16), toBlock: "0x" + toBlock.toString(16), topics: [TOPICS.commit] },
  ]);
  const games = await rpc("eth_getLogs", [
    { address, fromBlock: "0x" + args.from.toString(16), toBlock: "0x" + toBlock.toString(16), topics: [TOPICS.game] },
  ]);

  console.log(`contract      ${address}`);
  console.log(`block range   ${args.from} .. ${toBlock}`);
  console.log(`commit events ${commits.length}`);
  console.log(`game events   ${games.length}  (a settlement)`);

  // Settlements: the reveal is in the event, so the commit is recoverable.
  const settled = new Map(); // commit -> { reveal, totalWin, totalJackpot, block }
  const reveals = [];
  for (const log of games) {
    const d = strip0x(log.data);
    const reveal = toBig(d.slice(0, 64));
    // layout: reveal, result[10], totalWin, totalJackpot
    const totalWin = toBig(d.slice((1 + 10) * 64, (1 + 10) * 64 + 64));
    const totalJackpot = toBig(d.slice((1 + 11) * 64, (1 + 11) * 64 + 64));
    const commit = commitOf(reveal);
    settled.set(commit, { reveal, totalWin, totalJackpot, block: Number(BigInt(log.blockNumber)) });
    reveals.push(reveal);
  }

  // Placed bets: decode placeBet calldata for each Commit event's transaction.
  const seenTx = new Set();
  const bets = [];
  let decoded = 0;
  for (const log of commits.slice(0, args.maxTxs)) {
    if (seenTx.has(log.transactionHash)) continue;
    seenTx.add(log.transactionHash);
    let tx;
    try {
      tx = await rpc("eth_getTransactionByHash", [log.transactionHash]);
    } catch {
      continue;
    }
    if (!tx) continue;
    const parsed = decodePlaceBet(tx.input);
    if (!parsed) continue;
    decoded++;
    bets.push({ ...parsed, tx: log.transactionHash, block: Number(BigInt(log.blockNumber)) });
  }

  // Classify.
  let settledStake = 0n;
  let settledWin = 0n;
  let expiredStake = 0n;
  let expiredCount = 0;
  for (const bet of bets) {
    const s = settled.get(bet.commit);
    if (s) {
      settledStake += bet.stake;
      settledWin += s.totalWin + s.totalJackpot;
    } else {
      expiredCount++;
      expiredStake += bet.stake;
    }
  }

  const eth = (wei) => `${(Number(wei) / 1e18).toFixed(6)} ETH`;

  console.log("");
  console.log("## bets");
  console.log(`decoded       ${decoded} placeBet transactions (of ${commits.length} commit events)`);
  console.log(`settled       ${bets.length - expiredCount}  stake ${eth(settledStake)}  paid out ${eth(settledWin)}`);
  console.log(`unsettled     ${expiredCount}  stake ${eth(expiredStake)}  paid out: the stake, refunded`);

  // ---------------------------------------------------------------- entropy --
  // If reveals are guessable, the gambler can settle their own winning bets. That
  // is the inverse of the operator's option, and it is the only way to win here.
  console.log("");
  console.log("## reveal entropy");
  const bits = reveals.map((r) => (r === 0n ? 0 : r.toString(2).length));
  const maxBits = bits.length ? Math.max(...bits) : 0;
  const small = bits.filter((b) => b < 64).length;
  const dupes = reveals.length - new Set(reveals.map((r) => r.toString())).size;
  let sequential = 0;
  for (let i = 1; i < reveals.length; i++) if (reveals[i] === reveals[i - 1] + 1n) sequential++;
  console.log(`reveals       ${reveals.length}`);
  console.log(`max bit length ${maxBits}`);
  console.log(`under 64 bits ${small}${small > 0 ? "   <-- brute-forceable from commit" : ""}`);
  console.log(`duplicates    ${dupes}${dupes > 0 ? "   <-- reveal reused across bets" : ""}`);
  console.log(`sequential    ${sequential}${sequential > 0 ? "   <-- counter, not random" : ""}`);

  // ---------------------------------------------------------------- verdict --
  const totalStake = settledStake + expiredStake;
  const ratio = totalStake > 0n ? Number(expiredStake) / Number(totalStake) : 0;
  console.log("");
  console.log("## verdict");
  console.log(
    `${(ratio * 100).toFixed(1)}% of decoded stake expired without a settlement.`,
  );
  console.log(
    expiredCount > 0
      ? "Those gamblers were refunded their own stake and could not have been paid a win:\n" +
        "refundBet pays bet.totalAmount, and settleBet needs a reveal only the operator holds.\n" +
        "The operator therefore holds a free option on every bet, and the house cannot lose."
      : "No expired bets in this window — the operator settled everything it was given.",
  );
  if (small > 0 || dupes > 0 || sequential > 0) {
    console.log(
      "\nThe reveals are not random. commit = keccak256(abi.encodePacked(uint256 reveal)) and\n" +
        "settleBet is permissionless, so a gambler who recovers the reveal can settle their own\n" +
        "winning bets and skip the rest. Check the bit lengths above before trusting this operator.",
    );
  }

  if (args.json) {
    const { writeFileSync } = await import("node:fs");
    writeFileSync(
      args.json,
      JSON.stringify(
        {
          address,
          blockRange: [args.from, toBlock],
          bets: bets.map((b) => ({
            commit: b.commit,
            tx: b.tx,
            block: b.block,
            stake: b.stake.toString(),
            betCount: b.betCount,
            settled: settled.has(b.commit),
            reveal: settled.get(b.commit)?.reveal.toString() ?? null,
            totalWin: settled.get(b.commit)?.totalWin.toString() ?? null,
          })),
          reveals: { count: reveals.length, maxBits, small, dupes, sequential },
          totals: {
            stake: totalStake.toString(),
            settledStake: settledStake.toString(),
            settledWin: settledWin.toString(),
            expiredStake: expiredStake.toString(),
            expiredCount,
          },
        },
        null,
        2,
      ),
      "utf8",
    );
    console.log(`\nwrote ${args.json}`);
  }
}

main().catch((err) => {
  console.error(`\nfailed: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
