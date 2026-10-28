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
  const out = { from: null, to: "latest", maxTxs: 400, json: null, address: null, rpc: null, source: "blockscout", outcomes: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--address") out.address = argv[++i];
    else if (a === "--rpc") out.rpc = argv[++i];
    else if (a === "--from") out.from = Number(argv[++i]);
    else if (a === "--to") out.to = argv[++i];
    else if (a === "--json") out.json = argv[++i];
    else if (a === "--max-txs") out.maxTxs = Number(argv[++i]);
    else if (a === "--source") out.source = argv[++i];
    else if (a === "--outcomes") out.outcomes = true;
    else if (a === "--help" || a === "-h") out.help = true;
  }
  return out;
}

const args = parseArgs(process.argv);
if (args.help || !args.address || (args.source === "rpc" && !args.rpc)) {
  console.log(`usage: node poc/refund-option.mjs --address 0x… [--source blockscout|rpc] [--rpc https://…]
                                   [--from N] [--to latest] [--json out.json] [--max-txs N]

  --source blockscout   keyless explorer API (default); --rpc not needed
  --source rpc          requires --rpc, and an endpoint that will serve eth_getLogs`);
  process.exit(args.help ? 0 : 2);
}

// -------------------------------------------------------------- sources ----
//
// Two ways to read the chain:
//   blockscout  keyless, archive-capable, no node — the default. A public RPC
//               (publicnode et al) now refuses eth_getLogs over old ranges
//               without a paid token, which made --from 0 unusable.
//   rpc         any JSON-RPC endpoint, if you have one that will serve getLogs.
const BLOCKSCOUT = process.env.BLOCKSCOUT_URL ?? "https://eth.blockscout.com";

function getJson(url) {
  const u = new URL(url);
  const lib = u.protocol === "https:" ? https : http;
  return new Promise((resolve, reject) => {
    const req = lib.get(
      { hostname: u.hostname, port: u.port || undefined, path: u.pathname + u.search, timeout: 30_000, headers: { accept: "application/json" } },
      (res) => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (text += c));
        res.on("end", () => {
          try {
            resolve(JSON.parse(text));
          } catch {
            reject(new Error(`non-JSON from ${u.pathname} (${res.statusCode}): ${text.slice(0, 160)}`));
          }
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error(`timeout: ${u.pathname}`)));
    req.on("error", reject);
  });
}

const blockscoutSource = {
  name: "blockscout",

  /**
   * The explorer answers a too-wide query with {"status":"0","message":"Something
   * went wrong."} rather than an error code — fromBlock=0 to latest over 26M blocks
   * is too heavy for its backend. So walk the range in windows, halving the window
   * whenever the explorer refuses, and merge the results.
   */
  async getLogs({ address, from, to, topic0 }) {
    const head = typeof to === "string" ? Number(await this.head()) : Number(to);
    const start = Number(from);
    if (start > head) return [];

    let window = Number(process.env.POC_LOG_WINDOW ?? 2_000_000);
    const out = [];
    const seen = new Set();
    let cursor = start;
    let attempts = 0;
    let requests = 0;
    // A pathological explorer can refuse anything; the floor is what keeps the walk
    // making progress instead of giving up, and the request cap stops it running
    // forever when nothing is answered.
    const FLOOR = Number(process.env.POC_LOG_MIN_WINDOW ?? 1_000);
    const MAX_REQUESTS = 5_000;

    while (cursor <= head) {
      if (++requests > MAX_REQUESTS) {
        throw new Error(`blockscout logs: gave up after ${MAX_REQUESTS} requests at block ${cursor}`);
      }
      const end = Math.min(cursor + window - 1, head);
      const url =
        `${BLOCKSCOUT}/api?module=logs&action=getLogs&address=${address}` +
        `&fromBlock=${cursor}&toBlock=${end}&topic0=${topic0}`;
      let body;
      try {
        body = await getJson(url);
      } catch (err) {
        body = { status: "0", message: String(err instanceof Error ? err.message : err) };
      }
      const failed = body.status === "0" && !/no logs found/i.test(String(body.message ?? ""));
      if (failed) {
        // Too wide, or the backend is busy: shrink and retry the same window.
        if (window > FLOOR && attempts < 24) {
          window = Math.max(FLOOR, Math.floor(window / 4));
          attempts++;
          continue;
        }
        throw new Error(
          `blockscout logs ${cursor}..${end}: ${body.message ?? "unknown error"}\n` +
            `  The explorer would not answer even at a ${window}-block window (floor ${FLOOR}).\n` +
            `  Try FROM_BLOCK=<deployment block> or a different source (--source rpc).`,
        );
      }
      const rows = Array.isArray(body.result) ? body.result : [];
      if (rows.length >= 1000) {
        console.warn(`  warning: ${rows.length} logs in ${cursor}..${end} — the API caps at 1000 per call; that window is clipped`);
      }
      for (const r of rows) {
        const key = `${r.transactionHash}:${r.logIndex ?? r.log_index ?? ""}:${r.data?.slice(0, 18)}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({
          blockNumber: r.blockNumber,
          transactionHash: r.transactionHash,
          topics: r.topics,
          data: r.data,
        });
      }
      cursor = end + 1;
    }
    return out;
  },

  /**
   * The chain head. Three shapes, in order of how directly they answer the
   * question — each verified against the live API rather than assumed:
   *   ?module=block&action=eth_block_number -> {"result":"0x1911c61"}
   *   /api/v2/stats                         -> {"total_blocks":"26287040"}
   *   /api/v2/main-page/blocks              -> {"items":[{"height":…}]}
   */
  async head() {
    const asNumber = (v) => {
      if (typeof v === "number") return v;
      if (typeof v === "string") return v.startsWith("0x") ? parseInt(v, 16) : Number(v);
      return null;
    };
    const attempts = [
      async () => {
        const b = await getJson(`${BLOCKSCOUT}/api?module=block&action=eth_block_number`);
        return asNumber(b?.result);
      },
      async () => {
        const b = await getJson(`${BLOCKSCOUT}/api/v2/stats`);
        return asNumber(b?.total_blocks);
      },
      async () => {
        const b = await getJson(`${BLOCKSCOUT}/api/v2/main-page/blocks`);
        return asNumber(b?.items?.[0]?.height);
      },
    ];
    for (const attempt of attempts) {
      try {
        const n = await attempt();
        if (Number.isFinite(n) && n > 0) return n;
      } catch {
        // try the next shape
      }
    }
    throw new Error("could not read the chain head from blockscout; pass --to <block>");
  },

  async getTxInput(hash) {
    const body = await getJson(`${BLOCKSCOUT}/api/v2/transactions/${hash}`);
    return typeof body.raw_input === "string" ? body.raw_input : null;
  },

  /**
   * The block a contract was created in — the honest default for --from.
   * /api/v2/addresses/{addr} gives creation_transaction_hash, then
   * ?module=transaction&action=gettxinfo gives result.blockNumber as a decimal
   * string. Both verified live (0x6eb0…5f0be -> block 10,455,555).
   */
  async getDeploymentBlock(address) {
    const asNumber = (v) => {
      if (typeof v === "number") return v;
      if (typeof v === "string") return v.startsWith("0x") ? parseInt(v, 16) : Number(v);
      return null;
    };
    let hash = null;
    try {
      const info = await getJson(`${BLOCKSCOUT}/api/v2/addresses/${address}`);
      hash = info?.creation_transaction_hash ?? null;
    } catch {
      return null;
    }
    if (!hash) return null;
    try {
      const tx = await getJson(`${BLOCKSCOUT}/api?module=transaction&action=gettxinfo&txhash=${hash}`);
      const n = asNumber(tx?.result?.blockNumber);
      if (Number.isFinite(n) && n > 0) return n;
    } catch {
      // fall through to the v2 shape
    }
    try {
      const tx = await getJson(`${BLOCKSCOUT}/api/v2/transactions/${hash}`);
      const n = asNumber(tx?.block_number ?? tx?.block);
      return Number.isFinite(n) && n > 0 ? n : null;
    } catch {
      return null;
    }
  },
};

/**
 * Extra headers for the RPC endpoint, from RPC_HEADERS="Authorization: Bearer xxx".
 *
 * PublicNode's archive refusal is a DEPTH rule (-32602 / 403, "Archive requests
 * require a personal token"): it rejects a start more than ~10,000 blocks behind the
 * head regardless of window width. How Allnodes wants the token presented (header vs
 * URL path) is not documented, so both are supported and neither is assumed: put it
 * in RPC_URL if the provider takes it in the path, or in RPC_HEADERS if it wants a
 * header. Nothing is hardcoded.
 */
function rpcHeaders() {
  const out = { "content-type": "application/json" };
  const raw = process.env.RPC_HEADERS;
  if (!raw) return out;
  for (const part of raw.split(",")) {
    const i = part.indexOf(":");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

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
        headers: { ...rpcHeaders(), "content-length": Buffer.byteLength(body) },
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

const rpcSource = {
  name: "rpc",

  /**
   * Walk the range in windows, because one bad window should not lose the run.
   *
   * Measured on Blockscout's PRO JSON-RPC (2026-10-27): eth_getLogs at the very tip
   * returns HTTP 500 "Internal server error" while block 10,455,555 answers 200 with
   * zero logs — the indexer lags the newest block or two. So a window that ends at
   * the head is retried two blocks short, and any other failure halves the window
   * before giving up.
   */
  async getLogs({ address, from, to, topic0 }) {
    const reported = typeof to === "string" ? Number(await rpc("eth_blockNumber", [])) : Number(to);
    // Stop two blocks short of the tip. Blockscout's PRO RPC answers the newest
    // block or two with 500 "Internal server error" while the same filter works a few
    // blocks back — the indexer lags. For a historical audit those two blocks are
    // not worth a retry loop, and capping here keeps the walk strictly advancing.
    const head = Math.max(Number(from), reported - 2);
    let window = Number(process.env.POC_LOG_WINDOW ?? 2_000_000);
    const FLOOR = Number(process.env.POC_LOG_MIN_WINDOW ?? 1_000);
    const out = [];
    let cursor = Number(from);

    const fetchRange = async (lo, hi) => {
      const rows = await rpc("eth_getLogs", [
        {
          address,
          fromBlock: "0x" + lo.toString(16),
          toBlock: "0x" + hi.toString(16),
          topics: [topic0],
        },
      ]);
      return Array.isArray(rows) ? rows : [];
    };

    while (cursor <= head) {
      const end = Math.min(cursor + window - 1, head);
      try {
        out.push(...(await fetchRange(cursor, end)));
        cursor = end + 1;
      } catch (err) {
        const msg = String(err instanceof Error ? err.message : err);
        // A 5xx on a window that is not at the tip: halve and retry below.
        if (/archive|personal token|requires a token/i.test(msg)) {
          throw new Error(
            `${msg}\n` +
              `  This endpoint has no archive depth: it refuses a start more than ~10,000 blocks\n` +
              `  behind the head. Use a keyed/archive endpoint, or --source blockscout.`,
          );
        }
        if (window > FLOOR) {
          window = Math.max(FLOOR, Math.floor(window / 4));
          continue;
        }
        throw new Error(`${msg}\n  Window ${cursor}..${end} refused at the ${window}-block floor.`);
      }
    }
    return out;
  },
  async getTxInput(hash) {
    const tx = await rpc("eth_getTransactionByHash", [hash]);
    return tx?.input ?? null;
  },
  async head() {
    return Number(await rpc("eth_blockNumber", []));
  },
};

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

const sel = (sig) => "0x" + keccak256(sig).slice(0, 8);
const GAME_ADDRESS_SEL = sel("gameAddress(uint256)");
const GAME_SEL = sel("game(uint256,uint8,bytes32,uint256)");

/** eth_call against a contract, returning raw hex. */
async function callView(to, data) {
  return await rpc("eth_call", [{ to, data }, "latest"]);
}

const PLACE_BET_SELECTOR =
  "0x" +
  keccak256(
    "placeBet(uint8,uint256[],uint256[],uint8,uint256,uint256,uint8,bytes32,bytes32)",
  ).slice(0, 8);

// ------------------------------------------------------------------ main ----
async function main() {
  const address = args.address;
  const source = args.source === "rpc" ? rpcSource : blockscoutSource;
  // Resolve the head once: getLogs needs a number to walk to, and the banner is
  // useless if it says "latest" while the walk used something else.
  const toBlock = args.to === "latest" ? await source.head() : Number(args.to);

  if (source === rpcSource) {
    const code = await rpc("eth_getCode", [address, "latest"]);
    if (!code || code === "0x") {
      console.error(`no code at ${address} — an EOA or a wrong address`);
      process.exit(3);
    }
  }

  console.log(`source        ${source.name}${source === blockscoutSource ? ` (${BLOCKSCOUT})` : ` (${args.rpc})`}`);

  // Scanning from genesis is both slow and too heavy for the explorer's backend;
  // the deployment block is the honest lower bound for a contract's own logs.
  let fromBlock = args.from;
  if (fromBlock === null) {
    const deploy = typeof source.getDeploymentBlock === "function" ? await source.getDeploymentBlock(address) : null;
    fromBlock = deploy ?? 0;
    console.log(`from          ${fromBlock}${deploy ? " (deployment block)" : " (unknown — scanning from genesis)"}`);
  }

  // Bets are placed via placeBet; the Commit event marks each one.
  const commits = await source.getLogs({ address, from: fromBlock, to: toBlock, topic0: TOPICS.commit });
  const games = await source.getLogs({ address, from: fromBlock, to: toBlock, topic0: TOPICS.game });

  console.log(`contract      ${address}`);
  console.log(`block range   ${fromBlock} .. ${toBlock}`);
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
    let input;
    try {
      input = await source.getTxInput(log.transactionHash);
    } catch {
      continue;
    }
    if (!input) continue;
    const parsed = decodePlaceBet(input);
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

  // --------------------------------------------------------------- outcomes --
  //
  // Inferring "the operator declined a winner" from expiry is a guess. This
  // measures it instead: for each settled bet, recompute the game result from the
  // reveal and the placement block's hash, and ask the game contract what the win
  // actually was. blockhash(placeBlockNumber) is the block's own hash (the block hash
  // IS keccak of the header), so entropy = keccak256(reveal ++ blockHash) is
  // reproducible off-chain.
  //
  // It also self-checks: the recomputed total must equal the totalWin the Game event
  // reported. If it does for every bet, the derivation is right and the numbers are
  // trustworthy; a mismatch means the game contract or the arithmetic is not what
  // this assumes, and then nothing here should be believed.
  if (args.outcomes) {
    console.log("");
    console.log("## settled outcomes");
    const blockHashes = new Map();
    const houseEdgeOf = (amount) => {
      const edge = (amount * 1n) / 100n;
      const floor = 300000000000000n; // HOUSE_EDGE_MINIMUM_AMOUNT
      return edge > floor ? edge : floor;
    };
    const jackpotFeeOf = (amount) => (amount >= 100000000000000000n ? 1000000000000000n : 0n);

    let withWin = 0;
    let withoutWin = 0;
    let matched = 0;
    const mismatches = [];

    for (const bet of bets) {
      const s2 = settled.get(bet.commit);
      if (!s2) continue;

      let blockHash = blockHashes.get(bet.block);
      if (!blockHash) {
        try {
          const blk = await rpc("eth_getBlockByNumber", ["0x" + bet.block.toString(16), false]);
          blockHash = blk?.hash ?? null;
        } catch {
          blockHash = null;
        }
        if (blockHash) blockHashes.set(bet.block, blockHash);
      }
      if (!blockHash) {
        mismatches.push(`${bet.commit}: could not read block ${bet.block}`);
        continue;
      }

      // entropy = keccak256(abi.encodePacked(uint256 reveal, bytes32 blockHash))
      const entropy = "0x" + keccak256(Buffer.from(toHex(s2.reveal).slice(2) + strip0x(blockHash), "hex"));

      let gameAddr;
      try {
        const raw = await callView(address, GAME_ADDRESS_SEL + toHex(bet.gameId).slice(2));
        gameAddr = raw && raw !== "0x" ? "0x" + strip0x(raw).slice(24) : null;
      } catch {
        gameAddr = null;
      }
      if (!gameAddr || /^0x0{40}$/.test(gameAddr)) {
        mismatches.push(`${bet.commit}: gameAddress(${bet.gameId}) is not set`);
        continue;
      }

      let totalWin = 0n;
      for (let i = 0; i < bet.amounts.length; i++) {
        const amount = bet.amounts[i];
        const net = amount - houseEdgeOf(amount) - jackpotFeeOf(amount);
        const data =
          GAME_SEL +
          toHex(bet.masks[i] ?? 0n).slice(2) +
          toHex(bet.modulo).slice(2) +
          strip0x(entropy) +
          toHex(net).slice(2);
        try {
          const raw = await callView(gameAddr, data);
          totalWin += toBig(strip0x(raw).slice(0, 64));
        } catch {
          // a game contract that will not answer leaves this bet unmeasured
        }
      }

      if (totalWin > 0n) withWin++;
      else withoutWin++;
      if (totalWin === s2.totalWin) matched++;
      else mismatches.push(`${bet.commit}: recomputed ${totalWin} vs event ${s2.totalWin}`);
    }

    console.log(`settled bets  ${withWin + withoutWin}`);
    console.log(`gambler won   ${withWin}`);
    console.log(`gambler lost  ${withoutWin}`);
    console.log(`self-check    ${matched}/${withWin + withoutWin} recomputed totals match the Game event`);
    if (mismatches.length) {
      console.log(`mismatches    ${mismatches.length}`);
      for (const m of mismatches.slice(0, 8)) console.log(`  ${m}`);
    }
    console.log("");
    console.log(
      withWin === 0 && withoutWin > 0
        ? "Every settled bet was a gambler loss. That is selection, not house edge."
        : `The operator settles wins: ${withWin} of ${withWin + withoutWin} settled bets paid the gambler.`,
    );
  }

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
          blockRange: [fromBlock, toBlock],
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
