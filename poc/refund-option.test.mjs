// poc/refund-option.test.mjs
//
// Verifies the PoC against a local fake JSON-RPC, so the ABI decoding and the
// settled/expired classification are checked without touching a live chain.
//
// The fixture is built the way the contract builds it:
//   commit = keccak256(abi.encodePacked(uint256 reveal))
//   placeBet(uint8,uint256[],uint256[],uint8,uint256,uint256,uint8,bytes32,bytes32)
//   Game(uint256 reveal, uint256[10] result, uint256 totalWin, uint256 totalJackpot)

import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { keccak256 } = require("js-sha3");
const run = promisify(execFile);

const word = (n) => BigInt(n).toString(16).padStart(64, "0");
const addressWord = (a) => a.toLowerCase().replace(/^0x/, "").padStart(64, "0");
const commitOf = (reveal) => keccak256(Buffer.from(word(reveal), "hex"));

const SELECTOR = "0x" + keccak256("placeBet(uint8,uint256[],uint256[],uint8,uint256,uint256,uint8,bytes32,bytes32)").slice(0, 8);
const T_COMMIT = "0x" + keccak256("Commit(uint256)");
const T_GAME = "0x" + keccak256("Game(uint256,uint256[10],uint256,uint256)");

/** placeBet calldata for one bet. */
function placeBetCalldata({ gameId = 0, mask = [7], amount = [10n ** 16n], modulo = 6, commitLastBlock = 99999999, commit }) {
  const head = [
    word(gameId),
    word(9 * 32), // offset to betMask
    word(9 * 32 + 32 + mask.length * 32), // offset to amount
    word(modulo),
    word(commitLastBlock),
    commit, // already 32 bytes
    word(27),
    word(1),
    word(2),
  ].join("");
  const arr = (xs) => word(xs.length) + xs.map((x) => word(x)).join("");
  return SELECTOR + head + arr(mask) + arr(amount);
}

/** Game event data: reveal, result[10], totalWin, totalJackpot. */
function gameLogData(reveal, totalWin, totalJackpot) {
  return "0x" + word(reveal) + Array.from({ length: 10 }, () => word(0)).join("") + word(totalWin) + word(totalJackpot);
}

/** A fake Blockscout: v1 logs + v2 transaction raw_input. */
function serveBlockscout({ commits = [], games = [], inputs = {} }) {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const send = (obj) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };
    if (url.pathname === "/api" && url.searchParams.get("action") === "getLogs") {
      const topic0 = url.searchParams.get("topic0");
      const rows = topic0 === T_COMMIT ? commits : topic0 === T_GAME ? games : [];
      if (rows.length === 0) return send({ status: "0", message: "No logs found", result: [] });
      return send({ status: "1", message: "OK", result: rows });
    }
    const m = url.pathname.match(/^\/api\/v2\/transactions\/(0x[0-9a-fA-F]+)$/);
    if (m) {
      const input = inputs[m[1]];
      if (!input) {
        res.writeHead(404).end("{}");
        return;
      }
      return send({ raw_input: input });
    }
    res.writeHead(404).end("{}");
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

function serve(handlers) {
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const { method, params, id } = JSON.parse(body);
      const result = handlers[method]?.(params);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(result === undefined ? { jsonrpc: "2.0", id, error: { message: `no handler for ${method}` } } : { jsonrpc: "2.0", id, result }));
    });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

test("classifies settled vs expired bets and flags a guessable reveal", async () => {
  const ADDRESS = "0x6eb0e558140025cb740f99979613a0876685f0be";
  const REVEAL = 12345n; // deliberately small: brute-forceable, must be flagged
  const commitSettled = "0x" + commitOf(REVEAL);
  const commitExpired = "0x" + keccak256("never settled");

  const txFor = {
    "0xaa": placeBetCalldata({ commit: commitSettled.slice(2), amount: [10n ** 16n] }), // 0.01 ETH
    "0xbb": placeBetCalldata({ commit: commitExpired.slice(2), amount: [2n * 10n ** 16n] }), // 0.02 ETH
  };

  const server = await serveBlockscout({
    commits: [
      { blockNumber: "0x10", transactionHash: "0xaa", topics: [T_COMMIT], data: "0x" + commitSettled.slice(2) },
      { blockNumber: "0x11", transactionHash: "0xbb", topics: [T_COMMIT], data: "0x" + commitExpired.slice(2) },
    ],
    games: [{ blockNumber: "0x12", transactionHash: "0xcc", topics: [T_GAME], data: gameLogData(REVEAL, 3n * 10n ** 16n, 0n) }],
    inputs: txFor,
  });

  const port = server.address().port;
  try {
    const { stdout } = await run(process.execPath, [
      "poc/refund-option.mjs",
      "--address", ADDRESS,
      "--source", "blockscout",
      "--from", "0",
    ], { env: { ...process.env, BLOCKSCOUT_URL: `http://127.0.0.1:${port}` } });
    // one settled at 0.01, one expired at 0.02
    assert.match(stdout, /decoded\s+2 placeBet transactions/);
    assert.match(stdout, /settled\s+1\s+stake 0\.010000 ETH\s+paid out 0\.030000 ETH/);
    assert.match(stdout, /unsettled\s+1\s+stake 0\.020000 ETH/);
    // 0.02 of 0.03 stake expired
    assert.match(stdout, /66\.7% of decoded stake expired/);
    assert.match(stdout, /free option/);
    // the small reveal is called out
    assert.match(stdout, /under 64 bits 1\s+<-- brute-forceable/);
  } finally {
    server.close();
  }
});

test("a clean window reports no expired bets rather than inventing one", async () => {
  const ADDRESS = "0x6eb0e558140025cb740f99979613a0876685f0be";
  const REVEAL = 0x9f3a7c1d2e4b5a69788796a5b4c3d2e1f0091827364554637281900aabbccdden;
  const commit = "0x" + commitOf(REVEAL);
  const server = await serveBlockscout({
    commits: [{ blockNumber: "0x10", transactionHash: "0xaa", topics: [T_COMMIT], data: "0x" + commit.slice(2) }],
    games: [{ blockNumber: "0x11", transactionHash: "0xcc", topics: [T_GAME], data: gameLogData(REVEAL, 10n ** 16n, 0n) }],
    inputs: { "0xaa": placeBetCalldata({ commit: commit.slice(2), amount: [10n ** 16n] }) },
  });
  const port = server.address().port;
  try {
    const { stdout } = await run(process.execPath, [
      "poc/refund-option.mjs", "--address", ADDRESS, "--source", "blockscout",
    ], { env: { ...process.env, BLOCKSCOUT_URL: `http://127.0.0.1:${port}` } });
    assert.match(stdout, /unsettled\s+0/);
    assert.match(stdout, /No expired bets in this window/);
    assert.doesNotMatch(stdout, /under 64 bits 1/);
  } finally {
    server.close();
  }
});

test("the rpc source rejects an address with no code", async () => {
  const server = await serve({
    eth_blockNumber: () => "0x1000",
    eth_getCode: () => "0x",
    eth_getLogs: () => [],
  });
  const port = server.address().port;
  try {
    await assert.rejects(
      run(process.execPath, ["poc/refund-option.mjs", "--address", "0x0000000000000000000000000000000000000001", "--source", "rpc", "--rpc", `http://127.0.0.1:${port}`]),
      (err) => /no code at/.test(String(err.stderr ?? err.message)),
    );
  } finally {
    server.close();
  }
});

test("an RPC that refuses archive logs points at the keyless source", async () => {
  const server = await serve({
    eth_blockNumber: () => "0x1000",
    eth_getCode: () => "0x6080",
    eth_getLogs: () => undefined, // no handler -> the script sees an error
  });
  const port = server.address().port;
  try {
    const err = await run(process.execPath, [
      "poc/refund-option.mjs", "--address", "0x6eb0e558140025cb740f99979613a0876685f0be",
      "--source", "rpc", "--rpc", `http://127.0.0.1:${port}`,
    ]).then(() => null, (e) => e);
    assert.ok(err, "must fail rather than silently report zero bets");
    assert.match(String(err.stderr ?? ""), /eth_getLogs|no handler/);
  } finally {
    server.close();
  }
});
