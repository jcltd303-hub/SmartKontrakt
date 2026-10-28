import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { keccak256 } = require("js-sha3");
const run = promisify(execFile);

/**
 * A failed settleBet publishes its reveal. Whether that matters depends entirely on
 * whether the bet was still live at that moment — so the classifier must distinguish
 * four cases, not report "failed txs found".
 */

const word = (n) => BigInt(n).toString(16).padStart(64, "0");
const commitOf = (r) => keccak256(Buffer.from(word(r), "hex"));
const SETTLE_SEL = "0x" + keccak256("settleBet(uint256,bytes32)").slice(0, 8);
const GETBET_SEL = "0x" + keccak256("getBet(uint256)").slice(0, 8);

/** getBet return data with the given totalAmount / placeBlockNumber. */
function getBetReturn({ numberOfBets = 1, totalAmount = 10n ** 16n, placeBlock = 1000 }) {
  const head = [
    word(numberOfBets), // 0
    word(8 * 32), // 1 offset to amount[]
    word(totalAmount), // 2 static
    word(6), // 3 modulo
    word(placeBlock), // 4 static
    word(8 * 32 + 64), // 5 offset to mask[]
    word(0), // 6 gameId
    word(0), // 7 gambler
  ].join("");
  const arr = word(1) + word(10n ** 16n);
  return "0x" + head + arr + arr;
}

function serve(cases) {
  const server = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      const { method, params, id } = JSON.parse(b);
      const send = (result) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id, result }));
      };
      if (method === "eth_getTransactionByHash") {
        const c = cases[params[0]];
        if (!c) return send(null);
        const input = c.otherSelector ? "0x12345678" + word(c.reveal) : SETTLE_SEL + word(c.reveal) + word(0);
        return send({ input, blockNumber: "0x" + c.failedAt.toString(16) });
      }
      if (method === "eth_call") {
        const commit = "0x" + params[0].data.slice(10);
        const c = Object.values(cases).find((x) => "0x" + commitOf(x.reveal) === commit);
        if (!c) return send("0x" + "0".repeat(64 * 8));
        return send(getBetReturn({ totalAmount: c.totalAmount, placeBlock: c.placeBlock }));
      }
      send(null);
    });
  });
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r(server)));
}

test("classifies a leaked reveal as LIVE only when the bet was still claimable", async () => {
  const cases = {
    "0xlive": { reveal: 111n, placeBlock: 1000, failedAt: 1100, totalAmount: 10n ** 16n }, // 100 into the window
    "0xexpired": { reveal: 222n, placeBlock: 1000, failedAt: 1300, totalAmount: 10n ** 16n }, // 50 past expiry
    "0xprocessed": { reveal: 333n, placeBlock: 1000, failedAt: 1100, totalAmount: 0n }, // already settled
    "0xghost": { reveal: 444n, placeBlock: 0, failedAt: 1100, totalAmount: 0n }, // never placed
  };
  const server = await serve(cases);
  const port = server.address().port;
  try {
    const { stdout } = await run(process.execPath, [
      "poc/leak-check.mjs", "--address", "0x6eb0e558140025cb740f99979613a0876685f0be",
      "--rpc", `http://127.0.0.1:${port}`, "--txs", Object.keys(cases).join(","),
    ]);
    assert.match(stdout, /LIVE\s+0xlive\s+\+100 blocks into the window/);
    assert.match(stdout, /expired\s+0xexpired/);
    assert.match(stdout, /already processed\s+0xprocessed/);
    assert.match(stdout, /never placed\s+0xghost/);
    assert.match(stdout, /1 settlement\(s\) FAILED WHILE THE BET WAS STILL LIVE/);
    assert.match(stdout, /the operator's option, handed to the gambler/);
  } finally {
    server.close();
  }
});

test("no live leak says so plainly, rather than implying an exploit", async () => {
  const cases = {
    "0xa": { reveal: 555n, placeBlock: 1000, failedAt: 2000, totalAmount: 10n ** 16n }, // expired
    "0xb": { reveal: 666n, placeBlock: 1000, failedAt: 1100, totalAmount: 0n }, // processed
  };
  const server = await serve(cases);
  const port = server.address().port;
  try {
    const { stdout } = await run(process.execPath, [
      "poc/leak-check.mjs", "--address", "0x6eb0e558140025cb740f99979613a0876685f0be",
      "--rpc", `http://127.0.0.1:${port}`, "--txs", "0xa,0xb",
    ]);
    assert.match(stdout, /No reveal leaked while a bet was live/);
    assert.doesNotMatch(stdout, /FAILED WHILE THE BET WAS STILL LIVE/);
  } finally {
    server.close();
  }
});

test("a tx that is not a settleBet is reported as such, not classified", async () => {
  const server = await serve({ "0xdead": { reveal: 1n, placeBlock: 0, failedAt: 1, totalAmount: 0n, otherSelector: true } });
  const port = server.address().port;
  try {
    const { stdout } = await run(process.execPath, [
      "poc/leak-check.mjs", "--address", "0x6eb0e558140025cb740f99979613a0876685f0be",
      "--rpc", `http://127.0.0.1:${port}`, "--txs", "0xdead",
    ]);
    assert.match(stdout, /not a settleBet/);
  } finally {
    server.close();
  }
});

test("an unreadable transaction is INCONCLUSIVE, never 'no reveal leaked'", async () => {
  // The exact failure that shipped: every eth_getTransactionByHash returned
  // Unauthorized, and the summary said "No reveal leaked while a bet was live".
  // A read that failed is not evidence of absence.
  const server = await serve({}); // every lookup returns null -> classify errors
  const port = server.address().port;
  try {
    const err = await run(process.execPath, [
      "poc/leak-check.mjs", "--address", "0x6eb0e558140025cb740f99979613a0876685f0be",
      "--rpc", `http://127.0.0.1:${port}`, "--txs", "0xaa,0xbb",
    ]).then(() => null, (e) => e);
    assert.ok(err, "must exit non-zero when it could not read");
    const out = String(err.stdout ?? "");
    assert.match(out, /INCONCLUSIVE: 2 of 2/);
    assert.doesNotMatch(out, /No reveal leaked while a bet was live/);
  } finally {
    server.close();
  }
});

test("a Bearer header with an empty token is caught before any request", async () => {
  const err = await run(process.execPath, [
    "poc/leak-check.mjs", "--address", "0x6eb0e558140025cb740f99979613a0876685f0be",
    "--rpc", "http://127.0.0.1:1", "--txs", "0xaa", "--headers", "Authorization: Bearer ",
  ]).then(() => null, (e) => e);
  assert.ok(err, "must refuse to run");
  assert.match(String(err.stderr ?? ""), /"Bearer" with no token/);
});
