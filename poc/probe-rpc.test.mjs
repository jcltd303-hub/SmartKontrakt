import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);

// A probe must distinguish "no logs" from "refused", because both arrive as HTTP 200
// with a body a naive client reads the same way.
function serve(mode) {
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const { method, id } = JSON.parse(body);
      const send = (obj) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ jsonrpc: "2.0", id, ...obj })); };
      if (method === "eth_blockNumber") return send({ result: "0x1000" });
      if (mode === "refuses") return send({ error: { code: -32602, message: "Archive requests require a personal token" } });
      if (mode === "empty") return send({ result: [] });
      return send({ error: { code: -32005, message: "query returned more than 10000 results" } });
    });
  });
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r(server)));
}

test("the probe separates refused from empty, and names the reason", async () => {
  for (const [mode, needle] of [["refuses", /refused: Archive requests require a personal token/], ["empty", /ok — 0 logs/], ["tooWide", /refused: query returned more than 10000/]]) {
    const server = await serve(mode);
    const port = server.address().port;
    try {
      const { stdout } = await run(process.execPath, ["poc/probe-rpc.mjs", "0x6eb0e558140025cb740f99979613a0876685f0be", "--deploy", "10455555"], {
        env: { ...process.env, RPC_URLS: `http://127.0.0.1:${port}` },
      });
      assert.match(stdout, needle, `mode=${mode}`);
      assert.match(stdout, /eth_blockNumber\s+ok — 0x1000/);
    } finally {
      server.close();
    }
  }
});

test("the probe reports a header it was given without printing its value", async () => {
  const server = await serve("empty");
  const port = server.address().port;
  try {
    const { stdout } = await run(process.execPath, ["poc/probe-rpc.mjs", "0x6eb0e558140025cb740f99979613a0876685f0be"], {
      env: { ...process.env, RPC_URLS: `http://127.0.0.1:${port}`, RPC_HEADERS: "Authorization: Bearer SECRETVALUE" },
    });
    assert.match(stdout, /headers\s+content-type, Authorization/);
    assert.doesNotMatch(stdout, /SECRETVALUE/, "a credential must never be echoed");
  } finally {
    server.close();
  }
});
