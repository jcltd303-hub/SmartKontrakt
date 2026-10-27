#!/usr/bin/env node
// cli/audit-tui.mjs
//
// A menu-driven terminal interface for the audit pipeline — the replacement for
// the web UI, for the machine that actually runs the worker.
//
//   node cli/audit-tui.mjs                  # talks to the worker on :8788
//   WORKER_URL=http://127.0.0.1:8789 node cli/audit-tui.mjs
//   node cli/audit-tui.mjs --once           # one frame, then exit (CI / ssh)
//
// Why this and not Rust: the worker's state is already a set of functions and
// endpoints in this repo (triage queue, stats, freshness, LLM health). A terminal
// client in the same runtime imports them instead of re-implementing them over
// HTTP, needs no toolchain on the box, and renders identically over SSH.
//
// Nothing here writes to the database except through the worker's own endpoints.

import http from "node:http";
import process from "node:process";
import { createRequire } from "node:module";

import {
  MENU, dim, green, humanCount, red, renderFrame, yellow,
} from "./render.mjs";

const require = createRequire(import.meta.url);
const WORKER = (process.env.WORKER_URL ?? "http://127.0.0.1:8788").replace(/\/+$/, "");
const ONCE = process.argv.includes("--once");
const TICK_MS = Number(process.env.TUI_TICK_MS ?? 1000);

/** GET JSON from the worker. node:http, not fetch — see the llm-healthcheck note. */
function getJson(path) {
  return new Promise((resolve) => {
    const url = new URL(WORKER + path);
    const req = http.request(
      { hostname: url.hostname, port: url.port, path: url.pathname + url.search, method: "GET", timeout: 4000 },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (body += c));
        res.on("end", () => {
          try {
            resolve({ ok: res.statusCode === 200, status: res.statusCode, body: JSON.parse(body) });
          } catch {
            resolve({ ok: false, status: res.statusCode, body: null });
          }
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", (err) => resolve({ ok: false, status: 0, body: null, error: err.message }));
    req.end();
  });
}

/** POST to the worker's control endpoints. */
function postJson(path, payload = {}) {
  return new Promise((resolve) => {
    const url = new URL(WORKER + path);
    const data = JSON.stringify(payload);
    const req = http.request(
      {
        hostname: url.hostname, port: url.port, path: url.pathname, method: "POST", timeout: 10_000,
        headers: { "content-type": "application/json", "content-length": Buffer.byteLength(data) },
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (body += c));
        res.on("end", () => {
          let parsed = null;
          try { parsed = JSON.parse(body); } catch { /* plain text */ }
          resolve({ ok: res.statusCode === 200, status: res.statusCode, body: parsed ?? body });
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", (err) => resolve({ ok: false, status: 0, body: null, error: err.message }));
    req.write(data);
    req.end();
  });
}

/**
 * Poll the worker. Everything is best-effort: a TUI that dies because one endpoint
 * is down is worse than one that shows the gap.
 */
async function poll() {
  const [status, health, freshness] = await Promise.all([
    getJson("/status"),
    getJson("/health/llm"),
    getJson("/freshness"),
  ]);
  const state = {
    width: process.stdout.columns ?? 100,
    status: status.ok ? status.body : null,
    llm: health.ok ? { ...health.body, verdict: health.body?.verdict } : null,
    freshness: freshness.ok ? freshness.body : null,
    db: null,
    queue: null,
  };
  if (!status.ok) {
    state.notice = red(`worker unreachable at ${WORKER}${status.error ? ` (${status.error})` : ""} — is start.sh running?`);
  }
  return state;
}

/** The DB half: stats and the read queue, when a database is configured. */
async function pollDb(state) {
  const url = process.env.DATABASE_URL;
  if (!url) return state;
  try {
    const pg = require("pg");
    const client = new pg.Client({
      connectionString: url.replace(/([?&])sslmode=[^&]*(&|$)/, "$1").replace(/[?&]$/, ""),
      ssl: { rejectUnauthorized: false },
    });
    await client.connect();
    try {
      const stats = await client.query(
        `select (select count(*) from contract_scans) as scans,
                (select count(*) from findings) as findings,
                (select count(*) from findings where severity = 'critical') as critical,
                (select count(*) from findings where severity = 'high') as high`,
      );
      state.db = { ...stats.rows[0], dbState: "remote" };
    } finally {
      await client.end();
    }
  } catch (err) {
    state.db = { error: `db: ${err instanceof Error ? err.message : String(err)}` };
  }
  return state;
}

function clear() {
  if (!ONCE) process.stdout.write("\x1b[2J\x1b[H");
}

async function draw(state, selected, tick) {
  clear();
  process.stdout.write(renderFrame(state, selected, tick) + "\n");
}

async function once() {
  const state = await pollDb(await poll());
  await draw(state, 0, 0);
}

async function interactive() {
  let selected = 0;
  let tick = 0;
  let state = { width: process.stdout.columns ?? 100 };
  const refresh = async () => {
    state = await pollDb(await poll());
  };
  await refresh();
  await draw(state, selected, tick);

  const timer = setInterval(async () => {
    tick++;
    await refresh();
    await draw(state, selected, tick);
  }, TICK_MS);

  process.stdin.setRawMode?.(true);
  process.stdin.resume();
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", async (key) => {
    if (key === "\u0003" || key === "x") {
      clearInterval(timer);
      process.stdin.setRawMode?.(false);
      process.stdout.write("\x1b[2J\x1b[H");
      process.exit(0);
    }
    if (key === "\t" || key === "\u001b[B") selected = (selected + 1) % MENU.length;
    else if (key === "\u001b[A") selected = (selected - 1 + MENU.length) % MENU.length;
    else if (key === "\r") await activate(MENU[selected].key, state);
    else if (key === "p") {
      const r = await postJson("/pause");
      state.notice = r.ok ? yellow("paused") : red(`pause failed (${r.status})`);
    } else if (key === "u") {
      const r = await postJson("/resume");
      state.notice = r.ok ? green("resumed") : red(`resume failed (${r.status})`);
    }
    await refresh();
    await draw(state, selected, tick);
  });
}

/** Menu actions. Destructive ones print the command instead of running it. */
async function activate(key, state) {
  if (key === "r") {
    const r = await postJson("/start", {});
    state.notice = r.ok
      ? green(`started: ${humanCount(r.body?.toAnalyse ?? 0)} to analyse`)
      : red(`start refused (${r.status}): ${typeof r.body === "string" ? r.body : JSON.stringify(r.body)}`);
  } else if (key === "d") {
    state.notice = dim("schema check: psql \"$DATABASE_URL\" -f sql/ops/check-schema.sql");
  } else if (key === "g") {
    state.notice = dim(`RPC_URLS=${process.env.RPC_URLS ? "set" : "unset"}  RPC_MIN_INTERVAL_MS=${process.env.RPC_MIN_INTERVAL_MS ?? "200"}`);
  }
}

if (ONCE) {
  await once();
} else {
  await interactive();
}
