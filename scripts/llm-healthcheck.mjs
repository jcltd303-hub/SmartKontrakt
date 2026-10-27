#!/usr/bin/env node
// scripts/llm-healthcheck.mjs
//
// One command to answer "is the LLM working smoothly", meant to run on the host
// where the worker and its logs actually are.
//
//   node scripts/llm-healthcheck.mjs                      # worker on :8788
//   node scripts/llm-healthcheck.mjs --url http://host:8788
//   node scripts/llm-healthcheck.mjs --db                 # also read the DB
//   watch -n 30 "node scripts/llm-healthcheck.mjs"        # while a run is going
//
// Exit codes, so it can go straight into cron or a monitor:
//   0  smooth or off (no key: expected)
//   1  degraded (more than 20% of calls produced no usable text)
//   2  dead, or the worker is unreachable
//
// The DB mode is the retrospective check: the worker records `ai_status` per
// scan, so a run whose narratives are all fallback text still shows up here as a
// distribution — that is how you find out the LLM was off for last night's run.

import http from "node:http";
import { createRequire } from "node:module";

const DEFAULTS = { url: "http://127.0.0.1:8788", timeoutMs: 8000 };

/**
 * @param health the /health/llm counters
 * @param ctx    optional /status fields — `calls === 0` is ambiguous without them:
 *               it means "not enabled", "not started yet" or "enabled but broken",
 *               and only the run state can tell you which.
 */
export function judge(health, ctx = {}) {
  const attempted = (health.ok ?? 0) + (health.empty ?? 0) + (health.error ?? 0);
  const failures = (health.empty ?? 0) + (health.error ?? 0);
  if (attempted === 0) {
    if ((health.unavailable ?? 0) > 0) {
      return { state: "off", code: 0, reason: "no OPENROUTER_API_KEY — static-only run, narratives are fallback text" };
    }
    const completed = typeof ctx.completed === "number" ? ctx.completed : null;
    const secondPass = typeof ctx.aiSecondPass === "boolean" ? ctx.aiSecondPass : null;
    // Enabled, items finished, and still not one call: the call path is broken.
    if (secondPass === true && (completed ?? 0) > 0) {
      return {
        state: "degraded",
        code: 1,
        reason: `aiSecondPass is ON and ${completed} item(s) completed, but no LLM call was ever made — the second-pass call site is not being reached`,
      };
    }
    // Not enabled. This is the common case and it is NOT "smooth": nothing ran.
    if (secondPass === false && (completed ?? 0) > 0) {
      return {
        state: "off",
        code: 0,
        reason: `aiSecondPass is false — ${completed} item(s) completed with no LLM pass; send {"aiSecondPass": true} to /start to enable it`,
      };
    }
    if (completed === 0 || completed === null) {
      return {
        state: "waiting",
        code: 0,
        reason: `no LLM calls yet — the run has not completed an item${ctx.state ? ` (state=${ctx.state})` : ""}`,
      };
    }
    return { state: "waiting", code: 0, reason: "no LLM calls yet" };
  }
  if ((health.consecutiveFailures ?? 0) >= 3) {
    return {
      state: "dead",
      code: 2,
      reason: `${health.consecutiveFailures} consecutive failures — last: ${health.lastError ?? "unknown"}`,
    };
  }
  const rate = failures / attempted;
  if (rate > 0.2) {
    return {
      state: "degraded",
      code: 1,
      reason: `${(rate * 100).toFixed(0)}% of ${attempted} calls produced no usable text (${health.empty ?? 0} empty, ${health.error ?? 0} error)`,
    };
  }
  return { state: "smooth", code: 0, reason: `${health.ok}/${attempted} usable replies` };
}

/**
 * GET a JSON document with node:http.
 *
 * NOT `fetch`: on Node 20 the global fetch lazily instantiates undici's WASM
 * llhttp parser, and where WASM allocation is unavailable (constrained
 * containers, some CI runners) every request dies with "WebAssembly.instantiate():
 * Out of memory" — an error that looks like a network failure and sends you
 * hunting the wrong problem. node:http needs no WASM and exists on every Node
 * this repo supports.
 */
function httpGetJson(endpoint, timeoutMs) {
  return new Promise((resolve, reject) => {
    const req = http.get(endpoint, { timeout: timeoutMs }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        if (res.statusCode && (res.statusCode < 200 || res.statusCode >= 300)) {
          reject(Object.assign(new Error(`HTTP ${res.statusCode}`), { statusCode: res.statusCode, body: text }));
          return;
        }
        try {
          resolve(JSON.parse(text));
        } catch {
          reject(new Error(`reply was not JSON: ${text.slice(0, 120)}`));
        }
      });
    });
    req.on("timeout", () => req.destroy(new Error(`no reply within ${timeoutMs}ms`)));
    req.on("error", reject);
  });
}

export async function checkLlmHealth({ url = DEFAULTS.url, timeoutMs = DEFAULTS.timeoutMs, fetchImpl } = {}) {
  const base = url.replace(/\/+$/, "");
  const endpoint = `${base}/health/llm`;
  try {
    const body = fetchImpl ? await fetchImpl(endpoint) : await httpGetJson(endpoint, timeoutMs);
    const health = body.llm ?? body;               // /health/llm flattens, /status nests
    // Run context. Best-effort: an older worker has no /status in this shape, and
    // the health endpoint alone is still a valid answer.
    let ctx = {};
    try {
      const status = fetchImpl ? await fetchImpl(`${base}/status`) : await httpGetJson(`${base}/status`, timeoutMs);
      ctx = { aiSecondPass: status.aiSecondPass, completed: status.completed, state: status.state, total: status.total };
    } catch {
      /* context is optional */
    }
    const computed = judge(health, ctx);
    // A worker-reported verdict wins only when the counters back it up; a stale
    // "smooth" from a build that predates the run-context check must not hide an
    // un-run second pass.
    const verdict = body.verdict?.state && computed.state === "smooth"
      ? { ...computed, state: body.verdict.state, reason: body.verdict.reason }
      : computed;
    return { reachable: true, health, verdict, ctx, model: body.model, keyPresent: body.keyPresent };
  } catch (err) {
    if (err && typeof err.statusCode === "number") {
      return { reachable: false, verdict: { state: "unreachable", code: 2, reason: `${endpoint} returned HTTP ${err.statusCode}` } };
    }
    const msg = err instanceof Error ? err.message : String(err);
    return {
      reachable: false,
      verdict: {
        state: "unreachable",
        code: 2,
        reason: `cannot reach ${endpoint} (${msg}) — is the worker running? is this the right host/port?`,
      },
    };
  }
}

/** Recent ai_status distribution from the DB. Optional; needs DATABASE_URL + pg. */
export async function checkDb({ hours = 24 } = {}) {
  const url = process.env.DATABASE_URL?.trim();
  if (!url) {
    return {
      ok: false,
      reason:
        "DATABASE_URL is not set in this shell — it lives in pipeline-worker/.env, so run with: node --env-file=pipeline-worker/.env scripts/llm-healthcheck.mjs --db",
    };
  }
  let pg;
  try {
    const require = createRequire(import.meta.url);
    pg = require("pg");
  } catch {
    return { ok: false, reason: "the pg package is not installed (npm i pg) — skipping the DB check" };
  }
  const client = new pg.Client({ connectionString: url, ssl: url.includes("supabase.co") ? { rejectUnauthorized: false } : undefined });
  try {
    await client.connect();
    const { rows } = await client.query(
      `select coalesce(ai_status, 'null') as status, count(*)::int as scans
         from contract_scans
        where created_at > now() - ($1 || ' hours')::interval
        group by 1 order by 2 desc`,
      [String(hours)],
    );
    const total = rows.reduce((a, r) => a + r.scans, 0);
    const ok = rows.find((r) => r.status === "ok")?.scans ?? 0;
    return {
      ok: true,
      hours,
      total,
      rows,
      share: total ? ok / total : null,
      reason: total
        ? `${ok}/${total} recent scans have an AI narrative (${((ok / total) * 100).toFixed(0)}%)`
        : `no scans in the last ${hours}h`,
    };
  } catch (err) {
    return { ok: false, reason: `DB query failed: ${err instanceof Error ? err.message : String(err)}` };
  } finally {
    await client.end().catch(() => {});
  }
}

async function main() {
  const args = process.argv.slice(2);
  const url = args.includes("--url") ? args[args.indexOf("--url") + 1] : DEFAULTS.url;
  const wantDb = args.includes("--db");

  const live = await checkLlmHealth({ url });
  console.log(`LLM ${live.verdict.state.toUpperCase()} — ${live.verdict.reason}`);
  if (live.reachable) {
    const h = live.health;
    console.log(`  calls=${h.calls ?? 0} ok=${h.ok ?? 0} empty=${h.empty ?? 0} error=${h.error ?? 0} unavailable=${h.unavailable ?? 0}`);
    console.log(`  streak=${h.consecutiveFailures ?? 0} lastOkAt=${h.lastOkAt ?? "never"} key=${live.keyPresent ? "present" : "MISSING"}`);
    const c = live.ctx ?? {};
    if (c.state !== undefined) {
      console.log(`  run: state=${c.state} completed=${c.completed ?? "?"}/${c.total ?? "?"} aiSecondPass=${c.aiSecondPass === undefined ? "?" : c.aiSecondPass}`);
    }
    if (h.lastError) console.log(`  lastError: ${h.lastError}`);
    if (c.aiSecondPass === false) {
      console.log('  -> the second pass is OFF: POST /start with {"aiSecondPass": true} (a key alone does not enable it)');
    } else if (live.verdict.state === "off") {
      console.log("  -> set OPENROUTER_API_KEY in pipeline-worker/.env to turn the second pass on");
    }
    if (live.verdict.state === "degraded" || live.verdict.state === "dead") {
      console.log("  -> check OPENROUTER_MODEL and the account quota; `empty` rows mean a reply the output contract rejected");
    }
  }

  let dbCode = 0;
  if (wantDb) {
    const db = await checkDb();
    console.log(db.ok ? `DB: ${db.reason}` : `DB: skipped — ${db.reason}`);
    if (db.ok && db.share !== null && db.share < 0.5 && db.total > 0) {
      console.log("  -> most recent scans have no AI narrative: the second pass was off or failing for this window");
      dbCode = 1;
    }
  }
  process.exit(Math.max(live.verdict.code, dbCode));
}

// The entry-point guard needs the NODE_TEST_CONTEXT exclusion for the same
// reason the benchmark scripts do: when this file is bundled into a test, the
// bundle path IS argv[1], so main() would run at import time.
if (!process.env.NODE_TEST_CONTEXT && import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error("llm-healthcheck failed:", err instanceof Error ? err.message : String(err));
    process.exit(2);
  });
}
