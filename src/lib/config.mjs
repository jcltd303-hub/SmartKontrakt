/**
 * Central configuration — the ONE place shared constants live.
 *
 * Plain JavaScript (not TypeScript) on purpose, following the `pg-url.mjs`
 * pattern: the deploy-time migrator (`scripts/migrate-vercel.mjs`) and the
 * Termux backend (`termux-backend/server.mjs`) run under bare `node`, where a
 * `.ts` import would need `--experimental-strip-types`. App/worker code imports
 * the typed facade `config.ts`; bare-node consumers import this file directly.
 *
 * What lives here: values that were previously re-stated per subsystem and
 * drifted — the RPC endpoint table (five copies, one built with a positional
 * slice on another), the backend/worker URL and port defaults, the pipeline
 * worker's /start payload defaults, the app-origin fallback chain, the
 * OpenRouter endpoint URLs, and the database env-var priority tables.
 *
 * What does NOT live here: env LOADING (each runtime loads its environment
 * its own way — Vercel platform env, the worker's hand-rolled .env parser,
 * browser localStorage), secrets (names and order only, never values), and
 * behaviour (retry budgets, round caps — those stay with their owners).
 */

// ---------------------------------------------------------------------------
// RPC endpoints
// ---------------------------------------------------------------------------

/**
 * The built-in RPC endpoint table, one entry per supported chain, in
 * rotation order. Consumers: the workbench/worker via address-fetcher.ts
 * (which re-exports this as SUPPORTED_CHAINS), the Foundry backend's
 * fallback derivation, the Termux backend, and scripts/run-fork-poc.sh.
 *
 * Endpoint removal rule: an endpoint that fails 100% of the time is REMOVED
 * from every list, not demoted — it is pure latency on every request that
 * reaches it. Precedents: cloudflare-eth.com removed 2026-11-04 (JSON-RPC
 * -32603 for every request); eth.llamarpc.com and the arbitrum/base
 * *.llamarpc.com endpoints removed 2026-11-09 in the central-config batch
 * (llamarpc has answered HTTP 525 for months). Ankr is excluded: it now
 * requires an API key.
 *
 * @type {{ id: string, name: string, chainId: number, rpcUrls: string[], blockExplorer: string }[]}
 */
export const RPC_CHAINS = [
  {
    id: "ethereum",
    name: "Ethereum Mainnet",
    chainId: 1,
    rpcUrls: [
      "https://ethereum.publicnode.com",
      "https://eth.drpc.org",
      "https://1rpc.io/eth",
    ],
    blockExplorer: "https://etherscan.io",
  },
  {
    id: "arbitrum",
    name: "Arbitrum One",
    chainId: 42161,
    rpcUrls: [
      "https://arb1.arbitrum.io/rpc",
      "https://arbitrum-one.publicnode.com",
      "https://1rpc.io/arb",
    ],
    blockExplorer: "https://arbiscan.io",
  },
  {
    id: "base",
    name: "Base",
    chainId: 8453,
    rpcUrls: [
      "https://mainnet.base.org",
      "https://base.publicnode.com",
      "https://1rpc.io/base",
    ],
    blockExplorer: "https://basescan.org",
  },
  {
    id: "optimism",
    name: "Optimism",
    chainId: 10,
    rpcUrls: [
      "https://mainnet.optimism.io",
      "https://optimism.publicnode.com",
      "https://1rpc.io/op",
    ],
    blockExplorer: "https://optimistic.etherscan.io",
  },
  {
    id: "polygon",
    name: "Polygon",
    chainId: 137,
    rpcUrls: [
      "https://polygon-rpc.com",
      "https://polygon-bor-rpc.publicnode.com",
      "https://1rpc.io/matic",
    ],
    blockExplorer: "https://polygonscan.com",
  },
  {
    id: "bsc",
    name: "BNB Smart Chain",
    chainId: 56,
    rpcUrls: [
      "https://bsc-dataseed.binance.org",
      "https://bsc.publicnode.com",
      "https://1rpc.io/bnb",
    ],
    blockExplorer: "https://bscscan.com",
  },
];

/** Ethereum rotation order, derived — scripts/run-fork-poc.sh reads this. */
export const RPC_ORDER_ETHEREUM =
  RPC_CHAINS.find((c) => c.id === "ethereum")?.rpcUrls ?? [];

/** Every built-in endpoint, flattened in chain order, deduped. */
export const ALL_RPC_URLS = Array.from(new Set(RPC_CHAINS.flatMap((c) => c.rpcUrls)));

// ---------------------------------------------------------------------------
// Local services: Foundry backend + pipeline worker
// ---------------------------------------------------------------------------

/** Termux Foundry backend (termux-backend/server.mjs) default port. */
export const BACKEND_PORT_DEFAULT = 8787;
/** Pipeline worker (pipeline-worker/worker.ts) default port. */
export const WORKER_PORT_DEFAULT = 8788;
/** Default base URL of the Foundry backend. */
export const FOUNDRY_BACKEND_URL_DEFAULT = `http://127.0.0.1:${BACKEND_PORT_DEFAULT}`;
/** Default base URL of the pipeline worker. */
export const WORKER_URL_DEFAULT = `http://127.0.0.1:${WORKER_PORT_DEFAULT}`;

/**
 * Defaults for the pipeline worker's POST /start payload. One definition,
 * consumed by the worker (state defaults), the web UI (form defaults) and
 * documented for the HELLBENT feeder (which re-states them in Python —
 * pinned by the config drift test).
 */
export const WORKER_START_DEFAULTS = {
  chainId: "ethereum",
  aiSecondPass: false,
  delayMs: 600,
  deepAgent: false,
  deepAgentMaxItems: 250,
  deepAgentMinSeverity: "high",
  autoPoc: true,
  autoPocBreakerThreshold: 3,
};

// ---------------------------------------------------------------------------
// App origin (OpenRouter HTTP-Referer)
// ---------------------------------------------------------------------------

/** Production origin used when neither APP_URL nor VERCEL_URL is set. */
export const APP_ORIGIN_FALLBACK = "https://smart-kontrakt.vercel.app";

/**
 * The app origin for outbound attribution headers: APP_URL, then
 * VERCEL_URL, then the production fallback. Values are used as-is
 * (trimmed) — the same semantics the four former inline copies had.
 *
 * @param {Record<string, string | undefined>} env
 * @returns {string}
 */
export function appOrigin(env) {
  return env?.APP_URL?.trim() || env?.VERCEL_URL?.trim() || APP_ORIGIN_FALLBACK;
}

// ---------------------------------------------------------------------------
// OpenRouter endpoints
// ---------------------------------------------------------------------------

/** OpenRouter chat-completions endpoint (OpenAI-compatible). */
export const OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions";
/** OpenRouter API-key info endpoint (usage/limit probe). */
export const OPENROUTER_KEY_URL = "https://openrouter.ai/api/v1/auth/key";

// ---------------------------------------------------------------------------
// Database env-var priority tables (resolution logic stays in db-env.ts)
// ---------------------------------------------------------------------------

/**
 * Ordered: the first entry that yields a usable URL wins.
 *
 * Pooled URLs come before the direct one because serverless functions exhaust a
 * direct connection pool; migrations go the other way (see DIRECT_ENV_VARS).
 */
export const DATABASE_ENV_VARS = [
  { name: "DATABASE_URL", role: "explicit override" },
  { name: "POSTGRES_PRISMA_URL", role: "Vercel Supabase integration — pooled (pgbouncer)" },
  { name: "POSTGRES_URL", role: "Vercel Supabase integration — pooled" },
  { name: "POSTGRES_URL_NON_POOLING", role: "Vercel Supabase integration — direct" },
  { name: "SUPABASE_DB_URL", role: "Supabase CLI / manual" },
  { name: "SUPABASE_POOLER_URL", role: "Supabase pooler" },
];

/**
 * Variables that carry a DIRECT (non-pooled) connection.
 *
 * DDL is run over one of these when available: a transaction-mode pooler
 * (pgbouncer) can reject or mis-scope `CREATE TABLE` / multi-statement
 * migrations, and a migration failure takes the whole connection down with it.
 *
 * `DATABASE_URL` is included as a last resort even though it *may* be pooled:
 * it is usually a hand-pasted direct string, and a wrong guess here is no worse
 * than the previous behaviour of using the pooled URL for everything.
 */
export const DIRECT_ENV_VARS = [
  "POSTGRES_URL_NON_POOLING",
  "DATABASE_URL",
  "SUPABASE_DB_URL",
];

// ---------------------------------------------------------------------------
// Shared env-URL cleaning (used by db-env.ts and scripts/migrate-vercel.mjs)
// ---------------------------------------------------------------------------

import { encodePostgresCredentials, looksLikePlaceholder } from "./pg-url.mjs";

/**
 * Parameters that belong to a different client, not to node-postgres.
 *
 * `POSTGRES_PRISMA_URL` is the Vercel Supabase integration's Prisma-flavoured
 * URL — the same pooler, plus `?pgbouncer=true`, which Prisma needs and `pg`
 * must never see. Forwarding a client's private parameter to the server is a
 * way for a connection string that looks perfectly correct to fail at startup.
 */
const FOREIGN_URL_PARAMS = ["pgbouncer", "connection_limit", "pool_timeout", "schema"];

/**
 * Drop other clients' parameters from a connection string.
 *
 * Operates on the query string only — never through `new URL()`, which would
 * re-encode (and so corrupt) a raw password in the authority.
 *
 * @param {string} url
 * @returns {string}
 */
export function sanitizeForNodePostgres(url) {
  const q = url.indexOf("?");
  if (q === -1) return url;
  const base = url.slice(0, q);
  const kept = url
    .slice(q + 1)
    .split("&")
    .filter(Boolean)
    .filter((pair) => !FOREIGN_URL_PARAMS.includes(pair.split("=")[0].toLowerCase()));
  return kept.length > 0 ? `${base}?${kept.join("&")}` : base;
}

/**
 * Trim, reject empties/placeholders, and normalise credentials.
 *
 * @param {string | undefined | null} value
 * @returns {string | undefined}
 */
export function cleanEnvUrl(value) {
  const trimmed = typeof value === "string" ? value.trim() : "";
  if (!trimmed) return undefined;
  // An unreplaced deploy template, or a placeholder someone pasted.
  if (trimmed.includes("<") || trimmed.includes(">") || looksLikePlaceholder(trimmed)) return undefined;
  if (trimmed.startsWith("postgresql://") || trimmed.startsWith("postgres://")) {
    // Hand-written URLs often carry a raw password; encoding here means a
    // password containing `@ # / :` connects instead of silently mis-parsing.
    // Idempotent, so an already-encoded URL is untouched.
    return sanitizeForNodePostgres(encodePostgresCredentials(trimmed));
  }
  return undefined;
}
