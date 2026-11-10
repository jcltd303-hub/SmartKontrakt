/**
 * Typed facade over `config.mjs`.
 *
 * The implementation is plain JavaScript so bare-`node` consumers
 * (`scripts/migrate-vercel.mjs`, `termux-backend/server.mjs`,
 * `scripts/run-fork-poc.sh`) can share the very same constants — importing a
 * `.ts` file there would need `--experimental-strip-types`. App and worker
 * code imports this module for the same values with types. One definition,
 * used by the browser, the server, the worker, the migrator and the backend.
 * See the `.mjs` for what belongs here and what deliberately does not.
 */
export {
  RPC_CHAINS,
  RPC_ORDER_ETHEREUM,
  ALL_RPC_URLS,
  BACKEND_PORT_DEFAULT,
  WORKER_PORT_DEFAULT,
  FOUNDRY_BACKEND_URL_DEFAULT,
  WORKER_URL_DEFAULT,
  WORKER_START_DEFAULTS,
  APP_ORIGIN_FALLBACK,
  appOrigin,
  OPENROUTER_API_URL,
  OPENROUTER_KEY_URL,
  DATABASE_ENV_VARS,
  DIRECT_ENV_VARS,
  sanitizeForNodePostgres,
  cleanEnvUrl,
} from "./config.mjs";

export type RpcChain = {
  id: string;
  name: string;
  chainId: number;
  rpcUrls: string[];
  blockExplorer: string;
};

export type WorkerStartDefaults = {
  chainId: string;
  aiSecondPass: boolean;
  delayMs: number;
  deepAgent: boolean;
  deepAgentMaxItems: number;
  deepAgentMinSeverity: string;
  autoPoc: boolean;
  autoPocBreakerThreshold: number;
};
