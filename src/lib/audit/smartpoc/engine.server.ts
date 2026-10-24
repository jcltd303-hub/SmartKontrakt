/**
 * SmartPoC engine (server-only).
 *
 * Implements the SmartPoC pipeline of arXiv:2511.12993 end to end:
 *
 *   Bug-Context Extraction (BCE)   — `./bce.ts`
 *     → Generate-Repair-Execute (GRE-Engine) — this file
 *        generate → pre-execution sanitizer → execute → post-execution debugger
 *     → Action-State Differential Verification (DV) — this file
 *        extract action/state → insert pre/post checks → execute → verdict
 *
 * The LLM calls go through OpenRouter using the per-purpose free-tier models
 * (`resolveOpenRouterConfig`); execution is injected by the caller (`execute`),
 * so this module never touches the Foundry backend or the browser directly.
 *
 * Nothing here throws: every failure is returned as a stop reason so a caller
 * (worker loop, server function) can persist a non-reproducible verdict rather
 * than crash a run.
 */

import { openRouterLimiter, withRetry } from "../rate-limit.ts";
import {
  postChatWithModelFallback,
  resolveOpenRouterConfig,
  extractJsonContent,
  stripThinkBlocks,
  type OpenRouterPurpose,
} from "../ai-review.server.ts";
import { countExecutableTestFunctions } from "../poc-outcome.ts";
import { selectPocFallbacks } from "../poc-fallbacks.ts";
import { smartbugsCategoryForDetector } from "../smartbugs.ts";
import { tailorTemplateToAbi, interfaceFromAbi, type AbiItem } from "../abi.ts";
import { extractBugContext, type BceFinding } from "./bce.ts";
import { sanitizePocDraft, functionSignaturesFromInventory, type PocTarget } from "./sanitize.ts";
import {
  buildPocGenerationPrompt,
  buildPocRegenerationPrompt,
  buildActionStateExtractionPrompt,
  buildDifferentialInsertionPrompt,
  buildDifferentialVerdictPrompt,
} from "./prompts.ts";

/** Default GRE-Engine retry budget (paper: B = 5). */
export const SMART_POC_RETRY_BUDGET = 5;

export type PocExecution = {
  status: "passed" | "failed" | "error" | "backend_unreachable" | "skipped";
  logs: string;
  durationMs: number;
  runAt: string;
  error?: string;
};

/** Injected runner: compiles + runs a Foundry test, returns the outcome. */
export type GreExecute = (testCode: string) => Promise<PocExecution>;

export type GreInput = {
  contractName: string;
  body: string;
  findings: BceFinding[];
  /** Inventory functions (from `Report.inventory.functions`) for the signature set. */
  inventoryFunctions: { name: string; params: string }[];
  compilerVersion?: string | null;
  /** Public ABIs for DV extraction; derived from the inventory when omitted. */
  publicAbis?: string[];
  fourbyteSection?: string;
  retryBudget?: number;
  /** The target's gathered ABI, so the starting template is tailored to it. */
  abi?: AbiItem[] | null;
  /** Where that ABI came from (sourcify / etherscan / heuristic). */
  abiSource?: string | null;
};

export type GreResult = {
  ok: boolean;
  code: string | null;
  attempts: number;
  execution: PocExecution | null;
  bugContext: string;
  bugContextFunctions: string[];
  notes: string[];
  llmMs: number;
  stopReason: string | null;
};

export type DvResult = {
  validated: boolean;
  reason: string;
  instrumentedCode: string | null;
  differential: { action: string[]; state: string[] } | null;
  execution: PocExecution | null;
  preState: string[];
  postState: string[];
  notes: string[];
  stopReason: string | null;
};

export type SmartPocResult = {
  ok: boolean;
  poc: string | null;
  execution: PocExecution | null;
  differential: DvResult | null;
  /** DV verdict: the finding was confirmed exploitable. */
  validated: boolean;
  bugContext: string;
  notes: string[];
  stopReason: string | null;
};

function referer(): string {
  return (
    process.env.APP_URL?.trim() ||
    process.env.VERCEL_URL?.trim() ||
    "https://smart-kontrakt.vercel.app"
  );
}

/**
 * One OpenRouter chat call with the limiter, finite retries, and a fail-fast
 * timeout policy (a timeout means the prompt is too big for the model — retrying
 * the same huge prompt only burns time).
 */
async function chat(
  purpose: OpenRouterPurpose,
  system: string,
  user: string,
  opts: { json?: boolean; maxTokens?: number; timeoutMs?: number } = {},
): Promise<string> {
  const { apiKey } = resolveOpenRouterConfig(process.env, purpose);
  if (!apiKey) throw new Error("OPENROUTER_API_KEY is not set");
  const response = await withRetry(
    async () => {
      await openRouterLimiter.acquire();
      // The model is chosen — and fallen back through — inside the helper, so a
      // free model gated to an app (HTTP 403) degrades instead of failing the step.
      return postChatWithModelFallback({
        purpose,
        apiKey,
        timeoutMs: opts.timeoutMs ?? 180_000,
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
          "HTTP-Referer": referer(),
          "X-Title": "SmartKontrakt / Kiln SmartPoC",
        },
        makeBody: (model) => ({
          model,
          messages: [
            { role: "system", content: system },
            { role: "user", content: user },
          ],
          ...(opts.json ? { response_format: { type: "json_object" } } : {}),
          temperature: 0.3, // paper §4.2: temperature 0.3
          max_tokens: opts.maxTokens ?? 8000,
        }),
      });
    },
    {
      retries: 3,
      baseDelayMs: 2000,
      retryOn: (err) => {
        if (!(err instanceof Error)) return false;
        if (err.name === "AbortError" || err.name === "TimeoutError") return false;
        if (/timeout|timed out|abort/i.test(err.message)) return false;
        return /429|rate.?limit|too many|network|fetch failed|econnreset|etimedout|econnrefused|socket hang up|503|502|500/i.test(
          err.message,
        );
      },
    },
  );
  if (!response.ok) {
    const detail = (await response.text().catch(() => "")).slice(0, 400);
    throw new Error(`OpenRouter HTTP ${response.status}: ${detail}`);
  }
  const data = (await response.json()) as {
    choices?: Array<{ message?: { content?: string | null } }>;
  };
  const content = data.choices?.[0]?.message?.content;
  if (!content) throw new Error("OpenRouter returned no message content");
  return content;
}

/**
 * Extract the PoC source from a model response. When the response
 * carries several fenced blocks, prefer the first block that contains
 * executable test functions: models routinely emit a helper or attack
 * contract first and the Test contract second, and taking the first
 * block verbatim produced test-less drafts that forge "ran" as hollow
 * zero-test passes. When no block carries a test function — or there
 * is a single block — the first fenced block wins, exactly as before;
 * with no fences at all, the trimmed text.
 */
export function extractCodeBlock(text: string): string {
  const cleaned = stripThinkBlocks(text);
  const blocks = [...cleaned.matchAll(/```(?:solidity|sol)?\s*\n([\s\S]*?)```/gi)].map((m) => m[1].trim());
  if (blocks.length) {
    return blocks.find((b) => countExecutableTestFunctions(b) > 0) ?? blocks[0];
  }
  return cleaned.trim();
}

/** Derive public ABIs (functions + public getters) for the DV extractor. */
function derivePublicAbis(input: GreInput): string[] {
  if (input.publicAbis && input.publicAbis.length) return input.publicAbis;
  const abis = new Set<string>();
  for (const fn of input.inventoryFunctions) {
    const bare = fn.name.includes(".") ? fn.name.slice(fn.name.lastIndexOf(".") + 1) : fn.name;
    if (!bare || /^(constructor|fallback|receive)$/.test(bare)) continue;
    abis.add(`${bare}(${fn.params ?? ""})`);
  }
  return [...abis];
}

/** A short "does this function name exist" helper for the semantic-link LLM step. */
async function inferSemanticLinks(args: {
  functions: { name: string; signature: string }[];
  keyFunctions: string[];
}): Promise<string[]> {
  const user = `Key functions implicated by an audit finding:
${args.keyFunctions.join(", ")}

All functions in the contract:
${args.functions.map((f) => f.signature).join("\n")}

Return the names of functions that are SEMANTICALLY related to the key functions:
- inverse operations (deposit/withdraw, mint/burn, stake/unstake …), and
- state-coupled operations (functions that read or update the same storage variable).
Return strictly JSON: {"functions": ["name1", "name2"]}. Use only names from the list above.`;
  const raw = await chat(
    "json",
    "You select bug-related functions for a smart-contract PoC context slice. Respond strictly as JSON.",
    user,
    { json: true, maxTokens: 1000, timeoutMs: 60_000 },
  );
  const parsed = extractJsonContent(raw) as { functions?: unknown };
  return Array.isArray(parsed.functions)
    ? parsed.functions.filter((f): f is string => typeof f === "string")
    : [];
}

/**
 * GRE-Engine: iterative generate → sanitize → execute → debug until the PoC
 * runs or the retry budget is exhausted.
 */
export async function runGreEngine(input: GreInput, execute: GreExecute): Promise<GreResult> {
  const started = Date.now();
  const notes: string[] = [];
  const budget = Math.max(1, input.retryBudget ?? SMART_POC_RETRY_BUDGET);

  const { apiKey } = resolveOpenRouterConfig(process.env, "code");
  if (!apiKey) {
    return {
      ok: false, code: null, attempts: 0, execution: null, bugContext: "",
      bugContextFunctions: [], notes, llmMs: 0, stopReason: "no_api_key",
    };
  }

  // ── Bug-Context Extraction ────────────────────────────────────────────────
  let bugContext = "";
  let bugContextFunctions: string[] = [];
  try {
    const ctx = await extractBugContext({
      body: input.body,
      findings: input.findings,
      inferSemanticLinks: (args) => inferSemanticLinks(args).catch(() => []),
    });
    bugContext = ctx.context;
    bugContextFunctions = ctx.functions;
    notes.push(...ctx.notes);
  } catch (err) {
    notes.push(`BCE failed (${err instanceof Error ? err.message : String(err)}); using raw source`);
    bugContext = input.body.slice(0, 12000);
  }

  const target: PocTarget = {
    contractName: input.contractName,
    compilerVersion: input.compilerVersion ?? null,
    functionSignatures: functionSignaturesFromInventory(input.inventoryFunctions),
  };

  const primary =
    input.findings.find((f) => /critical|high/i.test(f.severity)) ?? input.findings[0] ?? {
      title: "Unspecified vulnerability",
      severity: "high",
      detector: "unknown",
      summary: "",
      locationFn: null,
    };

  // selectPocFallbacks falls back to the finding's SmartBugs-Curated (DASP)
  // category when the detector has no harness of its own. For not-PoC-able
  // detectors (hygiene / bytecode-shape / analyzer-meta findings) it yields
  // nothing, and the prompt below is built without a starting template.
  const smartbugs = smartbugsCategoryForDetector(primary.detector);
  const template = selectPocFallbacks([{ detector: primary.detector, severity: primary.severity }], 1)[0];

  const generation = buildPocGenerationPrompt({
    contractName: input.contractName,
    buildMetadata: `${input.compilerVersion ?? "unknown"} | contract ${input.contractName}`,
    finding: {
      title: primary.title, severity: primary.severity, detector: primary.detector,
      summary: primary.summary, locationFn: primary.locationFn ?? null, smartbugs,
    },
    bugContext,
    // Tailor the template's target surface to the real ABI when we have one, so
    // the harness starts from the contract's actual signatures, not a guess.
    targetAbiSection: input.abi && input.abi.length > 0 ? interfaceFromAbi(input.abi, "ITarget") : null,
    startingTemplate: template
      ? {
          file: template.file,
          source:
            input.abi && input.abi.length > 0
              ? tailorTemplateToAbi(template.source, input.abi, { source: input.abiSource ?? undefined })
              : template.source,
        }
      : null,
    fourbyteSection: input.fourbyteSection,
  });

  let previousCode = "";
  let errorLogs = "";
  let lastExecution: PocExecution | null = null;

  for (let attempt = 1; attempt <= budget; attempt += 1) {
    let draft: string;
    try {
      if (attempt === 1) {
        draft = await chat("code", generation.system, generation.user, { maxTokens: 8000 });
      } else {
        const regen = buildPocRegenerationPrompt({
          previousPoc: previousCode,
          errorLogs,
          generationUser: generation.user,
        });
        draft = await chat("code", regen.system, regen.user, { maxTokens: 8000 });
      }
    } catch (err) {
      notes.push(`generation failed on attempt ${attempt}: ${err instanceof Error ? err.message : String(err)}`);
      break;
    }

    // ── Pre-execution sanitizer ─────────────────────────────────────────────
    const { code: sanitized, notes: sanNotes } = sanitizePocDraft(extractCodeBlock(draft), target);
    notes.push(...sanNotes.map((n) => `sanitizer: ${n}`));

    // ── Execution ───────────────────────────────────────────────────────────
    let execution: PocExecution;
    try {
      execution = await execute(sanitized);
    } catch (err) {
      execution = {
        status: "error",
        logs: err instanceof Error ? err.message : String(err),
        durationMs: 0,
        runAt: new Date().toISOString(),
      };
    }
    lastExecution = execution;

    if (execution.status === "passed") {
      notes.push(`PoC executed on attempt ${attempt}`);
      return {
        ok: true, code: sanitized, attempts: attempt, execution, bugContext,
        bugContextFunctions, notes, llmMs: Date.now() - started, stopReason: null,
      };
    }
    if (execution.status === "backend_unreachable") {
      return {
        ok: false, code: sanitized, attempts: attempt, execution, bugContext,
        bugContextFunctions, notes, llmMs: Date.now() - started,
        stopReason: "backend_unreachable",
      };
    }
    if (execution.status === "skipped") {
      // Pre-run balance guard: nothing at stake. Repairing would be pointless.
      return {
        ok: false, code: sanitized, attempts: attempt, execution, bugContext,
        bugContextFunctions, notes, llmMs: Date.now() - started,
        stopReason: "skipped_zero_balance",
      };
    }

    // ── Post-execution debugger: feed diagnostics to the next iteration ──────
    previousCode = sanitized;
    errorLogs = execution.logs || execution.error || "(no diagnostics)";
    notes.push(`attempt ${attempt}: ${execution.status} — repairing`);
  }

  return {
    ok: false, code: previousCode || null, attempts: budget, execution: lastExecution,
    bugContext, bugContextFunctions, notes, llmMs: Date.now() - started,
    stopReason: "retry_budget_exhausted",
  };
}

/**
 * GRE-Engine seeded with an existing PoC draft (e.g. a Deep Agent hypothesis):
 * sanitize → execute → repair, up to `budget` attempts, returning the first PoC
 * that reaches a verdict. This is the GRE loop for callers that already have a
 * draft and do not need the generation prompt.
 */
export async function runGreRepairLoop(
  input: { draft: string; target: PocTarget },
  execute: GreExecute,
  budget = SMART_POC_RETRY_BUDGET,
): Promise<{ ok: boolean; code: string; attempts: number; execution: PocExecution | null; notes: string[]; stopReason: string | null }> {
  const notes: string[] = [];
  const { apiKey } = resolveOpenRouterConfig(process.env, "code");
  let sanitized = sanitizePocDraft(input.draft, input.target);
  notes.push(...sanitized.notes.map((n) => `sanitizer: ${n}`));
  let code = sanitized.code;
  let lastExecution: PocExecution | null = null;
  const attempts = Math.max(1, budget);

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    let execution: PocExecution;
    try {
      execution = await execute(code);
    } catch (err) {
      execution = {
        status: "error", logs: err instanceof Error ? err.message : String(err),
        durationMs: 0, runAt: new Date().toISOString(),
      };
    }
    lastExecution = execution;

    if (execution.status === "passed") {
      return { ok: true, code, attempts: attempt, execution, notes, stopReason: null };
    }
    if (execution.status === "backend_unreachable") {
      return { ok: false, code, attempts: attempt, execution, notes, stopReason: "backend_unreachable" };
    }
    if (execution.status === "skipped") {
      // Pre-run balance guard: nothing at stake, so do not spend a repair on it.
      return { ok: false, code, attempts: attempt, execution, notes, stopReason: "skipped_zero_balance" };
    }
    if (attempt === attempts) break;
    if (!apiKey) {
      notes.push("no OPENROUTER_API_KEY — cannot repair; stopping");
      break;
    }
    try {
      const regen = buildPocRegenerationPrompt({
        previousPoc: code,
        errorLogs: execution.logs || execution.error || "(no diagnostics)",
      });
      const raw = await chat("code", regen.system, regen.user, { maxTokens: 8000 });
      sanitized = sanitizePocDraft(extractCodeBlock(raw), input.target);
      notes.push(...sanitized.notes.map((n) => `sanitizer: ${n}`));
      code = sanitized.code;
      notes.push(`attempt ${attempt}: ${execution.status} — repaired`);
    } catch (err) {
      notes.push(`repair failed on attempt ${attempt}: ${err instanceof Error ? err.message : String(err)}`);
      break;
    }
  }

  return { ok: false, code, attempts, execution: lastExecution, notes, stopReason: "retry_budget_exhausted" };
}

/** Parse the `SMARTPOC_STATE|pre|post|<label>` lines the DV insertion emits. */
export function parseDifferentialLogs(logs: string): { pre: string[]; post: string[] } {
  const pre: string[] = [];
  const post: string[] = [];
  for (const line of logs.split("\n")) {
    const m = line.match(/SMARTPOC_STATE\|(pre|post)\|([^\s,]+)[\s,]+(.*)$/i);
    if (!m) continue;
    (m[1].toLowerCase() === "pre" ? pre : post).push(`${m[2]}=${m[3].trim()}`);
  }
  return { pre, post };
}

/**
 * Action-State Differential Verification: instrument the PoC with pre/post
 * trigger state queries, execute, and let the model issue a strict verdict.
 */
export async function runDifferentialVerification(
  input: { finding: BceFinding; poc: string; publicAbis: string[] },
  execute: GreExecute,
): Promise<DvResult> {
  const notes: string[] = [];
  const { apiKey } = resolveOpenRouterConfig(process.env, "json");
  if (!apiKey) {
    return {
      validated: false, reason: "OPENROUTER_API_KEY is not set", instrumentedCode: null,
      differential: null, execution: null, preState: [], postState: [], notes, stopReason: "no_api_key",
    };
  }

  // (1) Extraction — action + observable state from the public ABIs.
  let differential: { action: string[]; state: string[] };
  try {
    const prompt = buildActionStateExtractionPrompt({
      finding: { title: input.finding.title, summary: input.finding.summary },
      publicAbis: input.publicAbis,
      poc: input.poc,
    });
    const raw = await chat("json", prompt.system, prompt.user, { json: true, maxTokens: 1000, timeoutMs: 60_000 });
    const parsed = extractJsonContent(raw) as { action?: unknown; state?: unknown };
    differential = {
      action: Array.isArray(parsed.action) ? parsed.action.filter((a): a is string => typeof a === "string") : [],
      state: Array.isArray(parsed.state) ? parsed.state.filter((s): s is string => typeof s === "string") : [],
    };
    if (!differential.action.length && !differential.state.length) {
      return {
        validated: false, reason: "no action/state could be extracted", instrumentedCode: null,
        differential, execution: null, preState: [], postState: [], notes, stopReason: "no_oracle",
      };
    }
  } catch (err) {
    return {
      validated: false, reason: `extraction failed: ${err instanceof Error ? err.message : String(err)}`,
      instrumentedCode: null, differential: null, execution: null, preState: [], postState: [],
      notes, stopReason: "extraction_failed",
    };
  }

  // (2) Insertion — materialize the oracle as pre/post checks + logs.
  let instrumented: string;
  try {
    const prompt = buildDifferentialInsertionPrompt({ poc: input.poc, differential });
    const raw = await chat("code", prompt.system, prompt.user, { maxTokens: 8000 });
    instrumented = extractCodeBlock(raw);
    if (!/SMARTPOC_STATE/.test(instrumented)) {
      notes.push("insertion did not emit SMARTPOC_STATE markers; verdict relies on raw logs");
    }
  } catch (err) {
    return {
      validated: false, reason: `insertion failed: ${err instanceof Error ? err.message : String(err)}`,
      instrumentedCode: null, differential, execution: null, preState: [], postState: [],
      notes, stopReason: "insertion_failed",
    };
  }

  // (3) Execute + verdict.
  let execution: PocExecution;
  try {
    execution = await execute(instrumented);
  } catch (err) {
    execution = {
      status: "error", logs: err instanceof Error ? err.message : String(err),
      durationMs: 0, runAt: new Date().toISOString(),
    };
  }
  const { pre, post } = parseDifferentialLogs(execution.logs ?? "");
  if (execution.status === "backend_unreachable") {
    return {
      validated: false, reason: "backend unreachable", instrumentedCode: instrumented,
      differential, execution, preState: pre, postState: post, notes, stopReason: "backend_unreachable",
    };
  }

  try {
    const prompt = buildDifferentialVerdictPrompt({
      finding: { title: input.finding.title, summary: input.finding.summary },
      differential, preState: pre, postState: post, logs: execution.logs ?? "",
    });
    const raw = await chat("json", prompt.system, prompt.user, { json: true, maxTokens: 800, timeoutMs: 60_000 });
    const parsed = extractJsonContent(raw) as { validated?: unknown; reason?: unknown };
    const validated = parsed.validated === true;
    return {
      validated,
      reason: typeof parsed.reason === "string" ? parsed.reason : validated ? "state delta matches the bug" : "no conclusive delta",
      instrumentedCode: instrumented,
      differential,
      execution,
      preState: pre,
      postState: post,
      notes,
      stopReason: null,
    };
  } catch (err) {
    return {
      validated: false, reason: `verdict failed: ${err instanceof Error ? err.message : String(err)}`,
      instrumentedCode: instrumented, differential, execution, preState: pre, postState: post,
      notes, stopReason: "verdict_failed",
    };
  }
}

/**
 * End-to-end: BCE → GRE-Engine → Differential Verification. Returns a validated
 * PoC (or a clear stop reason) without throwing.
 */
export async function runSmartPocValidation(input: GreInput, execute: GreExecute): Promise<SmartPocResult> {
  const notes: string[] = [];
  const gre = await runGreEngine(input, execute);
  notes.push(...gre.notes);
  if (!gre.ok || !gre.code) {
    return {
      ok: false, poc: gre.code, execution: gre.execution, differential: null, validated: false,
      bugContext: gre.bugContext, notes, stopReason: gre.stopReason ?? "gre_failed",
    };
  }

  const primary =
    input.findings.find((f) => /critical|high/i.test(f.severity)) ?? input.findings[0] ?? {
      title: "Unspecified vulnerability", severity: "high", detector: "unknown", summary: "", locationFn: null,
    };

  const dv = await runDifferentialVerification(
    { finding: primary, poc: gre.code, publicAbis: derivePublicAbis(input) },
    execute,
  );
  notes.push(...dv.notes);

  return {
    ok: true,
    poc: gre.code,
    execution: gre.execution,
    differential: dv,
    validated: dv.validated,
    bugContext: gre.bugContext,
    notes,
    stopReason: dv.validated ? null : dv.stopReason,
  };
}
