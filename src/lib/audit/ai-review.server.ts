import type { ResnetResult } from "./resnet-result.ts";
import { auditEvidence } from "./audit-evidence.ts";
import type { Finding, Inventory } from "./types.ts";
import { isTransientError, openRouterLimiter, withRetry } from "./rate-limit.ts";
import { selectPocFallbacks } from "./poc-fallbacks.ts";
import { smartbugsCategoryForDetector } from "./smartbugs.ts";
import { formatFourbyteResultsForPrompt, type FourbyteResults } from "./fourbyte.ts";
import { countExecutableTestFunctions } from "./poc-outcome.ts";

export type AiSecurityReview = {
  threatModelReport: string;
  foundryTestCode: string;
  economicRiskSummary: string;
  source: "openrouter" | "template";
  // Read by the workbench's report export (use-workbench-controller). They were
  // always part of the model's reply, just never declared here, so the UI was
  // typed against fields the type did not have.
  overallVerdict?: string;
  summary?: string;
};

/** OpenRouter chat-completions endpoint (OpenAI-compatible). */
export const OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions";

/**
 * Best current OpenRouter **free-tier** models, by purpose. Verified against
 * the live catalog (GET https://openrouter.ai/api/v1/models + per-model
 * endpoints) on 2026-10-25: of 467 listed models only 20 are genuinely free
 * (prompt AND completion price 0). The big free coder/reasoner ids of earlier
 * rotations (Qwen3-Coder, DeepSeek, Kimi, gpt-oss) are not free in the
 * catalog today, so these picks are the best of what is actually free now.
 *
 * The free tier is a shared, per-account daily quota (50 requests/day, or
 * 1000 after a one-time $10 top-up) and the endpoints are 4-bit quantised, so
 * the model is chosen per task rather than globally:
 *
 *   review — the AI review's narrative call (threat model + economic
 *            summary) and the prose second pass. Nemotron 3 Ultra
 *            (550B/55B MoE): the strongest free reasoning class in the
 *            catalog, 1M-token context (full source + findings), 65,536
 *            max completion against the 4,000 the narrative call
 *            requests. Its single endpoint is healthy (status 0) and
 *            it carried Jer's 59,852-address live run. Unchanged.
 *   code   — Foundry PoC synthesis, regeneration and compile repair,
 *            plus the AI review's test-code call (the review is two
 *            calls since the 2026-10-25 split — see NARRATIVE/CODE
 *            budgets below). Laguna S 2.1 (Poolside): the free list's
 *            dedicated frontier coding model — 118B total / 8B active,
 *            70.2% Terminal-Bench 2.1 per its catalog description,
 *            262K context, 32,768 max completion (2x the 16,000 the
 *            review's test call requests, 4x the 8,000 the PoC calls
 *            request). Endpoint healthy
 *            (status 0). History: was `thinkingmachines/inkling-small:free`
 *            (harness-gated — OpenRouter refuses it for plain API calls,
 *            HTTP 403), then Nemotron Ultra as the one verified-working
 *            stopgap; now that a purpose-built coder is free and healthy,
 *            the code purposes go back to a dedicated model. One caveat,
 *            recorded deliberately: the repair call sends
 *            `response_format`, which Laguna's catalog entry does not list
 *            (Ultra's does not either, and NVIDIA's endpoint accepts it in
 *            practice). If Poolside's endpoint rejects it, repair degrades
 *            best-effort exactly as a failed repair does today — set
 *            OPENROUTER_MODEL_CODE back to the Nemotron id to restore the
 *            stopgap with no code change.
 *   json   — Deep Agent hypotheses, SmartPoC DV extraction and verdicts:
 *            exact-schema JSON via response_format. Stays on Nemotron 3
 *            Ultra. The tempting alternative is Nemotron 3 Super (120B/12B):
 *            the only free model whose catalog entry lists response_format
 *            AND structured_outputs, with a 235,929 max completion — but at
 *            decision time its single endpoint was flagged (endpoint status
 *            -5 in two independent catalog reads) while both models picked
 *            here sat at 0, a saturation liability for batch runs, and
 *            every free model here has exactly one endpoint, so there is no
 *            routing redundancy to absorb a degraded one. Ultra's JSON wobbles are
 *            already absorbed by the tolerant extraction + corrective-retry
 *            machinery. Revisit Super when its endpoint health clears;
 *            OPENROUTER_MODEL_JSON can point at it today.
 *
 * `OPENROUTER_MODEL` overrides every purpose; `OPENROUTER_MODEL_<PURPOSE>`
 * overrides one (e.g. OPENROUTER_MODEL_CODE). Free-tier ids churn — re-check
 * the live catalog before relying on one; the fallback chain below
 * (openrouter/free) absorbs an id that gets withdrawn or gated.
 */
export const OPENROUTER_MODELS = {
  review: "nvidia/nemotron-3-ultra-550b-a55b:free",
  code: "poolside/laguna-s-2.1:free",
  json: "nvidia/nemotron-3-ultra-550b-a55b:free",
} as const;

export type OpenRouterPurpose = keyof typeof OPENROUTER_MODELS;

/** Default model — matches the default purpose ("review"); overridable via env. */
export const DEFAULT_OPENROUTER_MODEL = OPENROUTER_MODELS.review;

/**
 * Tried in order when a preferred model cannot be used by a plain API call at
 * all — gated to specific apps, retired, or misspelled. Free-tier ids churn and
 * gating appears without notice, so the pipeline must degrade rather than stop.
 *
 * `openrouter/free` is OpenRouter's own router to whichever free model is
 * currently available, so it cannot itself be gated to an app.
 */
export const OPENROUTER_FALLBACK_MODELS: readonly string[] = ["openrouter/free"];

/** Models to try for a purpose, most preferred first, de-duplicated. */
export function modelCandidates(
  purpose: OpenRouterPurpose,
  env: NodeJS.ProcessEnv = process.env,
): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const id of [resolveOpenRouterModel(purpose, env), ...OPENROUTER_FALLBACK_MODELS]) {
    const model = id.trim();
    if (!model || seen.has(model)) continue;
    seen.add(model);
    out.push(model);
  }
  return out;
}

/**
 * Does this failure mean the MODEL cannot be used, as opposed to the request
 * being wrong or the provider being down?
 *
 * Matched on the message on purpose: OpenRouter answers 403 for a gated model
 * and 404 for an unknown one, but a plain 403/404 can also mean something else
 * entirely (a bad key), and falling back for those would triple the latency for
 * no reason.
 */
export function isModelUnavailable(status: number, body: string): boolean {
  if (status === 404) return true;
  if (status !== 400 && status !== 403) return false;
  return /only available on|agentic harness|gate free endpoints|no endpoints found|not a valid model|is not available|does not exist/i.test(
    body,
  );
}

/**
 * POST a chat completion, advancing through the candidate models when the model
 * itself is unusable.
 *
 * A gated free model used to fail the whole step: a SmartPoC repair died on
 * `thinkingmachines/inkling-small:free` with "only available on agentic
 * harnesses", and the run stopped there. Now the call degrades to the next free
 * model instead.
 *
 * Returns the first usable response. A non-model failure (bad request, provider
 * outage) is returned immediately for the caller to handle exactly as before.
 */
export async function postChatWithModelFallback(args: {
  purpose: OpenRouterPurpose;
  apiKey: string;
  headers: Record<string, string>;
  makeBody: (model: string) => unknown;
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
}): Promise<Response> {
  const candidates = modelCandidates(args.purpose, args.env ?? process.env);
  let last: Response | null = null;
  for (let i = 0; i < candidates.length; i += 1) {
    const model = candidates[i]!;
    const response = await fetch(OPENROUTER_API_URL, {
      method: "POST",
      headers: args.headers,
      body: JSON.stringify(args.makeBody(model)),
      signal: AbortSignal.timeout(args.timeoutMs ?? 60_000),
    });
    if (response.ok) return response;
    // Read a copy: the caller still needs the body for its own error message.
    const detail = (await response.clone().text().catch(() => "")).slice(0, 500);
    if (!isModelUnavailable(response.status, detail)) return response;
    last = response;
    const next = candidates[i + 1];
    console.warn(
      next
        ? `[openrouter] ${model} is not usable (HTTP ${response.status}) — falling back to ${next}`
        : `[openrouter] no usable model for purpose "${args.purpose}" (last tried ${model}, HTTP ${response.status})`,
    );
  }
  return last!;
}

export type OpenRouterConfig = {
  apiKey: string | undefined;
  model: string;
};

const PLACEHOLDER_KEYS = new Set(["", "MY_OPENROUTER_API_KEY", "YOUR_OPENROUTER_API_KEY"]);

/**
 * The model id for a purpose: `OPENROUTER_MODEL` (global) wins, then
 * `OPENROUTER_MODEL_<PURPOSE>`, then the per-purpose free-tier default.
 */
export function resolveOpenRouterModel(
  purpose: OpenRouterPurpose,
  env: NodeJS.ProcessEnv = process.env,
): string {
  const global = env.OPENROUTER_MODEL?.trim();
  if (global) return global;
  const perPurpose = env[`OPENROUTER_MODEL_${purpose.toUpperCase()}`]?.trim();
  return perPurpose || OPENROUTER_MODELS[purpose];
}

/**
 * Resolve OpenRouter config from the environment.
 * Returns apiKey undefined when no real key is configured, so callers
 * can fall back to the template review instead of calling the API.
 *
 * `purpose` selects the per-task free-tier default (see OPENROUTER_MODELS);
 * it defaults to "review" so existing callers keep the reasoning model.
 */
export function resolveOpenRouterConfig(
  env: NodeJS.ProcessEnv = process.env,
  purpose: OpenRouterPurpose = "review",
): OpenRouterConfig {
  const rawKey = env.OPENROUTER_API_KEY?.trim();
  const apiKey = rawKey && !PLACEHOLDER_KEYS.has(rawKey) ? rawKey : undefined;
  const model = resolveOpenRouterModel(purpose, env);
  return { apiKey, model };
}

/**
 * Default per-attempt timeout for the AI review call, ms.
 *
 * The review is the heaviest generation in the codebase: the
 * prompts carry up to 12,000 chars of source, the findings, the
 * fourbyte context and up to three FULL fallback templates, and the
 * two replies must hold a complete threat-model report and a
 * complete Foundry test file (split calls since 2026-10-25 —
 * max_tokens 4000 narrative, 16000 test code). The codebase's other long
 * generations (Deep Agent rounds, PoC repair, SmartPoC) already run
 * at 180s for comparable work; the review sat at 60s, and on the
 * shared free lane every attempt died at that budget in Jer's live
 * pipeline run (2026-10-25) — the run fell back to template reviews
 * for entry after entry. The timeout batch first raised the default
 * to 240s (the house 180s plus headroom for this prompt/response
 * size); Jer then directed 300s outright — his live run is a
 * 59,852-address batch on the shared free lane, whose queue latency
 * is the dominant term, and a timed-out review costs the entry its
 * LLM review entirely. `OPENROUTER_TIMEOUT_MS` overrides it (raise
 * it on the free lane, lower it behind a fast paid model).
 */
export const DEFAULT_OPENROUTER_TIMEOUT_MS = 300_000;

/** The review call's per-attempt timeout: `OPENROUTER_TIMEOUT_MS`
 *  when it parses to a positive number, else the default. */
export function resolveOpenRouterTimeoutMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = Number(env.OPENROUTER_TIMEOUT_MS);
  return Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : DEFAULT_OPENROUTER_TIMEOUT_MS;
}

/**
 * Is this failure the call's own clock — as opposed to an HTTP error,
 * a provider failure or a network error? `AbortSignal.timeout`
 * raises a DOMException named "TimeoutError" (the exact shape in
 * Jer's worker log: `DOMException [TimeoutError]: The operation was
 * aborted due to timeout`); an explicit abort surfaces as
 * "AbortError". The message check covers runtimes that surface the
 * same condition under a generic name.
 */
export function isOpenRouterTimeoutError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  if (err.name === "TimeoutError" || err.name === "AbortError") return true;
  return /aborted due to timeout|timed out/i.test(err.message);
}

/**
 * Reasoning models (Nemotron included) can leak chain-of-thought into the
 * message content as <think> blocks. Strip them before parsing or storing —
 * a stray brace inside a think block breaks JSON extraction, and raw
 * reasoning must never land in a stored narrative. Handles truncated
 * output (dangling open tag with no closer).
 */
export function stripThinkBlocks(content: string): string {
  return content
    .replace(/(?:<think>|<thinking>)[\s\S]*?(?:<\/think>|<\/thinking>)/gi, "")
    .replace(/(?:<think>|<thinking>)[\s\S]*$/i, "")
    .trim();
}

/**
 * Balanced top-level `{...}` spans of a text, in order. One pass that
 * tracks brace depth while respecting JSON string literals and their
 * escapes, so braces inside string values (a Solidity PoC is full of
 * them) never open or close a span. A span is only recorded when its
 * depth returns to zero — a truncated reply yields NO span for its
 * unclosed object instead of a corrupt slice, and balanced non-JSON
 * spans in surrounding prose (a code sketch) are returned as their own
 * candidates for the caller to reject and move past.
 */
export function balancedObjectSpans(text: string): Array<{ start: number; end: number }> {
  const spans: Array<{ start: number; end: number }> = [];
  let depth = 0;
  let spanStart = -1;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
    } else if (ch === "{") {
      if (depth === 0) spanStart = i;
      depth += 1;
    } else if (ch === "}") {
      if (depth > 0) {
        depth -= 1;
        if (depth === 0 && spanStart >= 0) {
          spans.push({ start: spanStart, end: i });
          spanStart = -1;
        }
      }
    }
  }
  return spans;
}

/** First ~200 chars of a model reply, whitespace-collapsed — enough of
 *  the offending text to diagnose a parse failure from the error alone. */
export function replySnippet(content: string): string {
  return content.replace(/\s+/g, " ").trim().slice(0, 200);
}

/**
 * Extract the JSON payload from a model reply — THE shared extractor
 * for every LLM-JSON consumer (AI review, Deep Agent rounds, PoC
 * repair, SmartPoC BCE/DV). Free-tier models routinely ignore
 * `response_format: json_object` and wrap the payload in prose or
 * fences; the tolerant paths below recover it. When nothing parses,
 * the thrown error carries the head of the offending reply — a bare
 * "did not contain a JSON object" with no trace of the reply cost a
 * full debugging round on 2026-10-25 (both the Deep Agent and a PoC
 * repair died on this in one screenshot).
 */
export function extractJsonContent(content: string): unknown {
  const trimmed = stripThinkBlocks(content);
  // Bare reply: the whole text is the payload (the historical fast path).
  try {
    return JSON.parse(trimmed);
  } catch {
    // fall through to the tolerant paths
  }
  // Fenced replies: try EVERY fenced block in order — free-tier models
  // routinely fence a prose sketch or an example before the real JSON,
  // and the old first-fence-only read died on exactly that.
  for (const fenced of trimmed.matchAll(/```(?:\w+)?\s*\n?([\s\S]*?)```/g)) {
    try {
      return JSON.parse(fenced[1].trim());
    } catch {
      // not this block — keep looking
    }
  }
  // Prose around the payload: parse the first balanced top-level
  // object that is actually JSON. Balanced non-JSON spans (a Solidity
  // sketch in the prose) fail their parse and are skipped, never
  // merged into the payload the way the old first-{ to last-} slice
  // merged them.
  for (const span of balancedObjectSpans(trimmed)) {
    try {
      return JSON.parse(trimmed.slice(span.start, span.end + 1));
    } catch {
      // balanced but not JSON — try the next span
    }
  }
  throw new Error(
    `Model reply did not contain a JSON object (reply began: "${replySnippet(trimmed)}")`,
  );
}

function buildFallbackReview(contractName: string, findings: Finding[], _codeOrBytecode: string): AiSecurityReview {
  const critList = findings.filter((f) => f.severity === "critical" || f.severity === "high");
  const topIssue = critList[0]?.title ?? findings[0]?.title ?? "No static finding reported";

  // No-AI path: return the best-matching fallback-library template as the
  // starting-point PoC, not a hollow sanity check. The template's TODOs
  // must be adapted to the target's real ABI before running — it fails
  // loudly (require with a message) until then, which is the honest
  // signal. A passing sanity check that proves nothing is worse.
  const [startingTemplate] = selectPocFallbacks(findings, 1);
  const foundryTestCode = startingTemplate
    ? startingTemplate.source
    : `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

// Fallback PoC for ${contractName} (used when the AI review is unavailable).
// Fork-ready: the Termux backend runs it with --match-contract PoC against a
// live-net fork, with POC_TARGET / POC_RPC_URL / POC_FORK_BLOCK in env.
// This is a sanity check (target has code), NOT an exploit reproduction —
// replace with the AI-generated exploit test for a real attack PoC.
contract PoC is Test {
    address public target;

    function setUp() public {
        string memory rpc = vm.envString("POC_RPC_URL");
        uint256 forkBlock = vm.envUint("POC_FORK_BLOCK");
        if (forkBlock > 0) vm.createSelectFork(rpc, forkBlock);
        else vm.createSelectFork(rpc);
        target = vm.envAddress("POC_TARGET");
    }

    function test_targetHasCode() public view {
        assertGt(target.code.length, 0, "target has no code at this fork");
    }

    // Primary finding (unverified — needs the AI-generated exploit test): ${topIssue}
}
`;

  return {
    threatModelReport: `### AI Review Unavailable for ${contractName}

Static analysis reported ${findings.length} finding(s), including ${critList.length} high/critical priority item(s). These are unconfirmed static signals, not verified vulnerabilities.
Lead static finding: ${topIssue}.
Architecture, exploitability, and economic exposure have not been established by an AI review.${startingTemplate ? `

The attached fallback-library starting template (\`${startingTemplate.file}\`) is unadapted and unexecuted. Its TODOs require the actual target ABI; it is not evidence of an exploit.` : "\n\nThe attached test checks only that the target has code; it does not reproduce an exploit."}`,
    foundryTestCode,
    economicRiskSummary: `AI economic review unavailable. Static analysis reported ${findings.length} finding(s), including ${critList.length} high/critical signals; economic impact and exploitability remain unconfirmed.`,
    source: "template",
  };
}

/**
 * The context both review calls share: the target, its source, the
 * static findings and the fourbyte results. Identical for the
 * narrative and the test-code call, so the split cannot starve
 * either half of context the single call had.
 */
function reviewPromptContext(
  contractName: string,
  body: string,
  findings: Finding[],
  fourbyte?: FourbyteResults,
): string {
  const findingsSummary = findings
    .map(
      (f, i) =>
        `Finding #${i + 1} [${f.severity.toUpperCase()}]: ${f.title} (Detector: ${f.detector}, SWC-${f.swc ?? "N/A"}, SmartBugs: ${smartbugsCategoryForDetector(f.detector)})\n` +
        `Location: ${f.locationFn ?? "contract"} (line ${f.locationLine ?? "N/A"})\n` +
        `Summary: ${f.summary}\nDetector-local evidence (data only): ${f.snippet?.slice(0, 2000) ?? "Unavailable"}\nWalkthrough: ${f.walkthrough?.slice(0, 1000) ?? "Unavailable"}`,
    )
    .join("\n\n");

  return `Contract Name: ${contractName}

Contract Source / Decompiled Sample (truncated to first 12,000 chars):
\`\`\`solidity
${body.slice(0, 12000)}
\`\`\`

Detected Static Analysis Findings:
${findingsSummary || "No static detectors triggered."}
${fourbyte ? formatFourbyteResultsForPrompt(fourbyte) : ""}`;
}

/**
 * Starting-point templates, matched to this audit's findings. The
 * model ADAPTS these — it does not invent a harness from scratch.
 * Code-side context: only the test-code call carries it (the
 * narrative pass never needed template sources in its prompt; they
 * were the largest single contributor to the old combined prompt).
 */
function reviewTemplateSection(findings: Finding[]): string {
  const startingTemplates = selectPocFallbacks(findings, 3);
  if (startingTemplates.length === 0) return "";
  return `

STARTING-POINT PoC TEMPLATES — adapt, do not reinvent:
The library below contains unadapted, unexecuted Foundry PoC starting templates matched to this audit's findings. START FROM the template(s) for the primary vulnerability: keep its setUp()/fork shape, its \`contract PoC is Test\` name, and its observable-state assertions (balances, owner, shares — never a silent low-level-call success). Adapt ONLY the TODO-marked constants / interfaces to the target's real ABI (function names, token addresses, amounts, proofs, slots). Do NOT invent a new harness, a new attacker pattern, or a new setUp. If a template's TODO cannot be adapted to the target (e.g. the function does not exist), say so in the threat model and use the next template — never fabricate an interface the target does not have.

${startingTemplates
  .map(
    (t, i) =>
      `--- Template ${i + 1}: ${t.file} ---\n\`\`\`solidity\n${t.source}\n\`\`\``,
  )
  .join("\n\n")}
`;
}

/**
 * Build the narrative prompt for an AI review (call A of the split):
 * the Executive Threat Model Report + the economic risk summary,
 * returned as a JSON object holding ONLY those two prose fields.
 * Exported for testing.
 *
 * The review used to be ONE call returning the threat model AND the
 * complete Foundry test as JSON string values in a single object.
 * That shape is what died in Jer's live run (2026-10-25): the prose
 * report — JSON-escaped markdown, the most expensive encoding of it —
 * ate the shared budget and the reply truncated at max_tokens with
 * the test code unborn (`{{"threatModelReport": "# Executive Threat
 * Model Report: xApesMarket…`, finish_reason "length"). Two calls,
 * each with one artifact and its own budget, is the fix; the return
 * shape of generateAiSecurityReview is unchanged.
 */
export function buildAiReviewPrompt(
  contractName: string,
  body: string,
  findings: Finding[],
  fourbyte?: FourbyteResults,
  inventory?: Partial<Inventory>,
  resnet?: ResnetResult | null,
): { system: string; user: string } {
  const userPrompt = `${reviewPromptContext(contractName, body, findings, fourbyte)}
${auditEvidence(inventory, resnet)}
Your tasks:
1. Provide a rigorous, concise Executive Threat Model Report grounded in the supplied evidence and finding-specific risks. Do not invent a vault, oracle, or economic exposure absent evidence.
2. Provide a 2-sentence economic risk summary.

Format your response strictly as JSON with this schema:
{
  "threatModelReport": "Markdown string containing the threat model",
  "economicRiskSummary": "Brief 2-sentence summary of the main economic/game-theoretic exposure"
}`;

  return {
    system:
      "You are a Principal EVM Security Auditor and White-Hat Exploit Researcher. Analyze the smart contract code / bytecode and detected vulnerabilities. Respond strictly as JSON matching the requested schema.",
    user: userPrompt,
  };
}

/**
 * Build the test-code prompt for an AI review (call B of the split):
 * the complete Foundry test, returned as a raw fenced code block —
 * NO JSON wrapping (JSON-escaping a whole Solidity file was pure
 * budget waste and a shape-failure magnet). The prompt carries the
 * same context as the narrative call, plus the starting-point
 * templates and — when the narrative pass produced one — the threat
 * model itself, so the test is aimed by the same analysis the single
 * combined call would have used. Exported for testing — the prompt
 * must carry the matching fallback-library template(s) as the
 * starting point for the generated PoC.
 */
export function buildAiReviewTestPrompt(
  contractName: string,
  body: string,
  findings: Finding[],
  fourbyte?: FourbyteResults,
  inventory?: Partial<Inventory>,
  resnet?: ResnetResult | null,
  threatModelReport?: string,
): { system: string; user: string } {
  const narrativeSection = threatModelReport?.trim()
    ? `

THREAT MODEL (produced by the narrative pass over this same evidence — aim the test at the primary finding it identifies):
${threatModelReport}`
    : "";

  const userPrompt = `${reviewPromptContext(contractName, body, findings, fourbyte)}
${reviewTemplateSection(findings)}
${auditEvidence(inventory, resnet)}${narrativeSection}
Your task:
Generate a complete, compilation-ready Foundry test suite contract in Solidity (\`test/Exploit.t.sol\`) that evaluates the primary finding without presuming it is confirmed. START FROM the starting-point template(s) above: keep the template's setUp()/fork shape, its \`contract PoC is Test\` name, and its observable-state assertions, adapting ONLY the TODO-marked constants / interfaces to the target's real ABI. The test MUST:
   - declare \`contract PoC is Test\` and \`import "forge-std/Test.sol";\`
   - in setUp(): fork live chain state with \`vm.createSelectFork(vm.envString("POC_RPC_URL"))\` (pin a block with \`vm.envUint("POC_FORK_BLOCK")\` when it is nonzero) and attach to the live target via \`vm.envAddress("POC_TARGET")\` — never hardcode a target address
   - choose a finding-specific observable invariant (authorization, owner, accounting, availability, or value movement as appropriate); fund an attacker only when required. Never treat a bare low-level-call success as proof
   - use only signatures supported by the actual ABI or supplied source. Selector databases and heuristic ABI entries are hypotheses, not verified call surfaces. Do not guess destructive selectors or invent interfaces; describe missing evidence and leave the finding unconfirmed when the required surface is unavailable
   - the finding is unconfirmed until execution demonstrates the predicted invariant violation; report confirmed, refuted, or inconclusive based on execution evidence, and never describe an unexecuted template as proven
   - a failed assertion alone does not refute a finding: distinguish missing prerequisites, compile or infrastructure failures, inconclusive execution, and actual counterevidence. Report what the observed execution supports.

Format your response as ONLY the complete Solidity test file inside exactly one \`\`\`solidity fenced code block — no JSON, no prose before or after the block.`;

  return {
    system:
      "You are a Principal EVM Security Auditor and White-Hat Exploit Researcher. Analyze the smart contract code / bytecode and detected vulnerabilities. Reply with only the requested Foundry test file in a single fenced code block.",
    user: userPrompt,
  };
}

/**
 * Output-token budgets for the review's two calls (the values
 * makeBody sends). History: the single combined call ran at 6000,
 * then 8000 — and 8000 still truncated (Jer's live run, 2026-10-25:
 * the threat-model prose, JSON-escaped, ate the budget and the
 * reply died at finish_reason "length" with the test code unborn).
 * One artifact per call is the structural fix; the budgets are then
 * sized to the artifact:
 *
 *   narrative — prose only. Observed threat-model reports run
 *     ~1–2.5k tokens; 4000 leaves ~1.6x headroom over the top of
 *     that range while staying tight enough that a rambling reply
 *     still finishes as an object instead of a cut string.
 *   test code — a complete template-adapted Foundry test file,
 *     observed at ~3–7k tokens. 16000 is 2x the old SHARED budget
 *     now spent on code alone, and half the code model's catalog
 *     max completion (32,768 for poolside/laguna-s-2.1:free), so
 *     the provider ceiling is never the binding constraint.
 *
 * max_tokens is a cap, not a target — a reply that completes
 * naturally is unaffected by either value.
 */
export const NARRATIVE_MAX_TOKENS = 4000;
export const CODE_MAX_TOKENS = 16000;

/**
 * Fields the NARRATIVE reply MUST carry (truthy) to be usable —
 * the schema the narrative prompt demands. `economicRiskSummary`
 * is the only other field; it is optional with a standing default.
 * (The combined call's required set was threatModelReport +
 * foundryTestCode; foundryTestCode is now call B's artifact.)
 */
export const NARRATIVE_REQUIRED_FIELDS = ["threatModelReport"] as const;

/**
 * A narrative reply that ARRIVED but is not a usable review object:
 * no JSON object could be extracted from it, or the extracted object
 * is missing the required field. Carries everything the corrective
 * retry and the fallback log line need — which required fields were
 * missing, which top-level keys the reply DID contain, whether the
 * provider cut the reply at the token budget, and which budget.
 *
 * This failure class is distinct from a timeout or an HTTP error:
 * the call succeeded and the model answered, just not in the schema.
 * In Jer's 59,852-address worker run (2026-10-25) it fell straight
 * through to the template with a bare "missing threatModelReport /
 * foundryTestCode" and no trace of what the reply actually held.
 */
export class ReviewReplyError extends Error {
  readonly missingFields: readonly string[];
  readonly receivedKeys: readonly string[];
  /** "threatModelReport=object, economicRiskSummary=string" — the types the
   *  reply actually carried, so a schema miss reads as a schema miss and not
   *  as an empty answer. Optional: older call sites construct without it. */
  readonly receivedTypes?: string;
  /** finish_reason === "length": the provider cut the reply at max_tokens. */
  readonly truncated: boolean;
  /** The max_tokens budget the failed reply was produced under. */
  readonly maxTokens: number;

  constructor(args: {
    detail: string;
    missingFields: readonly string[];
    receivedKeys: readonly string[];
    receivedTypes?: string;
    truncated: boolean;
    maxTokens?: number;
  }) {
    super(args.detail);
    this.name = "ReviewReplyError";
    this.missingFields = args.missingFields;
    this.receivedKeys = args.receivedKeys;
    this.receivedTypes = args.receivedTypes;
    this.truncated = args.truncated;
    this.maxTokens = args.maxTokens ?? NARRATIVE_MAX_TOKENS;
  }

  /**
   * The corrective user message for the single retry: names the exact
   * missing fields and demands the complete JSON object with the
   * exact narrative schema keys and nothing else (the Deep Agent's
   * corrective discipline, specialised to this schema). A truncated
   * reply also gets told to be compact — a same-size resend would
   * just be cut again.
   */
  correctiveInstruction(): string {
    const exactKeys = [...NARRATIVE_REQUIRED_FIELDS, "economicRiskSummary"]
      .map((k) => `"${k}"`)
      .join(", ");
    const head =
      this.missingFields.length > 0
        ? `Your previous reply was not a complete review object: it was missing ${this.missingFields
            .map((k) => `"${k}"`)
            .join(", ")}${this.receivedKeys.length > 0 ? ` (it contained only: ${this.receivedKeys.join(", ")})` : ""}.`
        : "Your previous reply could not be parsed as a JSON review object.";
    const compact = this.truncated
      ? ` Your previous reply was cut off at the token limit (finish_reason "length", max_tokens ${this.maxTokens}): keep the threat model concise so the entire JSON object fits in one reply.`
      : "";
    return `${head} Reply with ONLY the complete JSON object with exactly these keys: ${exactKeys} — no prose, no code fences, no explanation before or after it.${compact}`;
  }
}

/**
 * A test-code reply that ARRIVED but yields no usable Foundry test:
 * no fenced block (and no raw code), or the extracted code declares
 * no Test contract / carries no executable test function. The
 * code-call sibling of ReviewReplyError — same discipline (one
 * corrective retry, diagnosis in the fallback line), different
 * artifact: the corrective demands exactly one fenced block, not a
 * JSON object.
 */
export class ReviewCodeError extends Error {
  /** What was wrong with the extracted code, in order found. */
  readonly problems: readonly string[];
  /** finish_reason === "length": the provider cut the reply at max_tokens. */
  readonly truncated: boolean;

  constructor(args: { detail: string; problems: readonly string[]; truncated: boolean }) {
    super(args.detail);
    this.name = "ReviewCodeError";
    this.problems = args.problems;
    this.truncated = args.truncated;
  }

  correctiveInstruction(): string {
    const compact = this.truncated
      ? ` Your previous reply was cut off at the token limit (finish_reason "length", max_tokens ${CODE_MAX_TOKENS}): write a complete but more compact test so the whole file fits in one reply.`
      : "";
    return (
      `Your previous reply did not yield a usable Foundry test (${this.problems.join("; ")}). ` +
      "Reply with ONLY the complete Solidity test file inside exactly one ```solidity fenced code block — no JSON, no prose before or after the block. " +
      `The file must declare \`contract PoC is Test\` and contain at least one executable test function.${compact}`
    );
  }
}

/** The truncation marker appended to a reply-shape diagnosis. */
function truncationNote(truncated: boolean, maxTokens: number): string {
  return truncated
    ? `; reply truncated at max_tokens ${maxTokens} (finish_reason "length")`
    : "";
}

/**
 * Output bounds. The model's prose is stored, rendered, and — worse —
 * interpolated into the NEXT call's prompt (buildAiReviewPrompt takes
 * threatModelReport as context for the code call). Unbounded model output is
 * therefore unbounded prompt growth, which is the exact failure the split into
 * two calls was built to fix (2026-10-25: the combined reply truncated at
 * max_tokens with the test code unborn). Prose is truncated with a visible
 * marker; CODE is never truncated, because half a Solidity file is not a
 * smaller Solidity file — it is a file that will not compile.
 */
export const NARRATIVE_MAX_CHARS = 24_000;
export const ECONOMIC_MAX_CHARS = 4_000;
export const TEST_CODE_MAX_CHARS = 40_000;

/** The sentence shown when the model supplied no economic summary, so the
 *  field never claims a review that did not happen. */
export const ECONOMIC_SUMMARY_ABSENT =
  "The model did not provide an economic risk summary for this contract.";

/** A human-readable description of what a JSON value actually is, for the
 *  diagnosis line. "object" alone does not tell a reviewer whether the model
 *  nested the report or returned a list of paragraphs. */
export function modelValueKind(value: unknown): string {
  if (value === undefined) return "missing";
  if (value === null) return "null";
  if (Array.isArray(value)) {
    const kinds = [...new Set(value.map((v) => typeof v))];
    return `array of ${kinds.join("/") || "nothing"} (length ${value.length})`;
  }
  return typeof value;
}

/**
 * Coerce a model-supplied prose field to text, or null when it holds no text.
 *
 * The `as string` cast this replaces was a lie the compiler could not catch:
 * a reply of `{"threatModelReport": {"executive": "..."}}` passed the truthiness
 * gate, stayed an OBJECT, and then became `[object Object]` in the stored
 * narrative, in the UI, and in the next call's prompt. Models return objects
 * and arrays for prose often enough that the honest options are "recover the
 * text" or "reject with a diagnosis" — never "cast and hope".
 *
 *   string        → trimmed as-is
 *   array         → its string/number items joined with newlines (a model
 *                   returning a list of paragraphs means them in order)
 *   object        → its JSON text, so the content survives even when the shape
 *                   is wrong
 *   number/bool   → null (not prose; a corrective retry is the right answer)
 *   null/missing  → null
 *
 * Over-length text is cut at `maxChars` with an explicit marker appended, so a
 * truncated narrative says so rather than silently ending mid-sentence.
 */
export function coerceModelText(value: unknown, maxChars: number): string | null {
  let text: string | null = null;
  if (typeof value === "string") {
    text = value.trim();
  } else if (Array.isArray(value)) {
    const parts = value
      .filter((v) => typeof v === "string" || typeof v === "number")
      .map((v) => String(v).trim())
      .filter(Boolean);
    text = parts.length > 0 ? parts.join("\n") : null;
  } else if (typeof value === "object" && value !== null) {
    try {
      text = JSON.stringify(value);
    } catch {
      text = null;
    }
  }
  if (!text) return null;
  if (text.length > maxChars) {
    return `${text.slice(0, maxChars)}\n\n[... truncated at ${maxChars} characters by the analyzer: the model returned ${text.length} characters ...]`;
  }
  return text;
}

/**
 * Parse + validate one NARRATIVE reply (call A). Validation
 * strictness matches the original combined check for the fields
 * this call owns (threatModelReport truthy; economicRiskSummary
 * defaulted) — a failure throws a ReviewReplyError carrying the
 * diagnosis instead of a bare assertion, so the caller can spend
 * its one corrective retry and the fallback line can name the
 * received keys.
 *
 * `finishReason` is the choice's finish_reason from the SAME
 * response body the content came from (postChatWithModelFallback
 * returns the raw Response, so it was always reachable — it was
 * simply never read). "length" is the truncation signal: only
 * finish_reason separates "model chose a wrong schema" from
 * "model ran out of tokens".
 */
export function parseNarrativeReply(
  content: string,
  finishReason: string | undefined,
): { threatModelReport: string; economicRiskSummary: string } {
  const truncated = finishReason === "length";
  let parsed: unknown;
  try {
    parsed = extractJsonContent(content);
  } catch (err) {
    throw new ReviewReplyError({
      detail:
        `OpenRouter reply did not yield a JSON object: ${err instanceof Error ? err.message : String(err)}` +
        truncationNote(truncated, NARRATIVE_MAX_TOKENS),
      missingFields: [...NARRATIVE_REQUIRED_FIELDS],
      receivedKeys: [],
      truncated,
    });
  }
  const record =
    typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  const receivedKeys = record ? Object.keys(record) : [];
  const receivedTypes = record
    ? receivedKeys.map((k) => `${k}=${modelValueKind(record[k])}`).join(", ")
    : "";
  // A field is present only when it COERCES to text. Truthiness was the old
  // gate, and an object is truthy — which is how `[object Object]` reached the
  // stored narrative and the next prompt.
  const narrative = record ? coerceModelText(record.threatModelReport, NARRATIVE_MAX_CHARS) : null;
  const missing = narrative ? [] : [...NARRATIVE_REQUIRED_FIELDS];
  if (!record || !narrative) {
    const shape = record
      ? `reply keys: ${receivedKeys.join(", ") || "none"}${receivedTypes ? `; types: ${receivedTypes}` : ""}`
      : `reply was a JSON ${Array.isArray(parsed) ? "array" : typeof parsed}, not an object`;
    throw new ReviewReplyError({
      detail:
        `OpenRouter reply was missing ${missing.join(", ")} (${shape})` +
        truncationNote(truncated, NARRATIVE_MAX_TOKENS),
      missingFields: missing.length > 0 ? missing : [...NARRATIVE_REQUIRED_FIELDS],
      receivedKeys,
      receivedTypes,
      truncated,
    });
  }
  const economic = record ? coerceModelText(record.economicRiskSummary, ECONOMIC_MAX_CHARS) : null;
  return {
    threatModelReport: narrative,
    economicRiskSummary: economic ?? ECONOMIC_SUMMARY_ABSENT,
  };
}

/**
 * Extract the Foundry test source from a test-code reply — the
 * SmartPoC extractCodeBlock lineage (smartpoc/engine.server.ts):
 * when the reply carries several fenced blocks, prefer the first
 * block containing executable test functions (models routinely
 * emit a helper or attack contract first and the Test contract
 * second); a single block wins as-is; with no fences at all, the
 * trimmed text. Re-implemented here on the same primitives
 * (stripThinkBlocks + countExecutableTestFunctions) rather than
 * imported: the SmartPoC engine imports THIS module, so the import
 * would cycle.
 */
export function extractReviewTestCode(text: string): string {
  const cleaned = stripThinkBlocks(text);
  const blocks = [...cleaned.matchAll(/```(?:solidity|sol)?\s*\n([\s\S]*?)```/gi)].map((m) =>
    m[1].trim(),
  );
  if (blocks.length) {
    return blocks.find((b) => countExecutableTestFunctions(b) > 0) ?? blocks[0]!;
  }
  return cleaned.trim();
}

/**
 * Parse + validate one TEST-CODE reply (call B): the extraction
 * above, plus the shape gate — the code must declare a Test
 * contract and carry at least one executable test function (the
 * same "would forge actually run a test" bar the adjudicate
 * chain's gate applies downstream; catching a helper-only or
 * prose reply HERE is what lets the corrective retry ask for the
 * right thing). Failures throw ReviewCodeError with the problems
 * named; truncation rides on finish_reason as in the narrative
 * parser.
 */
export function parseTestCodeReply(content: string, finishReason: string | undefined): string {
  const truncated = finishReason === "length";
  const code = extractReviewTestCode(content);
  const problems: string[] = [];
  if (!code) {
    problems.push("the reply contained no code");
  } else {
    // Code is REJECTED over the bound, never truncated: half a Solidity file
    // does not compile, and a compile failure spends a backend run to learn
    // something the reply length already said.
    if (code.length > TEST_CODE_MAX_CHARS) {
      problems.push(
        `the extracted code is ${code.length} characters, over the ${TEST_CODE_MAX_CHARS}-character limit`,
      );
    }
    if (!/contract\s+\w+\s+is\s+Test\b/.test(code)) {
      problems.push("the extracted code declares no Test contract");
    }
    if (countExecutableTestFunctions(code) === 0) {
      problems.push("the extracted code contains no executable test function");
    }
    // A file with no pragma is not a file forge will compile, and every
    // harness in this repo carries one. Catching it here turns a wasted
    // backend run into a corrective retry.
    if (!/^\s*(?:\/\/[^\n]*\n\s*)*pragma\s+solidity\b/m.test(code)) {
      problems.push("the extracted code has no pragma solidity directive");
    }
  }
  if (problems.length > 0) {
    throw new ReviewCodeError({
      detail:
        `OpenRouter test-code reply was unusable: ${problems.join("; ")}` +
        truncationNote(truncated, CODE_MAX_TOKENS),
      problems,
      truncated,
    });
  }
  return code;
}

export async function generateAiSecurityReview(
  contractName: string,
  body: string,
  findings: Finding[],
  fourbyte?: FourbyteResults,
  inventory?: Partial<Inventory>,
  resnet?: ResnetResult | null,
): Promise<AiSecurityReview> {
  // The split (2026-10-25): call A (narrative) runs on the "review"
  // purpose, call B (test code) on the "code" purpose; the model for
  // each is chosen (and fallen back through) inside
  // postChatWithModelFallback. The API key is purpose-independent.
  const reviewConfig = resolveOpenRouterConfig(process.env, "review");
  const codeConfig = resolveOpenRouterConfig(process.env, "code");
  const timeoutMs = resolveOpenRouterTimeoutMs(process.env);

  if (!reviewConfig.apiKey) {
    return buildFallbackReview(contractName, findings, body);
  }
  const apiKey = reviewConfig.apiKey;

  // Retry state for the fallback line: which call died, and which
  // one-shot retries were spent along the way.
  let failedCall: "narrative" | "test code" = "narrative";
  let failedModel = reviewConfig.model;
  let timeoutRetried = false;
  let emptyRetried = false;
  let shapeRetried = false;
  try {
    const referer =
      process.env.APP_URL?.trim() ||
      process.env.VERCEL_URL?.trim() ||
      "https://smart-kontrakt.vercel.app";

    type CallSpec = {
      kind: "narrative" | "test code";
      purpose: OpenRouterPurpose;
      /** The purpose's preferred model — for log lines; the wire
       *  model is chosen per attempt by the fallback chain. */
      model: string;
      system: string;
      user: string;
      corrective?: string;
      jsonMode: boolean;
      maxTokens: number;
    };

    // One attempt. withRetry still absorbs the transient HTTP/network
    // failures (429 / 5xx / connection errors, 3 retries as before),
    // but it must NOT retry a timeout: a timed-out attempt restarts
    // the generation from zero, so the old default predicate burned
    // 4 x 60s on the same slow prompt and fell back anyway — the
    // exact failure in Jer's 2026-10-25 worker run (template reviews
    // for entry after entry, downstream no_tests verdicts). The Deep
    // Agent's calls learned this first ("do not retry timeouts");
    // here the discipline is: fail the attempt fast on timeout, and
    // let the single counted retry in fetchReply handle it.
    // `corrective` appends the reply-shape instruction used by a
    // call's corrective retry (same shape as the Deep Agent's call).
    const callChat = (spec: CallSpec): Promise<Response> =>
      withRetry(
        async () => {
          await openRouterLimiter.acquire();
          return postChatWithModelFallback({
            purpose: spec.purpose,
            apiKey,
            timeoutMs,
            headers: {
              Authorization: `Bearer ${apiKey}`,
              "Content-Type": "application/json",
              "HTTP-Referer": referer,
              "X-Title": "SmartKontrakt / Kiln",
            },
            makeBody: (candidate) => ({
              model: candidate,
              messages: [
                { role: "system", content: spec.system },
                { role: "user", content: spec.user },
                ...(spec.corrective
                  ? [{ role: "user" as const, content: spec.corrective }]
                  : []),
              ],
              // Call B asks for raw code — a JSON envelope around a
              // whole Solidity file is pure budget waste.
              ...(spec.jsonMode ? { response_format: { type: "json_object" } } : {}),
              temperature: 0.7,
              max_tokens: spec.maxTokens,
            }),
          });
        },
        {
          retries: 3,
          baseDelayMs: 2000,
          retryOn: (err) => !isOpenRouterTimeoutError(err) && isTransientError(err),
        },
      );

    // One logical call: the HTTP call plus the response read, with
    // the one-shot transport retries — ONE on a timeout (the
    // discipline above) and ONE on an empty completion. The empty
    // case is new with the split batch: the provider can answer 200
    // with no message content at all (Jer's 2026-10-25 log: "Error:
    // OpenRouter returned no message content" → straight to the
    // template). Nothing was generated, so a fresh attempt is the
    // cheapest correct response. Each retry class spends at most
    // once per logical call; the corrective retry is a NEW logical
    // call with its own pair. Returns the message content AND the
    // choice's finish_reason — "length" is the only truncation
    // signal the provider gives; the parsers need it to tell a cut
    // reply apart from a wrong-shape one.
    const fetchReply = async (
      spec: CallSpec,
    ): Promise<{ content: string; finishReason?: string }> => {
      let spentTimeoutRetry = false;
      let spentEmptyRetry = false;
      for (;;) {
        let response: Response;
        try {
          response = await callChat(spec);
        } catch (err) {
          if (isOpenRouterTimeoutError(err) && !spentTimeoutRetry) {
            // A slow free-lane queue can clear between attempts; a
            // second timeout means the lane is not answering at this
            // budget today, and the template fallback is the honest
            // outcome.
            spentTimeoutRetry = true;
            timeoutRetried = true;
            console.warn(
              `[Kiln] OpenRouter AI review ${spec.kind} call timed out (model ${spec.model}, timeout ${timeoutMs}ms) — retrying once`,
            );
            continue;
          }
          throw err;
        }

        if (!response.ok) {
          const detail = (await response.text().catch(() => "")).slice(0, 500);
          throw new Error(`OpenRouter returned HTTP ${response.status}: ${detail}`);
        }

        const data = (await response.json()) as {
          choices?: Array<{
            message?: { content?: string | null };
            finish_reason?: string | null;
          }>;
        };
        const content = data.choices?.[0]?.message?.content;
        if (!content) {
          if (!spentEmptyRetry) {
            spentEmptyRetry = true;
            emptyRetried = true;
            console.warn(
              `[Kiln] OpenRouter AI review ${spec.kind} call returned no message content (model ${spec.model}) — retrying once`,
            );
            continue;
          }
          throw new Error("OpenRouter returned no message content");
        }
        return { content, finishReason: data.choices?.[0]?.finish_reason ?? undefined };
      }
    };

    // — Call A: the narrative (threat model + economic summary). A
    // reply that arrived but is not a usable object gets ONE
    // corrective retry naming the exact missing fields; a second
    // shape failure falls back with the received keys in the error.
    const narrativePrompt = buildAiReviewPrompt(contractName, body, findings, fourbyte, inventory, resnet);
    const narrativeSpec: CallSpec = {
      kind: "narrative",
      purpose: "review",
      model: reviewConfig.model,
      system: narrativePrompt.system,
      user: narrativePrompt.user,
      jsonMode: true,
      maxTokens: NARRATIVE_MAX_TOKENS,
    };
    let narrative: { threatModelReport: string; economicRiskSummary: string };
    try {
      const first = await fetchReply(narrativeSpec);
      narrative = parseNarrativeReply(first.content, first.finishReason);
    } catch (err) {
      if (!(err instanceof ReviewReplyError)) throw err;
      shapeRetried = true;
      console.warn(
        `[Kiln] OpenRouter AI review narrative reply unusable (model ${reviewConfig.model}): ${err.message} — retrying once with a corrective instruction`,
      );
      const second = await fetchReply({ ...narrativeSpec, corrective: err.correctiveInstruction() });
      narrative = parseNarrativeReply(second.content, second.finishReason);
    }

    // — Call B: the Foundry test, aimed by call A's threat model
    // (the single combined call generated the test conditioned on
    // its own analysis in the same completion; the split preserves
    // that dependency explicitly). Runs only after A succeeded —
    // its retries never re-call A. A reply with no usable test
    // gets ONE corrective retry demanding exactly one fenced block.
    failedCall = "test code";
    failedModel = codeConfig.model;
    const testPrompt = buildAiReviewTestPrompt(
      contractName,
      body,
      findings,
      fourbyte,
      inventory,
      resnet,
      narrative.threatModelReport,
    );
    const testSpec: CallSpec = {
      kind: "test code",
      purpose: "code",
      model: codeConfig.model,
      system: testPrompt.system,
      user: testPrompt.user,
      jsonMode: false,
      maxTokens: CODE_MAX_TOKENS,
    };
    let foundryTestCode: string;
    try {
      const first = await fetchReply(testSpec);
      foundryTestCode = parseTestCodeReply(first.content, first.finishReason);
    } catch (err) {
      if (!(err instanceof ReviewCodeError)) throw err;
      shapeRetried = true;
      console.warn(
        `[Kiln] OpenRouter AI review test-code reply unusable (model ${codeConfig.model}): ${err.message} — retrying once with a corrective instruction`,
      );
      const second = await fetchReply({ ...testSpec, corrective: err.correctiveInstruction() });
      foundryTestCode = parseTestCodeReply(second.content, second.finishReason);
    }

    return {
      threatModelReport: narrative.threatModelReport,
      foundryTestCode,
      economicRiskSummary: narrative.economicRiskSummary,
      source: "openrouter",
    };
  } catch (err) {
    // The fallback line must carry the whole diagnosis — WHICH call
    // died, its model, the timeout budget in force, and which
    // one-shot retries were spent. The bare "aborted due to timeout"
    // this replaced cost a screenshot round-trip to explain
    // (2026-10-25).
    console.warn(
      `[Kiln] OpenRouter AI review failed, falling back to structured template ` +
        `(failed call: ${failedCall}, model ${failedModel}, timeout ${timeoutMs}ms${timeoutRetried ? ", timeout retry attempted and exhausted" : ""}${emptyRetried ? ", empty-reply retry attempted and exhausted" : ""}${shapeRetried ? ", corrective retry attempted and exhausted" : ""}): ` +
        `${err instanceof Error ? `${err.name}: ${err.message}` : String(err)}`,
    );
  }

  return buildFallbackReview(contractName, findings, body);
}
