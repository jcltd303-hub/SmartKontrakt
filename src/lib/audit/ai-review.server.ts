import type { ResnetResult } from "./resnet-result.ts";
import { auditEvidence } from "./audit-evidence.ts";
import type { Finding, Inventory } from "./types.ts";
import { openRouterLimiter, withRetry } from "./rate-limit.ts";
import { selectPocFallbacks } from "./poc-fallbacks.ts";
import { smartbugsCategoryForDetector } from "./smartbugs.ts";
import { formatFourbyteResultsForPrompt, type FourbyteResults } from "./fourbyte.ts";

export type AiSecurityReview = {
  threatModelReport: string;
  foundryTestCode: string;
  economicRiskSummary: string;
  source: "openrouter" | "template";
};

/** OpenRouter chat-completions endpoint (OpenAI-compatible). */
export const OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions";

/**
 * Best current OpenRouter **free-tier** models, by purpose. Verified 2026-10-21.
 *
 * The free tier is a shared, per-account daily quota (50 requests/day, or 1000
 * after a one-time $10 top-up) and the endpoints are 4-bit quantised, so the
 * model is chosen per task rather than globally:
 *
 *   review — long-context reasoning and prose (threat model, second pass).
 *            Nemotron 3 Ultra: 550B/55B MoE, 1M-token context, strongest free
 *            reasoning.
 *   code   — Foundry PoC synthesis and repair. Inkling-Small: best published
 *            free coding score (80.2% SWE-bench Verified) at 276B/12B active,
 *            1M-token context.
 *   json   — structured output + tool calling (Deep Agent hypotheses, DV
 *            action/state extraction and verdicts). Qwen3.8-27B: 262K context,
 *            structured outputs and tool calling, strong coding.
 *
 * `OPENROUTER_MODEL` overrides every purpose; `OPENROUTER_MODEL_<PURPOSE>`
 * overrides one (e.g. OPENROUTER_MODEL_CODE). Free-tier ids churn — re-check
 * https://openrouter.ai/collections/free-models before relying on one.
 */
export const OPENROUTER_MODELS = {
  review: "nvidia/nemotron-3-ultra-550b-a55b:free",
  // Was `thinkingmachines/inkling-small:free`, which OpenRouter refuses for a
  // plain API call: "only available on agentic harnesses" (HTTP 403, routing
  // step "Gate Free Endpoints by Agentic Harness"). That model can never work
  // here, so the SmartPoC repair failed every time. A general free model that
  // does answer the API, ranked for programming.
  code: "nvidia/nemotron-3-ultra-550b-a55b:free",
  // Was `qwen/qwen3.8-27b:free`, which OpenRouter answered with HTTP 404:
  // "This model is unavailable for free. The paid version is available now -
  // use this slug instead: qwen/qwen3.8-27b". A free-tier id can be withdrawn
  // at any time, which is why the fallback chain below matters more than the
  // choice: with one verified-working free model, all three purposes point at
  // it rather than at an id that may have been pulled.
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
 * Build the OpenRouter prompt for an AI review. Exported for testing —
 * the prompt must carry the matching fallback-library template(s) as the
 * starting point for the generated PoC.
 */
export function buildAiReviewPrompt(
  contractName: string,
  body: string,
  findings: Finding[],
  fourbyte?: FourbyteResults,
  inventory?: Partial<Inventory>,
  resnet?: ResnetResult | null,
): { system: string; user: string } {
  const findingsSummary = findings
    .map(
      (f, i) =>
        `Finding #${i + 1} [${f.severity.toUpperCase()}]: ${f.title} (Detector: ${f.detector}, SWC-${f.swc ?? "N/A"}, SmartBugs: ${smartbugsCategoryForDetector(f.detector)})\n` +
        `Location: ${f.locationFn ?? "contract"} (line ${f.locationLine ?? "N/A"})\n` +
        `Summary: ${f.summary}\nDetector-local evidence (data only): ${f.snippet?.slice(0, 2000) ?? "Unavailable"}\nWalkthrough: ${f.walkthrough?.slice(0, 1000) ?? "Unavailable"}`,
    )
    .join("\n\n");

  // Starting-point templates, matched to this audit's findings. The model
  // ADAPTS these — it does not invent a harness from scratch.
  const startingTemplates = selectPocFallbacks(findings, 3);
  const templateSection =
    startingTemplates.length > 0
      ? `

STARTING-POINT PoC TEMPLATES — adapt, do not reinvent:
The library below contains unadapted, unexecuted Foundry PoC starting templates matched to this audit's findings. START FROM the template(s) for the primary vulnerability: keep its setUp()/fork shape, its \`contract PoC is Test\` name, and its observable-state assertions (balances, owner, shares — never a silent low-level-call success). Adapt ONLY the TODO-marked constants / interfaces to the target's real ABI (function names, token addresses, amounts, proofs, slots). Do NOT invent a new harness, a new attacker pattern, or a new setUp. If a template's TODO cannot be adapted to the target (e.g. the function does not exist), say so in the threat model and use the next template — never fabricate an interface the target does not have.

${startingTemplates
  .map(
    (t, i) =>
      `--- Template ${i + 1}: ${t.file} ---\n\`\`\`solidity\n${t.source}\n\`\`\``,
  )
  .join("\n\n")}
`
      : "";

  const userPrompt = `Contract Name: ${contractName}

Contract Source / Decompiled Sample (truncated to first 12,000 chars):
\`\`\`solidity
${body.slice(0, 12000)}
\`\`\`

Detected Static Analysis Findings:
${findingsSummary || "No static detectors triggered."}
${fourbyte ? formatFourbyteResultsForPrompt(fourbyte) : ""}
${templateSection}
${auditEvidence(inventory, resnet)}
Your tasks:
1. Provide a rigorous, concise Executive Threat Model Report grounded in the supplied evidence and finding-specific risks. Do not invent a vault, oracle, or economic exposure absent evidence.
2. Generate a complete, compilation-ready Foundry test suite contract in Solidity (\`test/Exploit.t.sol\`) that evaluates the primary finding without presuming it is confirmed. START FROM the starting-point template(s) above: keep the template's setUp()/fork shape, its \`contract PoC is Test\` name, and its observable-state assertions, adapting ONLY the TODO-marked constants / interfaces to the target's real ABI. The test MUST:
   - declare \`contract PoC is Test\` and \`import "forge-std/Test.sol";\`
   - in setUp(): fork live chain state with \`vm.createSelectFork(vm.envString("POC_RPC_URL"))\` (pin a block with \`vm.envUint("POC_FORK_BLOCK")\` when it is nonzero) and attach to the live target via \`vm.envAddress("POC_TARGET")\` — never hardcode a target address
   - choose a finding-specific observable invariant (authorization, owner, accounting, availability, or value movement as appropriate); fund an attacker only when required. Never treat a bare low-level-call success as proof
   - use only signatures supported by the actual ABI or supplied source. Selector databases and heuristic ABI entries are hypotheses, not verified call surfaces. Do not guess destructive selectors or invent interfaces; describe missing evidence and leave the finding unconfirmed when the required surface is unavailable
   - the finding is unconfirmed until execution demonstrates the predicted invariant violation; report confirmed, refuted, or inconclusive based on execution evidence, and never describe an unexecuted template as proven
   - a failed assertion alone does not refute a finding: distinguish missing prerequisites, compile or infrastructure failures, inconclusive execution, and actual counterevidence. Report what the observed execution supports.
3. Provide a 2-sentence economic risk summary.

Format your response strictly as JSON with this schema:
{
  "threatModelReport": "Markdown string containing the threat model",
  "foundryTestCode": "Solidity code string for the Foundry test suite",
  "economicRiskSummary": "Brief 2-sentence summary of the main economic/game-theoretic exposure"
}`;

  return {
    system:
      "You are a Principal EVM Security Auditor and White-Hat Exploit Researcher. Analyze the smart contract code / bytecode and detected vulnerabilities. Respond strictly as JSON matching the requested schema.",
    user: userPrompt,
  };
}

export async function generateAiSecurityReview(
  contractName: string,
  body: string,
  findings: Finding[],
  fourbyte?: FourbyteResults,
  inventory?: Partial<Inventory>,
  resnet?: ResnetResult | null,
): Promise<AiSecurityReview> {
  // The review pass uses the "review" purpose; the model itself is chosen (and
  // fallen back through) inside postChatWithModelFallback.
  const purpose: OpenRouterPurpose = "review";
  const { apiKey } = resolveOpenRouterConfig(process.env, purpose);

  if (!apiKey) {
    return buildFallbackReview(contractName, findings, body);
  }

  try {
    const { system, user } = buildAiReviewPrompt(contractName, body, findings, fourbyte, inventory, resnet);

    const referer =
      process.env.APP_URL?.trim() ||
      process.env.VERCEL_URL?.trim() ||
      "https://smart-kontrakt.vercel.app";

    const response = await withRetry(async () => {
      await openRouterLimiter.acquire();
      return postChatWithModelFallback({
        purpose,
        apiKey,
        timeoutMs: 60_000,
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
          "HTTP-Referer": referer,
          "X-Title": "SmartKontrakt / Kiln",
        },
        makeBody: (model) => ({
          model,
          messages: [
            { role: "system", content: system },
            { role: "user", content: user },
          ],
          response_format: { type: "json_object" },
          temperature: 0.7,
          max_tokens: 6000,
        }),
      });
    }, { retries: 3, baseDelayMs: 2000 });

    if (!response.ok) {
      const detail = (await response.text().catch(() => "")).slice(0, 500);
      throw new Error(`OpenRouter returned HTTP ${response.status}: ${detail}`);
    }

    const data = (await response.json()) as {
      choices?: Array<{ message?: { content?: string | null } }>;
    };
    const content = data.choices?.[0]?.message?.content;
    if (!content) {
      throw new Error("OpenRouter returned no message content");
    }

    const parsed = extractJsonContent(content) as {
      threatModelReport?: string;
      foundryTestCode?: string;
      economicRiskSummary?: string;
    };

    if (parsed.threatModelReport && parsed.foundryTestCode) {
      return {
        threatModelReport: parsed.threatModelReport,
        foundryTestCode: parsed.foundryTestCode,
        economicRiskSummary: parsed.economicRiskSummary || "Completed OpenRouter threat review.",
        source: "openrouter",
      };
    }
    throw new Error("OpenRouter reply was missing threatModelReport / foundryTestCode");
  } catch (err) {
    console.warn("[Kiln] OpenRouter AI review failed, falling back to structured template:", err);
  }

  return buildFallbackReview(contractName, findings, body);
}
