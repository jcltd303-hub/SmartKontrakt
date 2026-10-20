import type { Finding } from "./types.ts";
import { openRouterLimiter, withRetry } from "./rate-limit.ts";
import { selectPocFallbacks } from "./poc-fallbacks.ts";
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
  code: "thinkingmachines/inkling-small:free",
  json: "qwen/qwen3.8-27b:free",
} as const;

export type OpenRouterPurpose = keyof typeof OPENROUTER_MODELS;

/** Default model — matches the default purpose ("review"); overridable via env. */
export const DEFAULT_OPENROUTER_MODEL = OPENROUTER_MODELS.review;

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
 * Extract the JSON payload from a model reply. Models sometimes wrap JSON
 * in ```json fences or add prose around it — find the outermost object.
 */
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

export function extractJsonContent(content: string): unknown {
  const trimmed = stripThinkBlocks(content);
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fenced ? fenced[1].trim() : trimmed;
  try {
    return JSON.parse(candidate);
  } catch {
    const start = candidate.indexOf("{");
    const end = candidate.lastIndexOf("}");
    if (start >= 0 && end > start) {
      return JSON.parse(candidate.slice(start, end + 1));
    }
    throw new Error("Model reply did not contain a JSON object");
  }
}

function buildFallbackReview(contractName: string, findings: Finding[], _codeOrBytecode: string): AiSecurityReview {
  const critList = findings.filter((f) => f.severity === "critical" || f.severity === "high");
  const topIssue = critList[0]?.title ?? "Potential Reentrancy / State Desynchronization";

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
    threatModelReport: `### Automated Threat Model for ${contractName}

1. **Architecture & Trust Invariants**:
   - The contract exposes public state-mutating functions that handle value or sensitive state transitions.
   - Analysis of current rule findings identified ${findings.length} issue(s), with ${critList.length} high/critical priority item(s).

2. **Economic & Game-Theoretic Risks**:
   - **Lead Risk**: ${topIssue}.
   - **Flash Loan Sensitivity**: Review all balance checks against instantaneous spot reserves.
   - **First Deposit / Vault Inflation**: Ensure minimum shares or virtual offsets exist on liquidity deposits.

3. **Governance & Centralization**:
   - Verify whether owner privileges include immediate withdrawals, pause flags, or proxy logic modifications without timelocks.${startingTemplate ? `

**PoC**: AI review unavailable — attached test is the fallback-library starting template (\`${startingTemplate.file}\`) for the lead finding. Adapt its TODOs to the target's real ABI before running; it fails loudly until adapted.` : ""}`,
    foundryTestCode,
    economicRiskSummary: `Identified ${critList.length} high/critical vulnerabilities. Top risk: ${topIssue}. Review economic price feeds and reentrancy vectors.`,
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
): { system: string; user: string } {
  const findingsSummary = findings
    .map(
      (f, i) =>
        `Finding #${i + 1} [${f.severity.toUpperCase()}]: ${f.title} (Detector: ${f.detector}, SWC-${f.swc ?? "N/A"})\n` +
        `Location: ${f.locationFn ?? "contract"} (line ${f.locationLine ?? "N/A"})\n` +
        `Summary: ${f.summary}`,
    )
    .join("\n\n");

  // Starting-point templates, matched to this audit's findings. The model
  // ADAPTS these — it does not invent a harness from scratch.
  const startingTemplates = selectPocFallbacks(findings, 3);
  const templateSection =
    startingTemplates.length > 0
      ? `

STARTING-POINT PoC TEMPLATES — adapt, do not reinvent:
The library below contains proven, fork-ready Foundry PoC templates matched to this audit's findings. START FROM the template(s) for the primary vulnerability: keep its setUp()/fork shape, its \`contract PoC is Test\` name, and its observable-state assertions (balances, owner, shares — never a silent low-level-call success). Adapt ONLY the TODO-marked constants / interfaces to the target's real ABI (function names, token addresses, amounts, proofs, slots). Do NOT invent a new harness, a new attacker pattern, or a new setUp. If a template's TODO cannot be adapted to the target (e.g. the function does not exist), say so in the threat model and use the next template — never fabricate an interface the target does not have.

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
Your tasks:
1. Provide a rigorous, concise Executive Threat Model Report (economic flash loan attack vectors, oracle spot-price manipulation, ERC-4626 share inflation risks, and administrative rug vectors).
2. Generate a complete, compilation-ready Foundry test suite contract in Solidity (\`test/Exploit.t.sol\`) that tests and confirms the primary vulnerability. START FROM the starting-point template(s) above: keep the template's setUp()/fork shape, its \`contract PoC is Test\` name, and its observable-state assertions, adapting ONLY the TODO-marked constants / interfaces to the target's real ABI. The test MUST:
   - declare \`contract PoC is Test\` and \`import "forge-std/Test.sol";\`
   - in setUp(): fork live chain state with \`vm.createSelectFork(vm.envString("POC_RPC_URL"))\` (pin a block with \`vm.envUint("POC_FORK_BLOCK")\` when it is nonzero) and attach to the live target via \`vm.envAddress("POC_TARGET")\` — never hardcode a target address
   - fund an attacker with \`vm.deal\`, execute the attack against the forked live contract, and assert a balance/profit change
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
): Promise<AiSecurityReview> {
  const { apiKey, model } = resolveOpenRouterConfig();

  if (!apiKey) {
    return buildFallbackReview(contractName, findings, body);
  }

  try {
    const { system, user } = buildAiReviewPrompt(contractName, body, findings, fourbyte);

    const referer =
      process.env.APP_URL?.trim() ||
      process.env.VERCEL_URL?.trim() ||
      "https://smart-kontrakt.vercel.app";

    const response = await withRetry(async () => {
      await openRouterLimiter.acquire();
      return fetch(OPENROUTER_API_URL, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
          "HTTP-Referer": referer,
          "X-Title": "SmartKontrakt / Kiln",
        },
        body: JSON.stringify({
          model,
          messages: [
            { role: "system", content: system },
            { role: "user", content: user },
          ],
          response_format: { type: "json_object" },
          temperature: 0.7,
          max_tokens: 6000,
        }),
        signal: AbortSignal.timeout(60_000),
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
