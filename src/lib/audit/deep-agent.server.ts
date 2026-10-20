import type { Finding } from "./types.ts";
import { openRouterLimiter, withRetry } from "./rate-limit.ts";
import {
  OPENROUTER_API_URL,
  extractJsonContent,
  resolveOpenRouterConfig,
} from "./ai-review.server.ts";
import { POC_FALLBACK_CATALOG, selectPocFallbacks } from "./poc-fallbacks.ts";
import { formatFourbyteResultsForPrompt, type FourbyteResults } from "./fourbyte.ts";
import { extractBugContext } from "./smartpoc/bce.ts";

/**
 * Deep Agent — DeepRL-style agentic exploit search.
 *
 * The static detectors + one-shot AI review only see what they were told
 * to look for. The Deep Agent closes the loop like an RL agent:
 *   1. PROPOSE — the model proposes NEW hypotheses (vulnerabilities the
 *      static detectors missed, or deeper variants of flagged ones), each
 *      with a PoC adapted from a fallback-library template.
 *   2. ACT — the browser runs each PoC on the fork via the Termux backend.
 *   3. REWARD — PoC passed = CONFIRMED vulnerability; failed = refuted.
 *   4. OBSERVE — next round's prompt carries confirmed + refuted results,
 *      so the agent exploits confirmed surfaces deeper and never repeats
 *      a refuted hypothesis.
 *
 * The server runs ONE round (LLM call). The browser orchestrates rounds
 * because PoC execution lives on the phone backend, not on Vercel.
 * Bounds: at most 2 hypotheses per round (enforced here), at most 3
 * rounds (enforced by the caller). A round that returns no hypotheses
 * ends the search.
 */

export type DeepAgentHypothesis = {
  title: string;
  detector: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  hypothesis: string;
  foundryTestCode: string;
};

export type DeepAgentPriorResult = {
  title: string;
  detector: string;
  outcome: "confirmed" | "refuted" | "error";
  /** PoC logs, truncated by the caller. */
  pocLogs: string;
};

export type DeepAgentRoundResult = {
  hypotheses: DeepAgentHypothesis[];
  /** Set when the search should stop (no more hypotheses, no API key, ...). */
  stopReason: string | null;
  /** Wall-clock ms for the LLM call + response parse. The 60s-timeout
   * saga showed this is the number that decides whether the prompt
   * fits the model's latency — the worker logs it per address. */
  llmMs: number;
};

/** Max hypotheses the server accepts from one round — the prompt asks for 2. */
export const DEEP_AGENT_MAX_HYPOTHESES_PER_ROUND = 2;

const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

/**
 * Build the prompt for one Deep Agent round. Exported for testing.
 */
export function buildDeepAgentPrompt(
  contractName: string,
  body: string,
  findings: Finding[],
  priorResults: DeepAgentPriorResult[],
  round: number,
  fourbyte?: FourbyteResults,
): { system: string; user: string } {
  const findingsSummary = findings
    .map(
      (f) =>
        `[${f.severity.toUpperCase()}] ${f.title} (Detector: ${f.detector})\n` +
        `Location: ${f.locationFn ?? "contract"} (line ${f.locationLine ?? "N/A"})\n` +
        `Summary: ${f.summary}`,
    )
    .join("\n\n");

  const priorSection =
    priorResults.length > 0
      ? `

PRIOR ROUNDS — reward signal. Treat these as ground truth from fork execution:
${priorResults
  .map(
    (p) =>
      `- [${p.outcome.toUpperCase()}] ${p.title} (Detector: ${p.detector})\n  PoC output: ${p.pocLogs.slice(0, 1500)}`,
  )
  .join("\n")}
Rules: NEVER propose a refuted hypothesis again (same function + same mechanism). When a hypothesis was CONFIRMED, go DEEPER on that same attack surface: variants, chained exploits, adjacent functions that share the flawed pattern. When a PoC errored (infra, not a verdict), do not retry the same shape.
`
      : `

This is round 1 — no prior PoC results yet.
`;

  // Starting-point templates matched to the static findings, plus the
  // catalog so the agent knows which shapes exist for other detectors.
  // Two templates, not three: each full template is several KB, and the
  // prompt is already large — the third is the least relevant match.
  const startingTemplates = selectPocFallbacks(findings, 2);
  const catalogLines = POC_FALLBACK_CATALOG.map(
    (c) => `- ${c.file}: ${c.scenario} (detectors: ${c.detectors.join(", ")})`,
  ).join("\n");
  const templateSection =
    startingTemplates.length > 0
      ? `

STARTING-POINT PoC TEMPLATES — adapt, do not reinvent:
${startingTemplates
  .map(
    (t) => `--- Template: ${t.file} ---\n\`\`\`solidity\n${t.source}\n\`\`\``,
  )
  .join("\n\n")}

Full template catalog (adapt the CLOSEST template above to your hypothesis):
${catalogLines}
`
      : "";

  const user = `Contract Name: ${contractName}

Contract Source / Decompiled Sample (truncated to first 12,000 chars):
\`\`\`solidity
${body.slice(0, 12000)}
\`\`\`

Static Analysis Findings (what the rule detectors already found):
${findingsSummary || "No static detectors triggered."}
${fourbyte ? formatFourbyteResultsForPrompt(fourbyte) : ""}
${priorSection}
${templateSection}
This is Deep Agent round ${round} of at most 3. Your task: find vulnerabilities the static detectors MISSED, or deeper variants of the flagged ones.

Propose up to ${DEEP_AGENT_MAX_HYPOTHESES_PER_ROUND} NEW hypotheses. Each hypothesis MUST:
- name a concrete attack path (function, state, ordering, economic mechanism) — not a generic "might be vulnerable"
- come with a complete, compilation-ready Foundry test (\`contract PoC is Test\`, \`import "forge-std/Test.sol";\`) STARTING FROM the closest starting-point template above: keep its setUp()/fork shape and observable-state assertions, adapt ONLY the TODOs to the target's real ABI
- fork with \`vm.createSelectFork(vm.envString("POC_RPC_URL"))\` (pin with \`vm.envUint("POC_FORK_BLOCK")\` when nonzero), target via \`vm.envAddress("POC_TARGET")\` — never hardcode an address
- assert a balance / owner / shares / state change that proves the exploit

If you cannot find a NEW, concrete, testable hypothesis, return an empty hypotheses array with a stopReason — do not pad with weak or repeated hypotheses.

Format your response strictly as JSON:
{
  "hypotheses": [
    {
      "title": "Short exploit title",
      "detector": "detector id (existing one, or a new descriptive id)",
      "severity": "critical | high | medium | low | info",
      "hypothesis": "1-3 sentences: the mechanism, why the static detectors missed it",
      "foundryTestCode": "Solidity code string for the PoC test"
    }
  ],
  "stopReason": "null or a short reason the search should stop"
}`;

  return {
    system:
      "You are a DeepRL-style exploit agent: propose concrete, testable vulnerability hypotheses and prove each with a fork PoC. You get a reward signal from PoC execution (confirmed / refuted) and must explore deeper on confirmed surfaces, never repeat refuted hypotheses. Respond strictly as JSON matching the requested schema.",
    user,
  };
}

/**
 * Run ONE Deep Agent round: one LLM call returning hypotheses + PoCs.
 * The caller runs the PoCs and feeds results back as priorResults.
 */
export async function runDeepAgentRound(
  contractName: string,
  body: string,
  findings: Finding[],
  priorResults: DeepAgentPriorResult[],
  round: number,
  fourbyte?: FourbyteResults,
): Promise<DeepAgentRoundResult> {
  // Structured output (JSON hypotheses + tool-calling shape) → the "json" model.
  const { apiKey, model } = resolveOpenRouterConfig(process.env, "json");
  if (!apiKey) {
    return { hypotheses: [], stopReason: "no_api_key", llmMs: 0 };
  }
  const started = Date.now();

  // SmartPoC Bug-Context Extraction (§3.2): hand the model a bug-relevant
  // function slice instead of the whole file, to cut noise and long-context
  // degradation. Falls back to the raw body if extraction yields nothing.
  let context = body;
  try {
    const ctx = await extractBugContext({
      body,
      findings: findings.map((f) => ({
        title: f.title,
        detector: f.detector,
        severity: f.severity,
        summary: f.summary,
        locationFn: f.locationFn,
      })),
    });
    if (ctx.context) context = ctx.context;
  } catch {
    // keep the raw body
  }

  const { system, user } = buildDeepAgentPrompt(contractName, context, findings, priorResults, round, fourbyte);
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
        "X-Title": "SmartKontrakt / Kiln Deep Agent",
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: "system", content: system },
          { role: "user", content: user },
        ],
        response_format: { type: "json_object" },
        temperature: 0.7,
        max_tokens: 8000,
      }),
      // The prompt carries source + templates + prior results, and the
      // model must emit up to 2 full PoCs — 60s was not enough (every
      // round timed out on the pipeline). 180s for one attempt.
      signal: AbortSignal.timeout(180_000),
    });
  }, {
    retries: 3,
    baseDelayMs: 2000,
    // Do NOT retry timeouts/aborts: a timeout means the model is too
    // slow for this prompt, and retrying the same huge prompt just
    // burns 4x the time (that is how every flagged address ate 4
    // minutes of timeouts). Fail fast after one long attempt. Keep
    // retrying 429 / 5xx / network errors, which are transient.
    retryOn: (err) => {
      if (!(err instanceof Error)) return false;
      if (err.name === "AbortError" || err.name === "TimeoutError") return false;
      if (/timeout|timed out|abort/i.test(err.message)) return false;
      return /429|rate.?limit|too many|network|fetch failed|econnreset|etimedout|econnrefused|socket hang up|503|502|500/i.test(err.message);
    },
  });

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
    hypotheses?: Array<Record<string, unknown>>;
    stopReason?: string | null;
  };

  // Validate: a hypothesis without a real PoC is not actionable.
  const hypotheses: DeepAgentHypothesis[] = (parsed.hypotheses ?? [])
    .filter(
      (h): h is Record<string, unknown> =>
        typeof h === "object" && h !== null,
    )
    .filter(
      (h) =>
        typeof h.title === "string" &&
        h.title.trim().length > 0 &&
        typeof h.foundryTestCode === "string" &&
        h.foundryTestCode.includes("contract PoC"),
    )
    .slice(0, DEEP_AGENT_MAX_HYPOTHESES_PER_ROUND)
    .map((h) => ({
      title: (h.title as string).trim(),
      detector:
        typeof h.detector === "string" && h.detector.trim().length > 0
          ? h.detector.trim()
          : "deep-agent",
      severity: SEVERITIES.has(h.severity as string)
        ? (h.severity as DeepAgentHypothesis["severity"])
        : "medium",
      hypothesis: typeof h.hypothesis === "string" ? h.hypothesis : "",
      foundryTestCode: h.foundryTestCode as string,
    }));

  return {
    hypotheses,
    stopReason:
      typeof parsed.stopReason === "string" && parsed.stopReason.trim().length > 0
        ? parsed.stopReason.trim()
        : hypotheses.length === 0
          ? "no_new_hypotheses"
          : null,
    llmMs: Date.now() - started,
  };
}

/**
 * Repair ONE PoC that failed to compile: a single LLM call that fixes
 * only the failure, changing as little as possible. `body` is the
 * target's source (truncated) — without it the model cannot look up the
 * real interface when the failure is a missing/wrong function, and
 * "don't fabricate" is unenforceable. The caller re-runs the fixed PoC
 * once; there is no second repair. Throws on LLM failure or on a fixed
 * PoC that is not a PoC test — the caller treats that as an error,
 * same as the original compile failure.
 */
/**
 * Removes duplicate function signatures within Solidity interfaces
 * to avoid solc Error (1686): Function with same name and parameter types defined twice.
 */
export function deduplicateInterfaceFunctions(solidityCode: string): string {
  return solidityCode.replace(
    /\binterface\s+(\w+)\s*\{([^}]+)\}/g,
    (interfaceMatch, interfaceName, interfaceBody) => {
      const lines = interfaceBody.split("\n");
      const seenSignatures = new Set<string>();
      const filteredLines: string[] = [];

      for (const line of lines) {
        const fnMatch = line.match(/^\s*function\s+(\w+)\s*\(([^)]*)\)/);
        if (fnMatch) {
          const fnName = fnMatch[1];
          const paramTypes = fnMatch[2]
            .split(",")
            .map((p: string) => p.trim().split(/\s+/)[0])
            .join(",");
          const sig = `${fnName}(${paramTypes})`;
          if (seenSignatures.has(sig)) {
            continue;
          }
          seenSignatures.add(sig);
        }
        filteredLines.push(line);
      }
      return `interface ${interfaceName} {${filteredLines.join("\n")}}`;
    }
  );
}

export async function repairPocCode(
  contractName: string,
  originalCode: string,
  errorLogs: string,
  body = "",
): Promise<{ fixedCode: string; llmMs: number }> {
  // Foundry/Solidity code repair → the "code" model.
  const { apiKey, model } = resolveOpenRouterConfig(process.env, "code");
  if (!apiKey) {
    throw new Error("OPENROUTER_API_KEY is not set");
  }
  const started = Date.now();
  const referer =
    process.env.APP_URL?.trim() ||
    process.env.VERCEL_URL?.trim() ||
    "https://smart-kontrakt.vercel.app";

  const user = `Contract: ${contractName}

Target contract source / body (truncated to 12,000 chars — use it to look up the REAL interface when the failure is a missing or wrong function; never guess a signature that is not in here):

\`\`\`solidity
${body.slice(0, 12000)}
\`\`\`

The Foundry PoC below FAILED TO COMPILE / RUN with this output:

\`\`\`
${errorLogs.slice(0, 8000)}
\`\`\`

Original PoC:

\`\`\`solidity
${originalCode.slice(0, 30000)}
\`\`\`

Fix ONLY the failure shown. Change as little as possible: keep \`contract PoC is Test\`, the fork setUp() shape (vm.createSelectFork + vm.envAddress POC_TARGET), and the observable-state assertions. Do NOT invent a new harness, a new attack, or interfaces the target does not have — if the failure is a call to a function that does not exist, remove that call path rather than guessing a signature. If the failure reports duplicate definitions (e.g. Error 1686), remove duplicate declarations so each function in an interface is declared once.

Respond strictly as JSON matching this schema:
\`{"foundryTestCode": "complete fixed Solidity code string"}\``;

  const response = await withRetry(async () => {
    await openRouterLimiter.acquire();
    return fetch(OPENROUTER_API_URL, {
      method: "POST",
      headers: {
        Authorization: ["Bearer", apiKey].join(" "),
        "Content-Type": "application/json",
        "HTTP-Referer": referer,
        "X-Title": "SmartKontrakt / Kiln PoC repair",
      },
      body: JSON.stringify({
        model,
        messages: [
          {
            role: "system",
            content:
              "You repair Foundry PoC tests that failed to compile or run. Fix only the failure shown, changing as little as possible. Respond strictly as JSON matching the requested schema.",
          },
          { role: "user", content: user },
        ],
        response_format: { type: "json_object" },
        temperature: 0.2,
        max_tokens: 8000,
      }),
      // A repair is one PoC, not a full round — but the model still
      // needs room to read the failure + rewrite the test.
      signal: AbortSignal.timeout(180_000),
    });
  }, {
    retries: 3,
    baseDelayMs: 2000,
    // Same fail-fast-on-timeout rule as runDeepAgentRound.
    retryOn: (err) => {
      if (!(err instanceof Error)) return false;
      if (err.name === "AbortError" || err.name === "TimeoutError") return false;
      if (/timeout|timed out|abort/i.test(err.message)) return false;
      return /429|rate.?limit|too many|network|fetch failed|econnreset|etimedout|econnrefused|socket hang up|503|502|500/i.test(err.message);
    },
  });

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
  const parsed = extractJsonContent(content) as { foundryTestCode?: unknown };
  const fixedCode = typeof parsed.foundryTestCode === "string" ? parsed.foundryTestCode : "";
  if (!fixedCode.includes("contract PoC")) {
    throw new Error("Repair did not return a PoC test");
  }
  return { fixedCode: deduplicateInterfaceFunctions(fixedCode), llmMs: Date.now() - started };
}
