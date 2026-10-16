import type { Finding } from "./types";
import { openRouterLimiter, withRetry } from "./rate-limit";

export type AiSecurityReview = {
  threatModelReport: string;
  foundryTestCode: string;
  economicRiskSummary: string;
  source: "openrouter" | "template";
};

/** OpenRouter chat-completions endpoint (OpenAI-compatible). */
export const OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions";

/** Default model — overridable with OPENROUTER_MODEL without a code change. */
export const DEFAULT_OPENROUTER_MODEL = "nvidia/nemotron-3-super-120b-a12b:free";

export type OpenRouterConfig = {
  apiKey: string | undefined;
  model: string;
};

const PLACEHOLDER_KEYS = new Set(["", "MY_OPENROUTER_API_KEY", "YOUR_OPENROUTER_API_KEY"]);

/**
 * Resolve OpenRouter config from the environment.
 * Returns apiKey undefined when no real key is configured, so callers
 * can fall back to the template review instead of calling the API.
 */
export function resolveOpenRouterConfig(
  env: NodeJS.ProcessEnv = process.env,
): OpenRouterConfig {
  const rawKey = env.OPENROUTER_API_KEY?.trim();
  const apiKey = rawKey && !PLACEHOLDER_KEYS.has(rawKey) ? rawKey : undefined;
  const model = env.OPENROUTER_MODEL?.trim() || DEFAULT_OPENROUTER_MODEL;
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

  const foundryTestCode = `// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

// Foundry Exploit Verification Suite for ${contractName}
// Run with: forge test -vvvv

interface ITestTarget {
    function deposit() external payable;
    function withdraw() external;
    function owner() external view returns (address);
}

contract ExploitTest {
    ITestTarget target;
    address attacker = address(0xBEEF);
    uint256 public attackCount;

    event AttackTriggered(address indexed attacker, uint256 amountDrained);

    function setUp() public {
        // Deploy or attach to deployed target instance
        // vm.prank(attacker);
    }

    function test_exploit_${(critList[0]?.detector || "vulnerability").replace(/[^a-zA-Z0-9_]/g, "_")}() public {
        // Primary Finding: ${topIssue}
        // 1. Initial State verification
        // 2. Exploit execution sequence
        // 3. Assertion: Attacker balance increases or target invariant broken
    }

    // Fallback handler for reentrancy tests
    receive() external payable {
        if (attackCount < 5 && address(target).balance >= 1 ether) {
            attackCount++;
            target.withdraw();
        }
    }
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
   - Verify whether owner privileges include immediate withdrawals, pause flags, or proxy logic modifications without timelocks.`,
    foundryTestCode,
    economicRiskSummary: `Identified ${critList.length} high/critical vulnerabilities. Top risk: ${topIssue}. Review economic price feeds and reentrancy vectors.`,
    source: "template",
  };
}

export async function generateAiSecurityReview(
  contractName: string,
  body: string,
  findings: Finding[]
): Promise<AiSecurityReview> {
  const { apiKey, model } = resolveOpenRouterConfig();

  if (!apiKey) {
    return buildFallbackReview(contractName, findings, body);
  }

  try {
    const findingsSummary = findings
      .map(
        (f, i) =>
          `Finding #${i + 1} [${f.severity.toUpperCase()}]: ${f.title} (Detector: ${f.detector}, SWC-${f.swc ?? "N/A"})\n` +
          `Location: ${f.locationFn ?? "contract"} (line ${f.locationLine ?? "N/A"})\n` +
          `Summary: ${f.summary}`
      )
      .join("\n\n");

    const userPrompt = `Contract Name: ${contractName}

Contract Source / Decompiled Sample (truncated to first 12,000 chars):
\`\`\`solidity
${body.slice(0, 12000)}
\`\`\`

Detected Static Analysis Findings:
${findingsSummary || "No static detectors triggered."}

Your tasks:
1. Provide a rigorous, concise Executive Threat Model Report (economic flash loan attack vectors, oracle spot-price manipulation, ERC-4626 share inflation risks, and administrative rug vectors).
2. Generate a complete, compilation-ready Foundry test suite contract in Solidity (\`test/Exploit.t.sol\`) that tests and confirms the primary vulnerability.
3. Provide a 2-sentence economic risk summary.

Format your response strictly as JSON with this schema:
{
  "threatModelReport": "Markdown string containing the threat model",
  "foundryTestCode": "Solidity code string for the Foundry test suite",
  "economicRiskSummary": "Brief 2-sentence summary of the main economic/game-theoretic exposure"
}`;

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
            {
              role: "system",
              content:
                "You are a Principal EVM Security Auditor and White-Hat Exploit Researcher. Analyze the smart contract code / bytecode and detected vulnerabilities. Respond strictly as JSON matching the requested schema.",
            },
            { role: "user", content: userPrompt },
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
