import { GoogleGenAI } from "@google/genai";
import type { Finding } from "./types";

export type AiSecurityReview = {
  threatModelReport: string;
  foundryTestCode: string;
  economicRiskSummary: string;
  source: "gemini" | "template";
};

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
  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey || !apiKey.trim() || apiKey === "MY_GEMINI_API_KEY") {
    return buildFallbackReview(contractName, findings, body);
  }

  try {
    const ai = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build",
        },
      },
    });

    const findingsSummary = findings
      .map(
        (f, i) =>
          `Finding #${i + 1} [${f.severity.toUpperCase()}]: ${f.title} (Detector: ${f.detector}, SWC-${f.swc ?? "N/A"})\n` +
          `Location: ${f.locationFn ?? "contract"} (line ${f.locationLine ?? "N/A"})\n` +
          `Summary: ${f.summary}`
      )
      .join("\n\n");

    const prompt = `You are a Principal EVM Security Auditor and White-Hat Exploit Researcher.
Analyze the following smart contract code / bytecode and detected vulnerabilities.

Contract Name: ${contractName}

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

    const response = await ai.models.generateContent({
      model: "gemini-3.8-flash",
      contents: prompt,
      config: {
        responseMimeType: "application/json",
      },
    });

    const text = response.text;
    if (text) {
      const parsed = JSON.parse(text) as {
        threatModelReport?: string;
        foundryTestCode?: string;
        economicRiskSummary?: string;
      };

      if (parsed.threatModelReport && parsed.foundryTestCode) {
        return {
          threatModelReport: parsed.threatModelReport,
          foundryTestCode: parsed.foundryTestCode,
          economicRiskSummary: parsed.economicRiskSummary || "Completed Gemini threat review.",
          source: "gemini",
        };
      }
    }
  } catch (err) {
    console.warn("[Kiln] Gemini AI review failed, falling back to structured template:", err);
  }

  return buildFallbackReview(contractName, findings, body);
}
