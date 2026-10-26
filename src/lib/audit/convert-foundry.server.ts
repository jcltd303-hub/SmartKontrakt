import { openRouterLimiter, withRetry, isTransientError } from "./rate-limit.ts";
import { postChatWithModelFallback, resolveOpenRouterConfig } from "./ai-review.server.ts";

export type ConvertFoundryResult = {
  plainSolidityCode: string;
  source: "openrouter" | "fallback";
  notes?: string;
  durationMs: number;
};

/**
 * Extract Solidity source code from model response (fenced block or raw code).
 */
export function extractSolidityCode(content: string): string {
  const match = content.match(/```(?:solidity)?\s*([\s\S]*?)```/i);
  if (match && match[1]?.trim()) {
    return match[1].trim();
  }
  return content.trim();
}

export type ConvertMode = "interaction" | "exploit" | "validation";

export type ConvertOptions = {
  contractName?: string;
  contractSource?: string;
  targetAddress?: string;
  mode?: ConvertMode;
};

/**
 * Build the prompt instructing the LLM to convert Foundry test code into plain,
 * deployable Solidity for contract interaction and validation.
 */
export function buildFoundryToPlainSolidityPrompt(
  foundryCode: string,
  contractName = "TargetContract",
  contractSource = "",
  options?: { targetAddress?: string; mode?: ConvertMode },
): { system: string; user: string } {
  const mode = options?.mode ?? "interaction";
  const targetAddr = options?.targetAddress?.trim() || "";

  const system =
    "You are a Principal EVM Security Researcher and Solidity Specialist. Your job is to convert Foundry test suites into clean, standalone, production-ready Plain Solidity contracts that interact with target contracts and validate state transitions without any Foundry, forge-std, or cheatcode dependencies.";

  const user = `Convert the following Foundry test code into a standalone PLAIN SOLIDITY CONTRACT for contract interaction and state validation.

Target Contract Name: ${contractName}
${targetAddr ? `Target Contract Address: ${targetAddr}\n` : ""}
Conversion Mode: ${mode.toUpperCase()} (contract interaction, state transition execution, and strict post-condition validation)
${contractSource ? `Target Contract Source snippet:\n\`\`\`solidity\n${contractSource.slice(0, 4000)}\n\`\`\`\n` : ""}

Foundry Test Suite Code to Convert:
\`\`\`solidity
${foundryCode.slice(0, 20000)}
\`\`\`

CONVERSION RULES:
1. NO Foundry dependencies: Remove \`import "forge-std/Test.sol";\`, \`contract ... is Test\`, \`makeAddr(...)\`, etc.
2. NO cheatcodes:
   - Eliminate all \`vm.*\` calls (\`vm.createSelectFork\`, \`vm.prank\`, \`vm.deal\`, \`vm.warp\`, \`vm.roll\`, \`vm.expectRevert\`, etc.).
   - Replace \`vm.prank(attacker)\` with direct caller invocation (\`msg.sender\`) or configurable caller parameters.
   - Replace \`vm.deal\` by making interaction functions \`payable\` with \`msg.value\`.
   - Replace \`vm.expectRevert\` with \`try / catch\` or low-level \`.call()\` checking \`!success\`.
   - Replace \`assertEq\`, \`assertTrue\`, \`assertFalse\` with Solidity \`require(condition, "error description")\` or custom errors (\`error ValidationFailed(string reason)\`).
3. Standalone Contract Architecture:
   - Declare SPDX license (\`// SPDX-License-Identifier: MIT\`) and pragma (\`pragma solidity ^0.8.20;\`).
   - Define necessary target interfaces based on the target functions called.
   - Contract name: \`${contractName.replace(/[^a-zA-Z0-9_]/g, "")}InteractionValidator\` (or \`ExploitContract\`).
   - Constructor accepts \`address _target\` ${targetAddr ? `(can default or accept \`${targetAddr}\`)` : ""} and records \`owner = msg.sender\`.
   - Dedicated interaction function: \`executeInteraction()\` (or \`attack()\`) that performs the exact method calls observed in the test.
   - Dedicated validation function: \`validateState()\` that validates state invariants (balances, allowances, ownership) and returns \`(bool isValid, string memory message)\`.
   - Combined entry point: \`runInteractionAndValidate() external payable returns (bool passed)\` that executes the interaction and asserts all validations.
   - Add \`receive() external payable\` if Ether transfers/reentrancy are involved.
   - Add \`withdraw()\` / \`withdrawLoot()\` to rescue any funds sent to the contract.
4. Add concise inline comments explaining how each Foundry assertion was translated to native Solidity validation.
5. Output ONLY the complete, compilable plain Solidity code inside a markdown code block (\`\`\`solidity ... \`\`\`). Do not wrap in JSON.`;

  return { system, user };
}

/**
 * Deterministic algorithmic fallback converter used when OpenRouter is unreachable,
 * rate-limited, or no API key is provided.
 */
export function convertFoundryToPlainSolidityFallback(
  foundryCode: string,
  contractName = "TargetContract",
): string {
  const safeName = contractName.replace(/[^a-zA-Z0-9_]/g, "") || "Target";

  // Extract any interface blocks present in the original code
  const interfaceMatches = foundryCode.match(/interface\s+\w+\s*\{[\s\S]*?\}/g) || [];
  const interfaces = interfaceMatches.join("\n\n");

  // Filter out forge-std imports, vm.* cheatcode calls, and assertions
  const lines = foundryCode.split("\n");
  const cleanedAttackLines: string[] = [];
  let inTestFunction = false;
  let hasReceive = false;

  for (const rawLine of lines) {
    const line = rawLine.trim();

    // Skip forge-std import and console statements
    if (line.includes("forge-std/Test.sol") || line.includes("console.log") || line.includes("console2.log")) {
      continue;
    }

    if (line.includes("receive()") || line.includes("fallback()")) {
      hasReceive = true;
    }

    // Identify start of test functions
    if (/function\s+(?:test|test_)\w*\s*\(/i.test(line)) {
      inTestFunction = true;
      continue;
    }

    if (inTestFunction) {
      if (line === "}" && rawLine.startsWith("    }")) {
        inTestFunction = false;
        continue;
      }

      // Skip cheatcodes
      if (
        line.startsWith("vm.") ||
        line.includes("vm.createSelectFork") ||
        line.includes("vm.prank") ||
        line.includes("vm.startPrank") ||
        line.includes("vm.stopPrank") ||
        line.includes("vm.deal") ||
        line.includes("vm.warp") ||
        line.includes("vm.roll") ||
        line.includes("vm.expectRevert") ||
        line.startsWith("assertEq") ||
        line.startsWith("assertTrue") ||
        line.startsWith("assertFalse")
      ) {
        continue;
      }

      cleanedAttackLines.push(rawLine);
    }
  }

  const attackBody =
    cleanedAttackLines.length > 0
      ? cleanedAttackLines.join("\n")
      : `        // Converted attack execution sequence
        (bool success, ) = address(target).call{value: msg.value}("");
        require(success, "Exploit call failed");`;

  return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ${safeName}Exploit
 * @notice Standalone Plain Solidity exploit contract converted from Foundry test suite.
 * @dev Stripped of forge-std/Test.sol and vm.* cheatcodes.
 *      Deployable via Remix, Hardhat, Foundry script, or cast.
 *
 * Deployment Guide:
 * 1. Deploy this contract passing the target contract address to the constructor.
 * 2. Call attack() with required msg.value if funding is needed.
 * 3. Call withdrawLoot() to collect drained ETH to your wallet.
 */

${interfaces ? interfaces + "\n" : `interface I${safeName} {
    // Add additional target function signatures here if not already defined
}`}

contract ${safeName}Exploit {
    address public immutable target;
    address payable public immutable owner;

    event ExploitExecuted(address indexed target, uint256 lootCaptured);
    event LootWithdrawn(address indexed recipient, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can execute");
        _;
    }

    constructor(address _target) payable {
        require(_target != address(0), "Invalid target address");
        target = _target;
        owner = payable(msg.sender);
    }

    /**
     * @notice Executes the exploit against the target contract.
     * @dev Replaces Foundry test execution with live EVM interactions.
     */
    function attack() external payable onlyOwner {
${attackBody}

        emit ExploitExecuted(target, address(this).balance);
    }

    /**
     * @notice Reentrancy or Ether receiving hook.
     */
    receive() external payable {
        ${hasReceive ? "// Target reentrancy logic triggers here" : "// Accepts ETH sent back during exploit"}
    }

    /**
     * @notice Claims any captured Ether from the exploit back to the owner.
     */
    function withdrawLoot() external onlyOwner {
        uint256 balance = address(this).balance;
        require(balance > 0, "No loot to withdraw");
        (bool sent, ) = owner.call{value: balance}("");
        require(sent, "ETH transfer failed");
        emit LootWithdrawn(owner, balance);
    }
}`;
}

/**
 * Server-side entry point to convert Foundry test code into plain Solidity.
 * Calls OpenRouter "code" model with fallback chain, and falls back to
 * deterministic template conversion if OpenRouter is unreachable.
 */
export async function convertFoundryToPlainSolidity(
  foundryCode: string,
  contractName = "TargetContract",
  contractSource = "",
  options?: ConvertOptions,
): Promise<ConvertFoundryResult> {
  const started = Date.now();
  const trimmedCode = foundryCode.trim();
  if (!trimmedCode) {
    throw new Error("Foundry test code is required for conversion");
  }

  const { apiKey } = resolveOpenRouterConfig(process.env, "code");

  if (!apiKey) {
    const fallbackCode = convertFoundryToPlainSolidityFallback(trimmedCode, contractName);
    return {
      plainSolidityCode: fallbackCode,
      source: "fallback",
      notes: "Converted using deterministic Solidity AST adapter (OPENROUTER_API_KEY not configured).",
      durationMs: Date.now() - started,
    };
  }

  const referer =
    process.env.APP_URL?.trim() ||
    process.env.VERCEL_URL?.trim() ||
    "https://smart-kontrakt.vercel.app";

  const prompt = buildFoundryToPlainSolidityPrompt(trimmedCode, contractName, contractSource, options);

  try {
    const response = await withRetry(
      async () => {
        await openRouterLimiter.acquire();
        return postChatWithModelFallback({
          purpose: "code",
          apiKey,
          timeoutMs: 90_000,
          headers: {
            Authorization: `Bearer ${apiKey}`,
            "Content-Type": "application/json",
            "HTTP-Referer": referer,
            "X-Title": "Kiln Foundry to Plain Solidity Converter",
          },
          makeBody: (model) => ({
            model,
            messages: [
              { role: "system", content: prompt.system },
              { role: "user", content: prompt.user },
            ],
            temperature: 0.2,
            max_tokens: 6000,
          }),
        });
      },
      {
        retries: 2,
        baseDelayMs: 1500,
        retryOn: (err) => isTransientError(err),
      },
    );

    if (!response.ok) {
      const detail = (await response.text().catch(() => "")).slice(0, 500);
      throw new Error(`OpenRouter returned HTTP ${response.status}: ${detail}`);
    }

    const data = (await response.json()) as {
      choices?: Array<{ message?: { content?: string | null } }>;
    };

    const content = data.choices?.[0]?.message?.content;
    if (!content || !content.trim()) {
      throw new Error("OpenRouter returned empty conversion content");
    }

    const plainSolidityCode = extractSolidityCode(content);

    return {
      plainSolidityCode,
      source: "openrouter",
      notes: "Successfully synthesized via OpenRouter frontier code model.",
      durationMs: Date.now() - started,
    };
  } catch (err) {
    console.warn(
      `[Kiln] OpenRouter Foundry-to-Solidity conversion failed, using fallback adapter: ${err instanceof Error ? err.message : String(err)}`,
    );

    const fallbackCode = convertFoundryToPlainSolidityFallback(trimmedCode, contractName);
    return {
      plainSolidityCode: fallbackCode,
      source: "fallback",
      notes: `Converted via fallback adapter (OpenRouter error: ${err instanceof Error ? err.message : "Request failed"}).`,
      durationMs: Date.now() - started,
    };
  }
}
