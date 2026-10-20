/**
 * SmartPoC prompt templates (arXiv:2511.12993 Figures 5, 6, 8, 9).
 *
 * Pure string builders — no I/O — so they are unit-testable and shared by the
 * GRE-Engine and the Differential Verification stage.
 */

export type Prompt = { system: string; user: string };

const FOUNDRY_RULES = [
  'declare `contract PoC is Test` and `import {Test, console} from "forge-std/Test.sol";`',
  'in setUp(): fork live state with `vm.createSelectFork(vm.envString("POC_RPC_URL"))` (pin a block with `vm.envUint("POC_FORK_BLOCK")` when it is nonzero)',
  "attach to the live target via `vm.envAddress(\"POC_TARGET\")` — NEVER hardcode the target address",
  "fund the attacker with `vm.deal`, run the attack against the forked live contract, and assert an observable state change (balance / owner / shares) — never assert a bare low-level-call success",
].join("\n- ");

/** Figure 5 — prompted PoC generation. */
export function buildPocGenerationPrompt(args: {
  contractName: string;
  buildMetadata: string;
  finding: { title: string; severity: string; detector: string; summary: string; locationFn?: string | null };
  bugContext: string;
  startingTemplate?: { file: string; source: string } | null;
  fourbyteSection?: string;
}): Prompt {
  const template = args.startingTemplate
    ? `\n## Starting-point template (adapt its TODOs to the target's real ABI; do not invent a new harness)\n--- ${args.startingTemplate.file} ---\n\`\`\`solidity\n${args.startingTemplate.source}\n\`\`\`\n`
    : "";
  const user = `## Project information & build metadata
${args.buildMetadata}

## Static finding
[${args.finding.severity.toUpperCase()}] ${args.finding.title} (detector: ${args.finding.detector})
Location: ${args.finding.locationFn ?? "contract"}
${args.finding.summary}
${args.fourbyteSection ?? ""}
## Bug-related code snippets (SmartPoC Bug-Context Extraction slice)
\`\`\`solidity
${args.bugContext}
\`\`\`
${template}
## One-shot example
Input: a finding on a Vault's \`withdraw\` (state updated after the external call).
Output: \`contract PoC is Test\` with setUp() forking and attaching to the target, an attacker that re-enters \`withdraw\`, and \`assertGt(address(attacker).balance, before)\`.

## Task
Generate a complete, compilation-ready Foundry test for the finding above. It MUST:
- ${FOUNDRY_RULES}
- use ONLY functions and state the slice shows exist — never invent an interface or a signature the target does not have

Output the test script as:
\`\`\`solidity
<code>
\`\`\``;
  return {
    system:
      "You are a smart contract audit expert. Based on the provided messages, your task is to generate a Foundry-compatible test script. Respond with the complete test in a single ```solidity code block.",
    user,
  };
}

/** Figure 6 — post-execution debugger (regeneration). */
export function buildPocRegenerationPrompt(args: {
  previousPoc: string;
  errorLogs: string;
  generationUser?: string;
}): Prompt {
  const user = `${args.generationUser ? `## Generation prompt\n${args.generationUser}\n\n` : ""}## Previous generated test
\`\`\`solidity
${args.previousPoc}
\`\`\`

## Error logs
\`\`\`
${args.errorLogs.slice(0, 8000)}
\`\`\`

## Task
Fix ONLY the failure shown. Change as little as possible; preserve every part that already works. Do NOT invent a new harness, a new attack, or interfaces the target does not have — if a call targets a function that does not exist, remove that path rather than guessing a signature. Output the complete fixed test script in a single \`\`\`solidity code block.`;
  return {
    system:
      "Please fix the test code according to the log above and regenerate the complete test script. Respond with the complete test in a single ```solidity code block.",
    user,
  };
}

/** Figure 8 — action/state extraction for differential verification. */
export function buildActionStateExtractionPrompt(args: {
  finding: { title: string; summary: string };
  publicAbis: string[];
  poc: string;
}): Prompt {
  const user = `## Static finding
${args.finding.title}
${args.finding.summary}

## Public ABIs (choose from these ONLY)
${args.publicAbis.map((a) => `- ${a}`).join("\n") || "(none)"}

## PoC
\`\`\`solidity
${args.poc.slice(0, 20000)}
\`\`\`

## Task
From the ABIs above, choose:
- "action": the one or few public calls/transactions that exercise the trigger and can be run BOTH before and after it,
- "state": the observable state (public variables or view functions) whose value should be compared before and after.

Return strictly JSON: {"action": ["..."], "state": ["..."]}. Choose only names that appear in the ABIs — never invent one.`;
  return {
    system:
      "From the provided ABIs, choose the concrete actions to execute both before and after the PoC's trigger, and observable states whose values should be compared. Respond strictly as JSON.",
    user,
  };
}

/** Figure 9 — differential check insertion. */
export function buildDifferentialInsertionPrompt(args: {
  poc: string;
  differential: { action: string[]; state: string[] };
}): Prompt {
  const user = `## PoC
\`\`\`solidity
${args.poc.slice(0, 20000)}
\`\`\`

## Differential description
action: ${JSON.stringify(args.differential.action)}
state: ${JSON.stringify(args.differential.state)}

## Task
Insert IDENTICAL action + state-query operations immediately BEFORE and immediately AFTER the PoC's critical attacker action (the trigger). Log both the state values and each executed step using EXACTLY this marker so they can be parsed:
  console.log("SMARTPOC_STATE|pre|<label>", <value>);
  console.log("SMARTPOC_STATE|post|<label>", <value>);
Do not change the trigger itself or the target's code. Keep \`contract PoC is Test\`. Output the complete instrumented test in a single \`\`\`solidity code block.`;
  return {
    system:
      "Please insert identical action and state-query operations from the differential description before and after the PoC's critical attacker action, compare the results, and log both the state values and each executed step. Respond with the complete test in a single ```solidity code block.",
    user,
  };
}

/** DV step 3 — verdict from the observed pre/post deltas. */
export function buildDifferentialVerdictPrompt(args: {
  finding: { title: string; summary: string };
  differential: { action: string[]; state: string[] };
  preState: string[];
  postState: string[];
  logs: string;
}): Prompt {
  const user = `## Static finding
${args.finding.title}
${args.finding.summary}

## Differential oracle
action: ${JSON.stringify(args.differential.action)}
state: ${JSON.stringify(args.differential.state)}

## Observed state
pre:  ${JSON.stringify(args.preState)}
post: ${JSON.stringify(args.postState)}

## Raw execution logs (truncated)
\`\`\`
${args.logs.slice(0, 6000)}
\`\`\`

## Task
Decide whether the observed state change is evidence that the reported vulnerability was exercised (the delta must be in the direction the bug predicts — e.g. attacker balance up, attacker owns the asset, a privilege check now true). Return strictly JSON: {"validated": true|false, "reason": "one or two sentences"}.`;
  return {
    system:
      "You validate whether an executed differential PoC is evidence of the reported vulnerability. Be strict: only mark validated when the state delta matches the bug. Respond strictly as JSON.",
    user,
  };
}

/** Shared instruction for extracting a single Solidity code block. */
export const CODE_BLOCK_INSTRUCTION =
  "Output the complete Solidity test in exactly one ```solidity fenced code block.";
