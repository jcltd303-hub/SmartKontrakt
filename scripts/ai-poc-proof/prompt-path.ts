// prompt-path.ts — the AI-PoC proof suite's bridge into the app's REAL
// prompt / template / wrap / repair code. run.mjs shells out to this file
// through tsx (the pipeline worker's TS runner) so the suite exercises the
// exact modules the app uses. (Not `node --experimental-strip-types`:
// distro Node builds can lack compiled-in TypeScript support —
// ERR_NO_TYPESCRIPT on Node v22.22.1, seen on the S24 proot install.)
//
//   buildAiReviewPrompt   src/lib/audit/ai-review.server.ts
//   generateAiSecurityReview (prompt -> OpenRouter -> JSON extraction)
//   selectPocFallbacks    src/lib/audit/poc-fallbacks.ts (template pick)
//   POC_FALLBACK_TEMPLATES (the library sources themselves)
//   wrapPocSnippetWithReason src/lib/audit/poc-wrap.ts
//   repairPocCode         src/lib/audit/deep-agent.server.ts (one repair)
//
// Protocol: one JSON object on argv[3] in, one JSON object on stdout out.
// The OpenRouter key is read from the environment by the app modules
// themselves; this bridge never prints it and never returns it.

import {
  buildAiReviewPrompt,
  generateAiSecurityReview,
  resolveOpenRouterConfig,
} from "../../src/lib/audit/ai-review.server.ts";
import {
  POC_FALLBACK_TEMPLATES,
  selectPocFallbacks,
} from "../../src/lib/audit/poc-fallbacks.ts";
import { wrapPocSnippetWithReason } from "../../src/lib/audit/poc-wrap.ts";
import { repairPocCode } from "../../src/lib/audit/deep-agent.server.ts";
import type { Finding } from "../../src/lib/audit/types.ts";

type FindingInput = {
  detector: string;
  severity?: string;
  title: string;
  summary: string;
};

function toFinding(f: FindingInput): Finding {
  return {
    id: `proof-${f.detector}`,
    severity: (f.severity ?? "critical") as Finding["severity"],
    swc: null,
    title: f.title,
    confidence: "high",
    detector: f.detector,
    summary: f.summary,
    walkthrough: "",
    exploitSolidity: "",
    remediationSolidity: "",
    locationFn: null,
    locationLine: null,
    snippet: "",
  };
}

function out(obj: unknown): void {
  process.stdout.write(JSON.stringify(obj) + "\n");
  process.exit(0);
}

async function main(): Promise<void> {
  const cmd = process.argv[2] ?? "";
  const args = JSON.parse(process.argv[3] ?? "{}") as Record<string, unknown>;

  if (cmd === "config") {
    // Preflight for live mode: is a real key configured, and which model
    // would the review call use? The key itself is never emitted.
    const { apiKey, model } = resolveOpenRouterConfig(process.env, "review");
    out({ hasKey: Boolean(apiKey), model });
    return;
  }

  if (cmd === "prompt") {
    const finding = toFinding(args.finding as FindingInput);
    const { system, user } = buildAiReviewPrompt(
      String(args.contractName),
      String(args.body),
      [finding],
    );
    const selected = selectPocFallbacks([finding], 3).map((t) => t.file);
    out({
      systemChars: system.length,
      userChars: user.length,
      selectedTemplates: selected,
    });
    return;
  }

  if (cmd === "template") {
    // Dry-run stand-in source: the type's own library template, taken
    // from the app's generated template map (not from disk), plus what
    // the app's selector would have picked for this finding.
    const finding = toFinding(args.finding as FindingInput);
    const file = String(args.file);
    const source = POC_FALLBACK_TEMPLATES[file];
    if (!source) throw new Error(`no template in POC_FALLBACK_TEMPLATES for ${file}`);
    const [top] = selectPocFallbacks([finding], 1);
    out({ file, source, selectorTopPick: top?.file ?? null });
    return;
  }

  if (cmd === "generate") {
    const finding = toFinding(args.finding as FindingInput);
    const review = await generateAiSecurityReview(
      String(args.contractName),
      String(args.body),
      [finding],
    );
    out({ source: review.source, foundryTestCode: review.foundryTestCode });
    return;
  }

  if (cmd === "wrap") {
    const res = wrapPocSnippetWithReason(String(args.code));
    out({
      wrapped: Boolean(res.wrapped),
      testFile: res.wrapped?.testFile ?? null,
      note: res.wrapped?.note ?? null,
      reason: res.reason ?? null,
    });
    return;
  }

  if (cmd === "repair") {
    try {
      const { fixedCode } = await repairPocCode(
        String(args.contractName),
        String(args.code),
        String(args.logs),
        String(args.body ?? ""),
      );
      out({ fixedCode });
    } catch (err) {
      out({ error: err instanceof Error ? err.message : String(err) });
    }
    return;
  }

  throw new Error(`unknown command: ${cmd}`);
}

main().catch((err) => {
  process.stdout.write(
    JSON.stringify({ fatal: err instanceof Error ? err.message : String(err) }) + "\n",
  );
  process.exit(1);
});
