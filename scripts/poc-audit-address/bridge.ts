// bridge.ts — the poc-audit-address driver's bridge into the app's REAL
// audit code, mirroring scripts/ai-poc-proof/prompt-path.ts: this file is
// run through tsx (the pipeline worker's TS runner) so the audit exercises
// the exact modules the app uses, never a reimplementation.
//
//   analyzeAddress          src/lib/audit/address-fetcher.ts
//                           (Sourcify source -> static + bytecode analysis)
//   pocAuditEligibility     src/lib/audit/adjudication.ts
//                           (the PoC feed's own eligibility rule)
//   generateAiSecurityReview src/lib/audit/ai-review.server.ts
//   wrapPocSnippetWithReason src/lib/audit/poc-wrap.ts
//   repairPocCode           src/lib/audit/deep-agent.server.ts (one repair)
//   isPocCompileError / isRpcOrForkFailure
//                           src/lib/audit/foundry-backend.ts (log classes)
//
// Protocol: one JSON object on argv[3] in, one JSON object on stdout out.
// Bulky artifacts (report, source, findings, review) are written as files
// into the caller's outDir; stdout carries only the small summary the
// driver branches on. The OpenRouter key is read from the environment by
// the app modules themselves; this bridge never prints or returns it.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  analyzeAddress,
  canonicalChainId,
  getRpcsForChain,
} from "../../src/lib/audit/address-fetcher.ts";
import { pocAuditEligibility } from "../../src/lib/audit/adjudication.ts";
import {
  generateAiSecurityReview,
  resolveOpenRouterConfig,
} from "../../src/lib/audit/ai-review.server.ts";
import {
  isPocCompileError,
  isRpcOrForkFailure,
} from "../../src/lib/audit/foundry-backend.ts";
import { wrapPocSnippetWithReason } from "../../src/lib/audit/poc-wrap.ts";
import { repairPocCode } from "../../src/lib/audit/deep-agent.server.ts";
import type { Finding } from "../../src/lib/audit/types.ts";

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function out(obj: unknown): void {
  process.stdout.write(JSON.stringify(obj) + "\n");
  process.exit(0);
}

async function main(): Promise<void> {
  const cmd = process.argv[2] ?? "";
  const args = JSON.parse(process.argv[3] ?? "{}") as Record<string, unknown>;
  const outDir = String(args.outDir ?? ".");
  mkdirSync(outDir, { recursive: true });

  if (cmd === "config") {
    // Preflight: is a real key configured, and which model would the
    // review call use? The key itself is never emitted.
    const { apiKey, model } = resolveOpenRouterConfig(process.env, "review");
    out({ hasKey: Boolean(apiKey), model });
    return;
  }

  if (cmd === "analyze") {
    const address = String(args.address);
    const chainId = canonicalChainId(String(args.chain ?? "ethereum"));
    const { report, rawBody, inputKind } = await analyzeAddress(address, chainId);
    writeFileSync(join(outDir, "report.json"), JSON.stringify(report, null, 2), "utf8");
    writeFileSync(join(outDir, "source.sol"), rawBody, "utf8");
    writeFileSync(join(outDir, "findings.json"), JSON.stringify(report.findings, null, 2), "utf8");

    // Pick the PoC target with the feed's own rule: highest severity
    // first (report order breaks ties), presence-only findings excluded
    // unless corroborated — exactly what pocAuditEligibility enforces.
    const ordered = report.findings
      .map((finding, index) => ({ finding, index }))
      .sort(
        (a, b) =>
          (SEVERITY_ORDER[a.finding.severity] ?? 9) -
            (SEVERITY_ORDER[b.finding.severity] ?? 9) || a.index - b.index,
      );
    let chosenIndex: number | null = null;
    const exclusions: Record<string, number> = {};
    for (const { finding, index } of ordered) {
      const { eligible, exclusion } = pocAuditEligibility(
        finding,
        "critical_and_high",
        inputKind === "source" ? rawBody : null,
      );
      if (eligible) {
        chosenIndex = index;
        break;
      }
      if (exclusion) exclusions[exclusion] = (exclusions[exclusion] ?? 0) + 1;
    }

    out({
      inputKind,
      label: report.label,
      contractName: report.mainContract ?? report.label,
      riskScore: report.riskScore,
      findings: report.findings.length,
      chosenIndex,
      chosen:
        chosenIndex === null
          ? null
          : {
              detector: report.findings[chosenIndex]!.detector,
              severity: report.findings[chosenIndex]!.severity,
              title: report.findings[chosenIndex]!.title,
            },
      exclusions,
      rpcUrls: getRpcsForChain(chainId),
      chainId,
    });
    return;
  }

  if (cmd === "generate") {
    const findings = JSON.parse(
      readFileSync(join(outDir, "findings.json"), "utf8"),
    ) as Finding[];
    const finding = findings[Number(args.findingIndex)];
    if (!finding) throw new Error(`no finding at index ${String(args.findingIndex)}`);
    const body = readFileSync(join(outDir, "source.sol"), "utf8");
    const review = await generateAiSecurityReview(
      String(args.contractName),
      body,
      [finding],
      undefined,
      undefined,
      null,
    );
    writeFileSync(join(outDir, "review.json"), JSON.stringify(review, null, 2), "utf8");
    writeFileSync(join(outDir, "poc-generated.sol"), review.foundryTestCode, "utf8");
    out({ source: review.source });
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
      const body = readFileSync(join(outDir, "source.sol"), "utf8");
      const { fixedCode } = await repairPocCode(
        String(args.contractName),
        String(args.code),
        String(args.logs),
        body,
      );
      out({ fixedCode });
    } catch (err) {
      out({ error: err instanceof Error ? err.message : String(err) });
    }
    return;
  }

  if (cmd === "classify") {
    const logs = String(args.logs ?? "");
    out({
      compileError: isPocCompileError(logs),
      rpcOrForkFailure: isRpcOrForkFailure(logs),
    });
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
