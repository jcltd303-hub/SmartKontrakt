import { PocEvidenceBadge } from "@/components/poc-evidence-badge";
import { classifyPocEvidence } from "@/lib/audit/poc-evidence";
import { FoundryExport } from "@/components/foundry-export";
import { FoundryLocalRun } from "@/components/foundry-local-run";
import { FoundryToSolidityConverter } from "@/components/foundry-to-solidity-converter";
import {
  Check,
  Copy,
  Crosshair,
  Loader2,
  RefreshCw,
  Shield,
  Sparkles,
  Terminal,
} from "lucide-react";
import type { WorkbenchController } from "./use-workbench-controller";

type AiTabProps = Pick<
  WorkbenchController,
  | "activeTab"
  | "handleTriggerAiReview"
  | "isLoadingAi"
  | "aiReview"
  | "copyToClipboard"
  | "copiedKey"
  | "singleAddressChain"
  | "singleAddress"
  | "report"
  | "pocRunning"
  | "pocResult"
  | "pocSaved"
  | "handleRunDeepAgent"
  | "deepAgentRunning"
  | "deepAgentStatus"
  | "deepAgentError"
  | "deepAgentRounds"
  | "contractBody"
  | "setContractBody"
>;

export function AiTab({
  activeTab,
  handleTriggerAiReview,
  isLoadingAi,
  aiReview,
  copyToClipboard,
  copiedKey,
  singleAddress,
  singleAddressChain,
  report,
  pocRunning,
  pocResult,
  pocSaved,
  handleRunDeepAgent,
  deepAgentRunning,
  deepAgentStatus,
  deepAgentError,
  deepAgentRounds,
  contractBody,
  setContractBody,
}: AiTabProps) {
  return (
    <>
      {activeTab === "ai" && (
        <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-5 flex flex-col gap-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#3a3428]">
            <div>
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-[#e8a54b]" />
                <h3 className="text-sm font-bold font-mono text-[#f4efe6]">
                  OpenRouter AI Threat Modeling & Foundry Exploit Suite
                </h3>
              </div>
              <p className="text-xs text-[#a39886] mt-0.5">
                Analyzes economic game-theory, flash loan risks, and generates a runnable Foundry
                test suite
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleTriggerAiReview}
                disabled={isLoadingAi}
                className="px-3.5 py-1.5 rounded bg-[#e8a54b] hover:brightness-110 text-[#12110e] font-bold font-mono text-xs flex items-center gap-1.5 shadow transition-all disabled:opacity-50"
              >
                {isLoadingAi ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <RefreshCw className="w-3.5 h-3.5" />
                )}
                <span>{isLoadingAi ? "Analyzing..." : "Re-Analyze with OpenRouter"}</span>
              </button>
            </div>
          </div>

          {isLoadingAi ? (
            <div className="p-12 text-center flex flex-col items-center justify-center gap-3">
              <Loader2 className="w-8 h-8 text-[#e8a54b] animate-spin" />
              <p className="text-xs font-mono text-[#a39886]">
                Synthesizing economic threat model and Foundry test suite...
              </p>
            </div>
          ) : aiReview ? (
            <div className="flex flex-col gap-4">
              <PocEvidenceBadge evidence={classifyPocEvidence({ code: aiReview.foundryTestCode,
                origin: aiReview.source === "template" ? "template" : "generated", result: pocResult,
                target: singleAddress, chainId: singleAddressChain })} />
              {/* Economic risk banner */}
              <div className="p-3 bg-amber-950/20 border border-amber-900/60 rounded-lg flex items-start gap-2.5 font-mono text-xs">
                <Shield className="w-4 h-4 text-[#e8a54b] shrink-0 mt-0.5" />
                <div>
                  <span className="font-bold text-[#e8a54b]">Economic Risk Profile: </span>
                  <span className="text-[#f4efe6]">{aiReview.economicRiskSummary}</span>
                  <span className="text-[10px] text-[#746c60] ml-2">
                    (
                    {aiReview.source === "openrouter"
                      ? "OpenRouter Live Engine"
                      : "Structured Baseline Template"}
                    )
                  </span>
                </div>
              </div>

              {/* Foundry Test Suite */}
              <div>
                <div className="flex items-center justify-between pb-1.5">
                  <span className="text-xs font-mono font-bold text-[#e8a54b] uppercase flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5" />
                    Foundry Exploit Verification Test (test/Exploit.t.sol)
                  </span>
                  <button
                    onClick={() => copyToClipboard(aiReview.foundryTestCode, "foundry-poc")}
                    className="text-xs font-mono text-[#e8a54b] hover:underline flex items-center gap-1"
                  >
                    {copiedKey === "foundry-poc" ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                    <span>Copy test/Exploit.t.sol</span>
                  </button>
                </div>
                <div className="p-3.5 bg-[#12110e] rounded-lg border border-[#3a3428] font-mono text-xs text-amber-200 overflow-x-auto max-h-72">
                  <pre>{aiReview.foundryTestCode}</pre>
                </div>
                <FoundryExport
                  testCode={aiReview.foundryTestCode}
                  contractAddress={singleAddress}
                  contractName={report?.label ?? "Contract"}
                />
                <FoundryLocalRun testCode={aiReview.foundryTestCode} address={singleAddress}
                  chainId={singleAddressChain} origin={aiReview.source === "template" ? "template" : "generated"} />
                {(pocRunning || pocResult) && (
                  <div className="mt-2 p-3 bg-[#12110e] rounded-lg border border-[#3a3428] flex flex-col gap-2">
                    <div className="flex items-center gap-1.5 text-xs font-mono font-bold text-[#e8a54b]">
                      <span>
                        Auto PoC run
                        {pocRunning
                          ? " — running on local backend…"
                          : pocSaved
                            ? " — saved to Supabase"
                            : ""}
                      </span>
                    </div>
                    {pocResult && (
                      <>
                        <pre className="max-h-64 overflow-y-auto bg-[#0a0908] border border-[#3a3428] rounded p-2 text-[11px] font-mono text-[#f4efe6] whitespace-pre-wrap">
                          {pocResult.logs || "(no output)"}
                        </pre>
                      </>
                    )}
                  </div>
                )}
              </div>

              {/* Separate Section: Foundry to Plain Solidity Exploit Converter */}
              <FoundryToSolidityConverter
                defaultFoundryCode={aiReview.foundryTestCode}
                contractName={report?.label ?? "TargetContract"}
                contractBody={contractBody}
                targetAddress={singleAddress}
                onLoadIntoEditor={setContractBody}
              />

              {/* Threat Model Narrative */}
              <div>
                <div className="flex items-center justify-between pb-1.5">
                  <span className="text-xs font-mono font-bold text-[#a39886] uppercase">
                    Executive Threat Model Narrative
                  </span>
                  <button
                    onClick={() => copyToClipboard(aiReview.threatModelReport, "threat-md")}
                    className="text-xs font-mono text-[#a39886] hover:text-[#f4efe6] flex items-center gap-1"
                  >
                    {copiedKey === "threat-md" ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                    <span>Copy Narrative</span>
                  </button>
                </div>
                <div className="p-4 bg-[#26231c]/60 rounded-lg border border-[#3a3428] text-xs font-mono leading-relaxed text-[#f4efe6] whitespace-pre-wrap max-h-80 overflow-y-auto">
                  {aiReview.threatModelReport}
                </div>
              </div>
            </div>
          ) : (
            <div className="flex flex-col gap-6">
              <div className="text-center py-8 flex flex-col items-center gap-3">
                <Sparkles className="w-8 h-8 text-[#e8a54b]" />
                <p className="text-xs font-mono text-[#a39886] max-w-md">
                  Click below to generate a deep AI Threat Model and an executable Foundry test suite
                  (`test/Exploit.t.sol`).
                </p>
                <button
                  onClick={handleTriggerAiReview}
                  className="px-4 py-2 rounded bg-[#e8a54b] text-[#12110e] font-bold font-mono text-xs shadow hover:brightness-110 cursor-pointer"
                >
                  Generate AI Threat Model
                </button>
              </div>

              {/* Standalone Foundry to Plain Solidity Converter accessible before AI review */}
              <div className="border-t border-[#3a3428] pt-4">
                <FoundryToSolidityConverter
                  defaultFoundryCode=""
                  contractName={report?.label ?? "TargetContract"}
                  contractBody={contractBody}
                  targetAddress={singleAddress}
                  onLoadIntoEditor={setContractBody}
                />
              </div>
            </div>
          )}

          {/* Deep Agent — agentic exploit search */}
          <div className="mt-6 border-t border-[#3a3428] pt-4 flex flex-col gap-3">
            <div className="flex items-center justify-between gap-3">
              <span className="text-xs font-mono font-bold text-[#e8a54b] uppercase flex items-center gap-1.5">
                <Crosshair className="w-3.5 h-3.5" />
                Deep Agent — agentic exploit search
              </span>
              <button
                onClick={handleRunDeepAgent}
                disabled={deepAgentRunning || !report}
                className="px-3 py-1.5 rounded bg-[#e8a54b] text-[#12110e] font-bold font-mono text-xs shadow hover:brightness-110 disabled:opacity-50 flex items-center gap-1.5"
              >
                {deepAgentRunning ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Crosshair className="w-3.5 h-3.5" />
                )}
                <span>{deepAgentRunning ? "Running…" : "Run Deep Agent"}</span>
              </button>
            </div>
            <p className="text-[11px] font-mono text-[#a39886]">
              Proposes hypotheses the static detectors missed, proves each with a fork PoC, and
              feeds the result back — confirmed findings drive the next round deeper. Max 3 rounds,
              2 hypotheses each. Each PoC runs on the local backend (forge fork), same as the AI PoC
              run.
            </p>
            {deepAgentStatus && (
              <p className="text-xs font-mono text-[#f4efe6]">{deepAgentStatus}</p>
            )}
            {deepAgentError && <p className="text-xs font-mono text-red-400">{deepAgentError}</p>}
            {deepAgentRounds
              .flatMap((r) => r.hypotheses)
              .filter((h) => classifyPocEvidence({ code: h.foundryTestCode, result: h.pocResult, target: singleAddress, chainId: singleAddressChain }).stage === "reproduced").length > 0 && (
              <p className="text-xs font-mono font-bold text-emerald-400">
                Reproduced assertions: {deepAgentRounds.flatMap((r) => r.hypotheses).filter((h) =>
                  classifyPocEvidence({ code: h.foundryTestCode, result: h.pocResult,
                    target: singleAddress, chainId: singleAddressChain }).stage === "reproduced").length}

              </p>
            )}
            {deepAgentRounds.map((r) => (
              <div key={r.round} className="flex flex-col gap-2">
                <span className="text-[11px] font-mono font-bold text-[#a39886] uppercase">
                  Round {r.round}
                </span>
                {r.hypotheses.map((h, i) => (
                  <details key={i} className="bg-[#12110e] rounded-lg border border-[#3a3428] p-3">
                    <summary className="cursor-pointer text-xs font-mono font-bold text-[#f4efe6] flex items-center gap-2 flex-wrap">
                      <span>{h.title}</span>
                      <span className="text-[10px] text-[#746c60]">
                        ({h.detector} · {h.severity})
                      </span>
                      <PocEvidenceBadge evidence={classifyPocEvidence({ code: h.foundryTestCode,
                        result: h.pocResult, target: singleAddress, chainId: singleAddressChain })} />
                    </summary>
                    <p className="mt-2 text-[11px] font-mono text-[#a39886] whitespace-pre-wrap">
                      {h.hypothesis}
                    </p>
                    <div className="mt-2 flex items-center justify-between">
                      <span className="text-[10px] font-mono font-bold text-[#e8a54b] uppercase">
                        PoC (test/Exploit.t.sol)
                      </span>
                      <button
                        onClick={() =>
                          copyToClipboard(h.foundryTestCode, `deep-poc-${r.round}-${i}`)
                        }
                        className="text-[11px] font-mono text-[#e8a54b] hover:underline flex items-center gap-1"
                      >
                        {copiedKey === `deep-poc-${r.round}-${i}` ? (
                          <Check className="w-3 h-3 text-emerald-400" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                        <span>Copy PoC</span>
                      </button>
                    </div>
                    <pre className="mt-1 max-h-64 overflow-y-auto bg-[#0a0908] border border-[#3a3428] rounded p-2 text-[11px] font-mono text-amber-200 whitespace-pre-wrap">
                      {h.foundryTestCode}
                    </pre>
                    {h.pocResult && (
                      <pre className="mt-2 max-h-48 overflow-y-auto bg-[#0a0908] border border-[#3a3428] rounded p-2 text-[11px] font-mono text-[#f4efe6] whitespace-pre-wrap">
                        {h.pocResult.logs || "(no output)"}
                      </pre>
                    )}
                  </details>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  );
}
