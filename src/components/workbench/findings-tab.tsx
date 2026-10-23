import { PocEvidenceBadge } from "@/components/poc-evidence-badge";
import { findingPocEvidence } from "@/lib/audit/poc-evidence";
import { aiReviewExcerptForFinding } from "@/lib/audit/adjudication";
import { CHAIN_STEP_ORDER } from "@/lib/audit/adjudicate-chain";
import { isValidEvmAddress } from "@/lib/audit/address-fetcher";
import {
  BookOpen,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Copy,
  Crosshair,
  Loader2,
  Scale,
  Search,
  ShieldCheck,
  X,
} from "lucide-react";
import { useState } from "react";
import { DISPOSITION_CONFIG, DISPOSITION_ORDER, SEVERITY_CONFIG } from "./presentation";
import type { WorkbenchController } from "./use-workbench-controller";

type FindingsTabProps = Pick<
  WorkbenchController,
  | "activeTab"
  | "report"
  | "aiReview"
  | "setSeverityFilter"
  | "severityFilter"
  | "findingSearch"
  | "setFindingSearch"
  | "filteredFindings"
  | "expandedFindings"
  | "findingPocRuns"
  | "setExpandedFindings"
  | "handleRunFindingPoc"
  | "findingPocRunning"
  | "singleAddressChain"
  | "singleAddress"
  | "copyToClipboard"
  | "copiedKey"
  | "handleRetryFindingPocSave"
  | "findingTriage"
  | "setFindingTriage"
  | "findingDispositions"
  | "findingDbId"
  | "handleSetFindingDisposition"
  | "dispositionSavingId"
  | "findingAdjudications"
  | "handleAdjudicateFinding"
  | "handleClearAdjudication"
  | "handleOpenRagForFinding"
>;

export function FindingsTab({
  activeTab,
  report,
  aiReview,
  setSeverityFilter,
  severityFilter,
  findingSearch,
  setFindingSearch,
  filteredFindings,
  expandedFindings,
  findingPocRuns,
  setExpandedFindings,
  handleRunFindingPoc,
  findingPocRunning,
  singleAddress,
  singleAddressChain,
  copyToClipboard,
  copiedKey,
  handleRetryFindingPocSave,
  findingTriage,
  setFindingTriage,
  findingDispositions,
  findingDbId,
  handleSetFindingDisposition,
  dispositionSavingId,
  findingAdjudications,
  handleAdjudicateFinding,
  handleClearAdjudication,
  handleOpenRagForFinding,
}: FindingsTabProps) {
  // Note drafts per DB finding id — a draft is attached to whichever
  // disposition the auditor taps next; untouched findings send no note
  // (the stored note is kept).
  const [noteDrafts, setNoteDrafts] = useState<Record<string, string>>({});
  const liveState = report?.inventory.liveState ?? null;
  return (
    <>
      {activeTab === "findings" && (
        <div className="flex flex-col gap-3">
          {/* Filter and Search Bar */}
          <div className="flex flex-wrap items-center justify-between gap-2 bg-[#1c1a16] p-2.5 rounded-lg border border-[#3a3428]">
            {/* Severity filter pills */}
            <div className="flex items-center gap-1 flex-wrap">
              {(["all", "critical", "high", "medium", "low", "info"] as const).map((sev) => {
                const count =
                  sev === "all"
                    ? (report?.findings.length ?? 0)
                    : (report?.findings.filter((f) => f.severity === sev).length ?? 0);
                return (
                  <button
                    key={sev}
                    onClick={() => setSeverityFilter(sev)}
                    className={`text-xs px-2 py-0.5 rounded font-mono capitalize transition-all ${
                      severityFilter === sev
                        ? "bg-[#e8a54b] text-[#12110e] font-bold"
                        : "bg-[#26231c] text-[#a39886] hover:text-[#f4efe6]"
                    }`}
                  >
                    {sev} ({count})
                  </button>
                );
              })}
            </div>

            {/* Search input */}
            <div className="relative w-44 sm:w-56">
              <Search className="w-3.5 h-3.5 text-[#746c60] absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Filter findings..."
                value={findingSearch}
                onChange={(e) => setFindingSearch(e.target.value)}
                className="w-full bg-[#12110e] border border-[#3a3428] rounded-md pl-8 pr-2.5 py-1 text-xs text-[#f4efe6] placeholder-[#746c60] focus:outline-none focus:border-[#e8a54b]"
              />
            </div>
          </div>

          {/* Findings List */}
          {filteredFindings.length === 0 ? (
            <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-8 text-center flex flex-col items-center justify-center gap-3">
              <ShieldCheck className="w-10 h-10 text-emerald-400/80" />
              <h3 className="text-sm font-semibold text-[#f4efe6]">
                No Matching Vulnerabilities Found
              </h3>
              <p className="text-xs text-[#a39886] max-w-md">
                {findingSearch || severityFilter !== "all"
                  ? "Try loosening your severity filter or search terms."
                  : "None of the active security heuristics matched this contract. Always inspect the surface map manually before deployment."}
              </p>
            </div>
          ) : (
            filteredFindings.map((finding) => {
              const cfg = SEVERITY_CONFIG[finding.severity] ?? SEVERITY_CONFIG.info;
              const isExpanded = Boolean(expandedFindings[finding.id]);
              const findingRun = findingPocRuns[finding.id];
              const evidence = findingPocEvidence({ ...finding, targetAddress: singleAddress,
                chainId: singleAddressChain, ...(findingRun?.result ? {
                  pocCode: findingRun.result.source, pocStatus: findingRun.result.status,
                  pocOutput: findingRun.result.output, pocRunAt: findingRun.result.finishedAt,
                } : {}) });
              const dbId = findingDbId(finding);
              const disposition = dbId ? findingDispositions[dbId] : undefined;
              const adjudication = dbId ? findingAdjudications[dbId] : undefined;
              const reviewExcerpt = aiReviewExcerptForFinding(aiReview, finding);
              const noteArg = dbId && dbId in noteDrafts ? noteDrafts[dbId] : undefined;

              return (
                <div
                  key={finding.id}
                  className={`border rounded-xl transition-all overflow-hidden ${
                    isExpanded
                      ? `${cfg.border} bg-[#1c1a16]`
                      : "border-[#3a3428] bg-[#1c1a16] hover:border-[#4d4536]"
                  }`}
                >
                  {/* Finding Card Header */}
                  <button
                    onClick={() =>
                      setExpandedFindings((prev) => ({ ...prev, [finding.id]: !prev[finding.id] }))
                    }
                    className="w-full text-left p-3.5 flex items-start justify-between gap-3 focus:outline-none"
                  >
                    <div className="flex items-start gap-2.5 flex-1 min-w-0">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider shrink-0 border ${cfg.badge}`}
                      >
                        {cfg.label}
                      </span>

                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <h3 className="text-sm font-semibold text-[#f4efe6]">{finding.title}</h3>
                          {finding.swc && (
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#26231c] text-[#e8a54b] border border-[#3a3428]">
                              SWC-{finding.swc}
                            </span>
                          )}
                          <span className="text-[10px] font-mono text-[#746c60]">
                            Conf: {finding.confidence}
                          </span>
                          {disposition && (
                            <span
                              className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${DISPOSITION_CONFIG[disposition.disposition].badge}`}
                              title={`Auditor disposition${disposition.note ? `: ${disposition.note}` : ""} — set ${new Date(disposition.updatedAt).toLocaleString()}`}
                            >
                              {DISPOSITION_CONFIG[disposition.disposition].label}
                            </span>
                          )}
                        </div>

                        <p className="text-xs text-[#a39886] mt-1 line-clamp-2">
                          {finding.summary}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0 pt-1">
                      {finding.locationFn && (
                        <span className="text-[11px] font-mono text-[#e8a54b] bg-[#3a2c14] px-2 py-0.5 rounded hidden sm:inline-block">
                          {finding.locationFn}
                          {finding.locationLine ? `:${finding.locationLine}` : ""}
                        </span>
                      )}
                      {isExpanded ? (
                        <ChevronDown className="w-4 h-4 text-[#a39886]" />
                      ) : (
                        <ChevronRight className="w-4 h-4 text-[#a39886]" />
                      )}
                    </div>
                  </button>

                  {/* Finding Expanded Details */}
                  {isExpanded && (
                    <div className="px-4 pb-4 pt-1 border-t border-[#3a3428] bg-[#12110e]/40 flex flex-col gap-3.5 text-xs">
                      {/* Location / Code Snippet */}
                      {finding.snippet && (
                        <div>
                          <div className="flex items-center justify-between text-[11px] font-mono text-[#a39886] mb-1">
                            <span>Vulnerable Code Line:</span>
                            {finding.locationLine && <span>Line {finding.locationLine}</span>}
                          </div>
                          <div className="p-3 bg-[#12110e] rounded-lg border border-[#3a3428] font-mono text-xs overflow-x-auto text-red-300">
                            <pre>{finding.snippet}</pre>
                          </div>
                        </div>
                      )}

                      {/* Technical Walkthrough */}
                      <div>
                        <span className="text-[11px] font-mono text-[#a39886] uppercase tracking-wider block mb-1">
                          Exploit Mechanics & Walkthrough:
                        </span>
                        <div className="p-3 bg-[#26231c]/50 rounded-lg border border-[#3a3428] text-[#f4efe6] leading-relaxed">
                          {finding.walkthrough}
                        </div>
                      </div>

                      <PocEvidenceBadge evidence={evidence} />

                      {/* Adjudication: stored evidence + one-action chain + disposition */}
                      <div className="p-3 bg-[#26231c]/50 rounded-lg border border-[#3a3428] flex flex-col gap-2.5">
                        <div className="flex items-center justify-between gap-2 flex-wrap">
                          <span className="text-[11px] font-mono text-[#a39886] uppercase tracking-wider flex items-center gap-1.5">
                            <Scale className="w-3.5 h-3.5 text-[#e8a54b]" />
                            Adjudication
                          </span>
                          {dbId ? (
                            <button
                              onClick={() => handleAdjudicateFinding(finding, Boolean(disposition || adjudication?.outcome))}
                              disabled={adjudication?.running || findingPocRunning}
                              className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#e8a54b] text-[#12110e] text-[10px] font-mono font-bold hover:brightness-110 disabled:opacity-50 transition-all"
                              title="Fetch (if needed) → AI review (reused if present) → run the PoC (reused if this exact PoC already ran) → suggestion. Never writes a disposition by itself."
                            >
                              {adjudication?.running ? (
                                <Loader2 className="w-3 h-3 animate-spin" />
                              ) : (
                                <Scale className="w-3 h-3" />
                              )}
                              <span>
                                {adjudication?.running
                                  ? "Adjudicating…"
                                  : disposition || adjudication?.outcome
                                    ? "Redo adjudication"
                                    : "Adjudicate"}
                              </span>
                            </button>
                          ) : (
                            <span className="text-[10px] font-mono text-[#746c60]">
                              Save the scan to adjudicate
                            </span>
                          )}
                        </div>

                        {(adjudication?.steps || adjudication?.outcome) && (
                          <div className="flex items-center gap-1.5 flex-wrap text-[10px] font-mono">
                            {CHAIN_STEP_ORDER.map((s) => {
                              const state = adjudication.outcome?.steps[s] ?? adjudication.steps?.[s];
                              return (
                                <span
                                  key={s}
                                  className={`px-1.5 py-0.5 rounded border capitalize ${
                                    state === "done"
                                      ? "border-emerald-800 text-emerald-300"
                                      : state === "reused"
                                        ? "border-sky-800 text-sky-300"
                                        : state === "failed"
                                          ? "border-red-800 text-red-300"
                                          : state === "running"
                                            ? "border-[#e8a54b]/50 text-[#e8a54b]"
                                            : "border-[#3a3428] text-[#746c60]"
                                  }`}
                                >
                                  {s}{" "}
                                  {state === "done"
                                    ? "✓"
                                    : state === "reused"
                                      ? "↺"
                                      : state === "failed"
                                        ? "✗"
                                        : state === "running"
                                          ? "…"
                                          : state === "skipped"
                                            ? "–"
                                            : "·"}
                                </span>
                              );
                            })}
                            {adjudication.outcome && !adjudication.outcome.complete && (
                              <span className="text-red-400 font-bold">
                                INCOMPLETE — stopped at {adjudication.outcome.stoppedAt}
                              </span>
                            )}
                            {adjudication.outcome?.complete &&
                              adjudication.outcome.kind !== "already_adjudicated" && (
                                <span className="text-emerald-400">pipeline complete</span>
                              )}
                          </div>
                        )}

                        {adjudication?.running && adjudication.notice && (
                          <div className="text-[11px] font-mono text-[#e8a54b] flex items-center gap-1.5">
                            <Loader2 className="w-3 h-3 animate-spin shrink-0" />
                            <span>{adjudication.notice}</span>
                          </div>
                        )}

                        {adjudication?.outcome && !adjudication.running && (
                          <div className="p-2.5 bg-[#12110e] rounded-lg border border-[#3a3428] flex flex-col gap-1.5">
                            <span className="text-[11px] font-mono text-[#f4efe6]">
                              {adjudication.outcome.message}
                            </span>
                            {adjudication.outcome.saveError && (
                              <span className="text-[11px] font-mono text-red-400">
                                Run completed but saving failed: {adjudication.outcome.saveError}
                              </span>
                            )}
                            <div className="flex items-center gap-2 flex-wrap text-[11px] font-mono">
                              <span className="text-[#a39886]">Suggested disposition:</span>
                              <span
                                className={`px-1.5 py-0.5 rounded border font-bold ${DISPOSITION_CONFIG[adjudication.outcome.suggestion].badge}`}
                              >
                                {DISPOSITION_CONFIG[adjudication.outcome.suggestion].label}
                              </span>
                              {adjudication.outcome.kind !== "already_adjudicated" && dbId && (
                                <button
                                  onClick={() =>
                                    handleSetFindingDisposition(finding, adjudication.outcome!.suggestion, noteArg)
                                  }
                                  disabled={dispositionSavingId === dbId}
                                  className="px-2 py-0.5 rounded bg-emerald-900/60 text-emerald-300 border border-emerald-800 hover:bg-emerald-900 font-bold disabled:opacity-50"
                                >
                                  Accept suggestion
                                </button>
                              )}
                              <button
                                onClick={() => handleClearAdjudication(finding)}
                                className="flex items-center gap-1 px-2 py-0.5 rounded bg-[#26231c] text-[#a39886] hover:text-[#f4efe6] border border-[#3a3428]"
                              >
                                <X className="w-3 h-3" />
                                <span>Dismiss</span>
                              </button>
                            </div>
                          </div>
                        )}

                        {/* Stored PoC verdict + full log (the manual check, inline) */}
                        {finding.pocStatus && !findingRun?.result && (
                          <div>
                            <div className="flex items-center gap-2 text-[11px] font-mono text-[#a39886] flex-wrap">
                              <span className="uppercase tracking-wider">Latest PoC verdict:</span>
                              <span
                                className={
                                  finding.pocStatus === "passed"
                                    ? "text-emerald-400 font-bold"
                                    : finding.pocStatus === "failed"
                                      ? "text-amber-400 font-bold"
                                      : finding.pocStatus === "no_tests"
                                        ? "text-[#e8a54b] font-bold"
                                        : finding.pocStatus === "skipped"
                                          ? "text-[#a39886] font-bold"
                                          : "text-red-400 font-bold"
                                }
                              >
                                {finding.pocStatus}
                              </span>
                              {finding.pocRunAt && (
                                <span>· {new Date(finding.pocRunAt).toLocaleString()}</span>
                              )}
                              {finding.pocDurationMs != null && <span>· {finding.pocDurationMs}ms</span>}
                            </div>
                            {finding.pocOutput && (
                              <details className="mt-1">
                                <summary className="text-[11px] font-mono text-[#e8a54b] cursor-pointer hover:underline">
                                  Full PoC output log
                                </summary>
                                <pre className="mt-1.5 max-h-96 overflow-y-auto bg-[#0a0908] border border-[#3a3428] rounded p-2 text-[11px] font-mono text-[#f4efe6] whitespace-pre-wrap">
                                  {finding.pocOutput}
                                </pre>
                              </details>
                            )}
                          </div>
                        )}

                        {/* AI review excerpt that actually discusses this finding */}
                        {reviewExcerpt && (
                          <div>
                            <span className="text-[11px] font-mono text-[#a39886] uppercase tracking-wider block mb-1">
                              AI review on this finding:
                            </span>
                            <div className="p-2.5 bg-[#12110e] rounded-lg border border-[#3a3428] text-[#f4efe6] leading-relaxed whitespace-pre-wrap">
                              {reviewExcerpt}
                            </div>
                          </div>
                        )}

                        {/* Live-state evidence attached to the scan */}
                        {liveState && liveState.reads.length > 0 && (
                          <div className="text-[11px] font-mono text-[#a39886]">
                            <span className="uppercase tracking-wider">Live state</span>
                            {liveState.blockNumber != null && <span> @ block {liveState.blockNumber}</span>}
                            <span>: </span>
                            <span className="text-[#f4efe6]">
                              {liveState.reads.map((r) => `${r.name}=${r.value}`).join(" · ")}
                            </span>
                            {liveState.failures.length > 0 && (
                              <span className="text-[#746c60]">
                                {" "}
                                ({liveState.failures.length} getter{liveState.failures.length === 1 ? "" : "s"} unreadable)
                              </span>
                            )}
                          </div>
                        )}

                        {/* Disposition of record: buttons + note */}
                        {dbId && (
                          <div className="pt-2 border-t border-[#3a3428] flex flex-col gap-2">
                            <div className="flex items-center gap-1.5 flex-wrap text-[11px] font-mono">
                              <span className="text-[#a39886] text-[10px] uppercase font-bold">
                                Disposition:
                              </span>
                              {DISPOSITION_ORDER.map((d) => {
                                const isCur = disposition?.disposition === d;
                                return (
                                  <button
                                    key={d}
                                    onClick={() => handleSetFindingDisposition(finding, d, noteArg)}
                                    disabled={dispositionSavingId === dbId}
                                    className={`px-2 py-0.5 rounded text-[10px] transition-colors disabled:opacity-50 ${
                                      isCur
                                        ? `${DISPOSITION_CONFIG[d].badge} border font-bold`
                                        : "bg-[#26231c] text-[#746c60] hover:text-[#f4efe6] border border-[#3a3428]"
                                    }`}
                                  >
                                    {DISPOSITION_CONFIG[d].label}
                                  </button>
                                );
                              })}
                              {dispositionSavingId === dbId && (
                                <Loader2 className="w-3 h-3 animate-spin text-[#e8a54b]" />
                              )}
                              {disposition && (
                                <span className="text-[10px] text-[#746c60]">
                                  set {new Date(disposition.updatedAt).toLocaleString()}
                                </span>
                              )}
                            </div>
                            <input
                              type="text"
                              value={noteDrafts[dbId] ?? disposition?.note ?? ""}
                              onChange={(e) =>
                                setNoteDrafts((prev) => ({ ...prev, [dbId]: e.target.value }))
                              }
                              placeholder="Auditor note (saved with the next disposition tap)"
                              className="w-full bg-[#12110e] border border-[#3a3428] rounded-md px-2.5 py-1 text-[11px] font-mono text-[#f4efe6] placeholder-[#746c60] focus:outline-none focus:border-[#e8a54b]"
                            />
                          </div>
                        )}
                      </div>

                      {/* Attack PoC Solidity */}
                      {finding.exploitSolidity && (
                        <div>
                          <div className="flex items-center justify-between text-[11px] font-mono text-[#a39886] mb-1">
                            <span className="flex items-center gap-1.5 text-red-400">
                              <Crosshair className="w-3.5 h-3.5" />
                              Attack Contract (PoC):
                            </span>
                            <div className="flex items-center gap-2">
                              <button
                                onClick={() => handleRunFindingPoc(finding)}
                                disabled={
                                  findingPocRunning ||
                                  !isValidEvmAddress(singleAddress.trim()) ||
                                  !finding.exploitSolidity?.trim()
                                }
                                title={
                                  !isValidEvmAddress(singleAddress.trim())
                                    ? "Fetch an on-chain address first"
                                    : "Run this PoC on the local backend (Termux + Foundry, fork-only)"
                                }
                                className="flex items-center gap-1 text-[10px] text-[#e8a54b] hover:underline disabled:opacity-50 disabled:no-underline"
                              >
                                {findingRun?.running ? (
                                  <Loader2 className="w-3 h-3 animate-spin" />
                                ) : null}
                                <span>{findingRun?.running ? "Running…" : "Run"}</span>
                              </button>
                              <button
                                onClick={() =>
                                  copyToClipboard(finding.exploitSolidity, `poc-${finding.id}`)
                                }
                                className="flex items-center gap-1 text-[10px] text-[#e8a54b] hover:underline"
                              >
                                {copiedKey === `poc-${finding.id}` ? (
                                  <Check className="w-3 h-3 text-emerald-400" />
                                ) : (
                                  <Copy className="w-3 h-3" />
                                )}
                                <span>Copy PoC</span>
                              </button>
                            </div>
                          </div>
                          <div className="p-3 bg-[#12110e] rounded-lg border border-red-950 font-mono text-xs text-red-200 overflow-x-auto">
                            <pre>{finding.exploitSolidity}</pre>
                          </div>
                          {findingRun?.running && (
                            <div className="mt-2 p-3 bg-[#12110e] rounded-lg border border-[#3a3428] text-xs font-mono text-[#e8a54b]">
                              Running PoC on local backend…
                            </div>
                          )}
                          {findingRun?.result && (
                            <div className="mt-2 p-3 bg-[#12110e] rounded-lg border border-[#3a3428] flex flex-col gap-2">
                              <pre className="max-h-64 overflow-y-auto bg-[#0a0908] border border-[#3a3428] rounded p-2 text-[11px] font-mono text-[#f4efe6] whitespace-pre-wrap">
                                {findingRun.result.output || "(no output)"}
                                {findingRun.result.truncated ? "\n… (output truncated)" : ""}
                              </pre>
                              {findingRun.save !== "idle" && (
                                <div className="flex items-center gap-2 flex-wrap text-[11px] font-mono">
                                  {findingRun.save === "saving" && (
                                    <span className="text-[#a39886]">Saving to poc_runs…</span>
                                  )}
                                  {findingRun.save === "saved" && (
                                    <span className="text-emerald-400">Saved to poc_runs</span>
                                  )}
                                  {findingRun.save === "not-configured" && (
                                    <span className="text-amber-300">
                                      Not saved — Supabase not configured.
                                    </span>
                                  )}
                                  {findingRun.save === "failed" && (
                                    <>
                                      <span className="text-red-400">
                                        Save failed
                                        {findingRun.saveError ? `: ${findingRun.saveError}` : ""}
                                      </span>
                                      <button
                                        onClick={() => handleRetryFindingPocSave(finding.id)}
                                        className="text-[10px] text-[#e8a54b] hover:underline"
                                      >
                                        Retry Save
                                      </button>
                                    </>
                                  )}
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      )}

                      {/* Remediation Solidity */}
                      {finding.remediationSolidity && (
                        <div>
                          <div className="flex items-center justify-between text-[11px] font-mono text-[#a39886] mb-1">
                            <span className="flex items-center gap-1.5 text-emerald-400">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              Recommended Fix (Remediation):
                            </span>
                            <button
                              onClick={() =>
                                copyToClipboard(finding.remediationSolidity, `fix-${finding.id}`)
                              }
                              className="flex items-center gap-1 text-[10px] text-[#e8a54b] hover:underline"
                            >
                              {copiedKey === `fix-${finding.id}` ? (
                                <Check className="w-3 h-3 text-emerald-400" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                              <span>Copy Fix</span>
                            </button>
                          </div>
                          <div className="p-3 bg-[#12110e] rounded-lg border border-emerald-950 font-mono text-xs text-emerald-300 overflow-x-auto">
                            <pre>{finding.remediationSolidity}</pre>
                          </div>
                        </div>
                      )}

                      {/* Auditor Triage Selector */}
                      <div className="pt-2 border-t border-[#3a3428] flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] font-mono">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="text-[#a39886] text-[10px] uppercase font-bold">
                            Auditor Triage:
                          </span>
                          {(
                            ["active", "acknowledged", "false_positive", "remediated"] as const
                          ).map((st) => {
                            const current = findingTriage[finding.id]?.status ?? "active";
                            const isCur = current === st;
                            return (
                              <button
                                key={st}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setFindingTriage((prev) => ({
                                    ...prev,
                                    [finding.id]: { ...prev[finding.id], status: st },
                                  }));
                                }}
                                className={`px-2 py-0.5 rounded text-[10px] capitalize transition-colors ${
                                  isCur
                                    ? st === "remediated"
                                      ? "bg-emerald-950 text-emerald-300 border border-emerald-800 font-bold"
                                      : st === "false_positive"
                                        ? "bg-purple-950 text-purple-300 border border-purple-800 font-bold"
                                        : st === "acknowledged"
                                          ? "bg-amber-950 text-amber-300 border border-amber-800 font-bold"
                                          : "bg-red-950 text-red-300 border border-red-800 font-bold"
                                    : "bg-[#26231c] text-[#746c60] hover:text-[#f4efe6] border border-[#3a3428]"
                                }`}
                              >
                                {st.replace("_", " ")}
                              </button>
                            );
                          })}
                        </div>
                        <div className="flex items-center gap-2">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleOpenRagForFinding(finding);
                            }}
                            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#26231c] hover:bg-[#3a3428] text-[#e8a54b] hover:text-[#f4efe6] border border-[#3a3428] transition-colors text-[10px] font-mono shrink-0 shadow-sm"
                            title="Query local RAG knowledgebase for historical occurrences, exploit vectors, and fixes"
                          >
                            <BookOpen className="w-3 h-3 text-[#e8a54b]" />
                            <span>Ask RAG About Vuln</span>
                          </button>
                          <span className="text-[10px] text-[#746c60] hidden sm:inline">
                            Status saved
                          </span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      )}
    </>
  );
}
