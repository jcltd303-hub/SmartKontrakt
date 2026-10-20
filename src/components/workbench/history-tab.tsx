import { SAMPLES } from "@/lib/audit/samples";
import { Trash2 } from "lucide-react";
import { formatDate } from "./presentation";
import type { WorkbenchController } from "./use-workbench-controller";

type HistoryTabProps = Pick<
  WorkbenchController,
  | "activeTab"
  | "scanHistory"
  | "getRiskColor"
  | "handleSelectSample"
  | "setContractLabel"
  | "handleRunAnalysis"
  | "contractBody"
  | "setActiveTab"
  | "handleDeleteScan"
>;

export function HistoryTab({
  activeTab,
  scanHistory,
  getRiskColor,
  handleSelectSample,
  setContractLabel,
  handleRunAnalysis,
  contractBody,
  setActiveTab,
  handleDeleteScan,
}: HistoryTabProps) {
  return (
    <>
      {activeTab === "history" && (
        <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 flex flex-col gap-3">
          <div className="flex items-center justify-between pb-2 border-b border-[#3a3428]">
            <h3 className="text-xs font-mono font-bold text-[#e8a54b] uppercase tracking-wider">
              Audit History Archive ({scanHistory.length})
            </h3>
            <span className="text-[11px] text-[#746c60]">Persisted across sessions</span>
          </div>

          {scanHistory.length === 0 ? (
            <p className="text-xs text-[#746c60] text-center py-6">No audits archived yet.</p>
          ) : (
            <div className="divide-y divide-[#3a3428] flex flex-col">
              {scanHistory.map((scan) => {
                const r = getRiskColor(scan.riskScore);
                return (
                  <div
                    key={scan.id}
                    className="py-3 flex items-center justify-between gap-3 hover:bg-[#26231c]/40 px-2 rounded-lg transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <span
                        className={`w-9 h-9 rounded-lg flex items-center justify-center font-mono font-bold text-xs ${r.bg} text-[#12110e]`}
                      >
                        {scan.riskScore}
                      </span>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-xs text-[#f4efe6]">{scan.label}</span>
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#26231c] text-[#a39886]">
                            {scan.inputKind}
                          </span>
                        </div>
                        <div className="text-[11px] text-[#746c60] mt-0.5 flex items-center gap-2 font-mono">
                          <span>Crit: {scan.criticalCount}</span>
                          <span>•</span>
                          <span>High: {scan.highCount}</span>
                          <span>•</span>
                          <span>{formatDate(scan.createdAt)}</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => {
                          const foundSample = SAMPLES.find((s) => s.label === scan.label);
                          if (foundSample) {
                            handleSelectSample(foundSample);
                          } else {
                            setContractLabel(scan.label);
                            handleRunAnalysis(contractBody, scan.label);
                          }
                          setActiveTab("findings");
                        }}
                        className="px-2.5 py-1 text-xs font-mono bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] rounded text-[#f4efe6]"
                      >
                        Load
                      </button>
                      <button
                        onClick={(e) => handleDeleteScan(scan.id, e)}
                        className="p-1 text-[#746c60] hover:text-[#e25b45]"
                        title="Remove scan"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </>
  );
}
