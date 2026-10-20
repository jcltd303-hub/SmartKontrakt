import { Activity, CheckCircle2, Loader2, RefreshCw } from "lucide-react";
import type { WorkbenchController } from "./use-workbench-controller";

type ProbeTabProps = Pick<
  WorkbenchController,
  "activeTab" | "handleRunManualProbe" | "isProbing" | "probes"
>;

export function ProbeTab({ activeTab, handleRunManualProbe, isProbing, probes }: ProbeTabProps) {
  return (
    <>
      {activeTab === "probe" && (
        <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-5 flex flex-col gap-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#3a3428]">
            <div>
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-[#e8a54b]" />
                <h3 className="text-sm font-bold font-mono text-[#f4efe6]">
                  On-Chain Interface & State Simulator
                </h3>
              </div>
              <p className="text-xs text-[#a39886] mt-0.5">
                Live eth_call query probes against standard ERC-20, Vault, and Admin view selectors
              </p>
            </div>

            <button
              onClick={handleRunManualProbe}
              disabled={isProbing}
              className="px-3.5 py-1.5 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] font-mono text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              {isProbing ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <RefreshCw className="w-3.5 h-3.5 text-[#e8a54b]" />
              )}
              <span>Re-Probe RPC</span>
            </button>
          </div>

          {probes.length === 0 ? (
            <div className="text-center py-8 text-xs font-mono text-[#746c60] flex flex-col items-center gap-2">
              <Activity className="w-6 h-6 text-[#746c60]" />
              <p>
                No active probe results. Enter an EVM contract address in the top toolbar to query
                live on-chain state.
              </p>
            </div>
          ) : (
            <div className="border border-[#3a3428] rounded-lg overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead className="bg-[#26231c] border-b border-[#3a3428] text-[#a39886]">
                  <tr>
                    <th className="p-2.5">Interface Selector</th>
                    <th className="p-2.5">Method Signature</th>
                    <th className="p-2.5">Status</th>
                    <th className="p-2.5">Decoded Value</th>
                    <th className="p-2.5">Raw Hex</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#3a3428] text-[#f4efe6]">
                  {probes.map((probe, idx) => (
                    <tr key={idx} className="hover:bg-[#26231c]/40">
                      <td className="p-2.5 font-bold text-[#e8a54b]">{probe.selector}</td>
                      <td className="p-2.5 font-bold">{probe.name}</td>
                      <td className="p-2.5">
                        {probe.success ? (
                          <span className="text-emerald-400 flex items-center gap-1 text-[11px]">
                            <CheckCircle2 className="w-3 h-3" />
                            Returned
                          </span>
                        ) : (
                          <span
                            className="text-[#746c60] text-[11px] truncate max-w-[120px]"
                            title={probe.error}
                          >
                            Reverted
                          </span>
                        )}
                      </td>
                      <td className="p-2.5 font-bold text-blue-300 max-w-[200px] truncate">
                        {probe.decodedString ||
                          probe.decodedNumber ||
                          probe.decodedAddress ||
                          (probe.success ? "0x" : "—")}
                      </td>
                      <td
                        className="p-2.5 text-[#746c60] text-[10px] max-w-[180px] truncate"
                        title={probe.rawResult}
                      >
                        {probe.rawResult || "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </>
  );
}
