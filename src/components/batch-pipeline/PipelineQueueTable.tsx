import type { Dispatch, SetStateAction } from "react";
import { SUPPORTED_CHAINS, type BatchItem } from "@/lib/audit/address-fetcher";
import { Download, Search, ExternalLink, Copy, Check, CheckCircle2, XCircle, Loader2, Eye, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from "lucide-react";

type Setter<T> = Dispatch<SetStateAction<T>>;
interface PipelineQueueTableProps {
  queue: BatchItem[];
  isRunning: boolean;
  filterQuery: string;
  setFilterQuery: Setter<string>;
  exportCsv: () => void;
  exportJson: () => void;
  filteredQueue: BatchItem[];
  paginatedQueue: BatchItem[];
  safeCurrentPage: number;
  pageSize: number;
  currentIndex: number;
  copyText: (text: string, key: string) => void;
  copiedKey: string | null;
  activeChainObj: (typeof SUPPORTED_CHAINS)[number];
  handleInspect: (item: BatchItem) => Promise<void>;
  inspectingAddr: string | null;
  setPageSize: Setter<number>;
  setCurrentPage: Setter<number>;
  totalPages: number;
  jumpPageInput: string;
  setJumpPageInput: Setter<string>;
}

export function PipelineQueueTable({
  queue,
  isRunning,
  filterQuery,
  setFilterQuery,
  exportCsv,
  exportJson,
  filteredQueue,
  paginatedQueue,
  safeCurrentPage,
  pageSize,
  currentIndex,
  copyText,
  copiedKey,
  activeChainObj,
  handleInspect,
  inspectingAddr,
  setPageSize,
  setCurrentPage,
  totalPages,
  jumpPageInput,
  setJumpPageInput
}: PipelineQueueTableProps) {
  return (
    <>
        {/* Right: Batch Execution Table */}
        <div className="lg:col-span-7 bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 flex flex-col gap-3">
          <div className="flex items-center justify-between gap-2 flex-wrap pb-2 border-b border-[#3a3428]">
            <div className="flex items-center gap-2">
              <h3 className="text-xs font-mono font-bold text-[#f4efe6] uppercase">
                Pipeline Queue ({queue.length})
              </h3>
              {isRunning && (
                <span className="flex items-center gap-1 text-[10px] text-[#e8a54b] font-mono bg-[#3a2c14] px-2 py-0.5 rounded border border-[#e8a54b]/30">
                  <Loader2 className="w-3 h-3 animate-spin" />
                  <span>Processing...</span>
                </span>
              )}
            </div>

            {/* Filter and Exports */}
            <div className="flex items-center gap-2 text-xs font-mono">
              <div className="relative w-36 sm:w-44">
                <Search className="w-3.5 h-3.5 text-[#746c60] absolute left-2 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Filter queue..."
                  value={filterQuery}
                  onChange={(e) => setFilterQuery(e.target.value)}
                  className="w-full bg-[#12110e] border border-[#3a3428] rounded pl-7 pr-2 py-0.5 text-xs text-[#f4efe6] focus:outline-none focus:border-[#e8a54b]"
                />
              </div>

              <button
                onClick={exportCsv}
                disabled={queue.length === 0}
                className="px-2.5 py-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#a39886] hover:text-[#f4efe6] flex items-center gap-1"
                title="Export CSV"
              >
                <Download className="w-3 h-3" />
                <span>CSV</span>
              </button>

              <button
                onClick={exportJson}
                disabled={queue.length === 0}
                className="px-2.5 py-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#a39886] hover:text-[#f4efe6] flex items-center gap-1"
                title="Export JSON"
              >
                <Download className="w-3 h-3" />
                <span>JSON</span>
              </button>
            </div>
          </div>

          {/* Queue List Table */}
          <div className="border border-[#3a3428] rounded-lg overflow-x-auto max-h-[380px] overflow-y-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#26231c] text-[#a39886] border-b border-[#3a3428] sticky top-0 z-10">
                <tr>
                  <th className="p-2.5">#</th>
                  <th className="p-2.5">Address</th>
                  <th className="p-2.5">Label</th>
                  <th className="p-2.5">Status</th>
                  <th className="p-2.5 text-center">Risk</th>
                  <th className="p-2.5 text-center">Crit</th>
                  <th className="p-2.5 text-center">High</th>
                  <th className="p-2.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#3a3428]">
                {filteredQueue.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="p-6 text-center text-[#746c60]">
                      No contracts in queue. Paste addresses on the left or upload a file.
                    </td>
                  </tr>
                ) : (
                  paginatedQueue.map((item, idx) => {
                    const rowNumber = (safeCurrentPage - 1) * pageSize + idx + 1;
                    const isCurrent = rowNumber - 1 === currentIndex && isRunning;
                    return (
                      <tr
                        key={item.id}
                        className={`hover:bg-[#26231c]/50 transition-colors ${
                          isCurrent ? "bg-[#3a2c14]/40" : ""
                        }`}
                      >
                        <td className="p-2.5 text-[#746c60]">{rowNumber}</td>
                        <td className="p-2.5">
                          <div className="flex items-center gap-1.5 font-bold text-[#f4efe6]">
                            <span title={item.address}>
                              {item.address.slice(0, 6)}...{item.address.slice(-4)}
                            </span>
                            <button
                              onClick={() => copyText(item.address, `copy-${item.id}`)}
                              className="text-[#746c60] hover:text-[#e8a54b]"
                              title="Copy full address"
                            >
                              {copiedKey === `copy-${item.id}` ? (
                                <Check className="w-3 h-3 text-emerald-400" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                            <a
                              href={`${(SUPPORTED_CHAINS.find((chain) => chain.id === item.chainId) ?? activeChainObj).blockExplorer}/address/${item.address}`}
                              target="_blank"
                              rel="noreferrer"
                              className="text-[#746c60] hover:text-[#e8a54b]"
                              title="View on block explorer"
                            >
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          </div>
                        </td>
                        <td className="p-2.5 text-[#a39886] max-w-[140px] truncate" title={item.label}>
                          {item.label}
                        </td>
                        <td className="p-2.5">
                          {item.status === "pending" && (
                            <span className="text-[#746c60] text-[11px]">Pending</span>
                          )}
                          {item.status === "analyzing" && (
                            <span className="text-[#e8a54b] flex items-center gap-1 text-[11px] font-bold">
                              <Loader2 className="w-3 h-3 animate-spin" />
                              Analyzing...
                            </span>
                          )}
                          {item.status === "completed" && (
                            <span className="text-emerald-400 flex items-center gap-1 text-[11px]">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              Done
                            </span>
                          )}
                          {item.status === "failed" && (
                            <span
                              className="text-red-400 flex items-center gap-1 text-[11px]"
                              title={item.error}
                            >
                              <XCircle className="w-3.5 h-3.5" />
                              Failed
                            </span>
                          )}
                        </td>
                        <td className="p-2.5 text-center font-bold">
                          {typeof item.riskScore === "number" ? (
                            <span
                              className={`px-1.5 py-0.5 rounded text-[11px] ${
                                item.riskScore >= 70
                                  ? "bg-red-950 text-red-300"
                                  : item.riskScore >= 40
                                  ? "bg-amber-950 text-amber-300"
                                  : "bg-emerald-950 text-emerald-300"
                              }`}
                            >
                              {item.riskScore}
                            </span>
                          ) : (
                            <span className="text-[#746c60]">—</span>
                          )}
                        </td>
                        <td className="p-2.5 text-center">
                          {item.criticalCount && item.criticalCount > 0 ? (
                            <span className="text-red-400 font-bold">{item.criticalCount}</span>
                          ) : (
                            <span className="text-[#746c60]">0</span>
                          )}
                        </td>
                        <td className="p-2.5 text-center">
                          {item.highCount && item.highCount > 0 ? (
                            <span className="text-amber-400 font-bold">{item.highCount}</span>
                          ) : (
                            <span className="text-[#746c60]">0</span>
                          )}
                        </td>
                        <td className="p-2.5 text-right">
                          {item.status === "completed" ? (
                            <button
                              onClick={() => handleInspect(item)}
                              disabled={inspectingAddr === item.address}
                              className="px-2 py-1 rounded bg-[#3a2c14] hover:bg-[#e8a54b] hover:text-[#12110e] text-[#e8a54b] text-[11px] font-bold flex items-center gap-1 ml-auto transition-colors disabled:opacity-50"
                              title="Inspect full audit in Workbench"
                            >
                              {inspectingAddr === item.address ? (
                                <Loader2 className="w-3 h-3 animate-spin" />
                              ) : (
                                <Eye className="w-3 h-3" />
                              )}
                              <span>Inspect</span>
                            </button>
                          ) : (
                            <span className="text-[#746c60] text-[11px]">—</span>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Table Pagination & Windowing Controls (handles 50,000+ rows smoothly) */}
          {filteredQueue.length > 0 && (
            <div className="flex items-center justify-between flex-wrap gap-3 pt-2 text-xs font-mono text-[#a39886] border-t border-[#3a3428]">
              <div className="flex items-center gap-2">
                <span>
                  Showing {((safeCurrentPage - 1) * pageSize + 1).toLocaleString()} -{" "}
                  {Math.min(safeCurrentPage * pageSize, filteredQueue.length).toLocaleString()} of{" "}
                  <strong className="text-[#f4efe6]">{filteredQueue.length.toLocaleString()}</strong> contracts
                </span>
                <span className="text-[#746c60]">|</span>
                <div className="flex items-center gap-1">
                  <span>Page Size:</span>
                  <select
                    value={pageSize}
                    onChange={(e) => {
                      setPageSize(Number(e.target.value));
                      setCurrentPage(1);
                    }}
                    className="bg-[#12110e] border border-[#3a3428] rounded px-1.5 py-0.5 text-[#f4efe6] focus:outline-none"
                  >
                    <option value={25}>25</option>
                    <option value={50}>50</option>
                    <option value={100}>100</option>
                    <option value={250}>250</option>
                  </select>
                </div>
              </div>

              {/* Navigation buttons */}
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setCurrentPage(1)}
                  disabled={safeCurrentPage === 1}
                  className="p-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] disabled:opacity-30 disabled:pointer-events-none"
                  title="First Page"
                >
                  <ChevronsLeft className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  disabled={safeCurrentPage === 1}
                  className="p-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] disabled:opacity-30 disabled:pointer-events-none"
                  title="Previous Page"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                </button>

                <div className="flex items-center gap-1 px-1.5 text-[#f4efe6]">
                  <span>Page</span>
                  <input
                    type="number"
                    min={1}
                    max={totalPages}
                    value={jumpPageInput !== "" ? jumpPageInput : safeCurrentPage}
                    onChange={(e) => setJumpPageInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        const val = parseInt(jumpPageInput, 10);
                        if (!isNaN(val) && val >= 1 && val <= totalPages) {
                          setCurrentPage(val);
                        }
                        setJumpPageInput("");
                      }
                    }}
                    onBlur={() => {
                      if (jumpPageInput !== "") {
                        const val = parseInt(jumpPageInput, 10);
                        if (!isNaN(val) && val >= 1 && val <= totalPages) {
                          setCurrentPage(val);
                        }
                        setJumpPageInput("");
                      }
                    }}
                    className="w-12 text-center bg-[#12110e] border border-[#3a3428] rounded px-1 py-0.5 text-xs text-[#e8a54b] focus:outline-none focus:border-[#e8a54b]"
                  />
                  <span>of {totalPages.toLocaleString()}</span>
                </div>

                <button
                  onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                  disabled={safeCurrentPage === totalPages}
                  className="p-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] disabled:opacity-30 disabled:pointer-events-none"
                  title="Next Page"
                >
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => setCurrentPage(totalPages)}
                  disabled={safeCurrentPage === totalPages}
                  className="p-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] disabled:opacity-30 disabled:pointer-events-none"
                  title="Last Page"
                >
                  <ChevronsRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}
        </div>
    </>
  );
}
