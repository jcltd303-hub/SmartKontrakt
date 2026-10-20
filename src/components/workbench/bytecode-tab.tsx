import { CfgViewer } from "@/components/cfg-viewer";
import { GitBranch } from "lucide-react";
import type { WorkbenchController } from "./use-workbench-controller";

type BytecodeTabProps = Pick<
  WorkbenchController,
  | "activeTab"
  | "report"
  | "contractBody"
  | "disasmLines"
  | "setBytecodeSubView"
  | "bytecodeSubView"
  | "disasmFilter"
  | "setDisasmFilter"
  | "cfgDisassembly"
>;

export function BytecodeTab({
  activeTab,
  report,
  contractBody,
  disasmLines,
  setBytecodeSubView,
  bytecodeSubView,
  disasmFilter,
  setDisasmFilter,
  cfgDisassembly,
}: BytecodeTabProps) {
  return (
    <>
      {activeTab === "bytecode" && (
        <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 flex flex-col gap-4">
          {/* Bytecode Meta Stats */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
            <div className="p-3 bg-[#26231c] border border-[#3a3428] rounded-lg text-center font-mono">
              <span className="text-[10px] text-[#a39886] uppercase block">BYTECODE SIZE</span>
              <span className="text-base font-bold text-[#f4efe6]">
                {report?.inventory.bytecodeBytes ??
                  (contractBody.startsWith("0x") ? (contractBody.length - 2) / 2 : "N/A")}{" "}
                B
              </span>
            </div>
            <div className="p-3 bg-[#26231c] border border-[#3a3428] rounded-lg text-center font-mono">
              <span className="text-[10px] text-[#a39886] uppercase block">BASIC BLOCKS</span>
              <span className="text-base font-bold text-amber-400">
                {report?.inventory.basicBlocks ?? "Inferred"}
              </span>
            </div>
            <div className="p-3 bg-[#26231c] border border-[#3a3428] rounded-lg text-center font-mono">
              <span className="text-[10px] text-[#a39886] uppercase block">PROXY TYPE</span>
              <span className="text-sm font-bold text-purple-300 truncate block">
                {report?.inventory.proxy ?? "None / Direct"}
              </span>
            </div>
            <div className="p-3 bg-[#26231c] border border-[#3a3428] rounded-lg text-center font-mono">
              <span className="text-[10px] text-[#a39886] uppercase block">OPCODES PARSED</span>
              <span className="text-base font-bold text-emerald-400">
                {report?.inventory.opcodes.reduce((acc, o) => acc + o.count, 0) ||
                  disasmLines.length}
              </span>
            </div>
          </div>

          {/* Critical Security Opcodes Table */}
          <div>
            <h4 className="text-xs font-mono font-bold text-[#e8a54b] uppercase tracking-wider mb-2">
              Sensitive Opcode Occurrences
            </h4>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-xs">
              {[
                { name: "DELEGATECALL", hex: "0xf4", risk: "Critical" },
                { name: "SELFDESTRUCT", hex: "0xff", risk: "Critical" },
                { name: "ORIGIN", hex: "0x32", risk: "High" },
                { name: "CALL", hex: "0xf1", risk: "Medium" },
                { name: "CREATE2", hex: "0xf5", risk: "Medium" },
                { name: "SLOAD", hex: "0x54", risk: "State Read" },
                { name: "SSTORE", hex: "0x55", risk: "State Write" },
                { name: "REVERT", hex: "0xfd", risk: "Control" },
              ].map((op) => {
                const found = report?.inventory.opcodes.find((o) => o.name === op.name)?.count ?? 0;
                return (
                  <div
                    key={op.name}
                    className={`p-2 rounded border flex items-center justify-between ${
                      found > 0
                        ? op.risk === "Critical"
                          ? "bg-red-950/40 border-red-800 text-red-300"
                          : "bg-amber-950/30 border-amber-800 text-amber-300"
                        : "bg-[#26231c] border-[#3a3428] text-[#746c60]"
                    }`}
                  >
                    <div>
                      <div className="font-bold">{op.name}</div>
                      <div className="text-[10px] opacity-70">{op.hex}</div>
                    </div>
                    <span className="text-sm font-bold font-mono">{found}</span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Disassembly Stream vs CFG View Toggle */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-1 bg-[#26231c] p-1 rounded-lg border border-[#3a3428]">
                <button
                  onClick={() => setBytecodeSubView("stream")}
                  className={`px-2.5 py-1 rounded text-[11px] font-mono transition-colors ${
                    bytecodeSubView === "stream"
                      ? "bg-[#e8a54b] text-[#12110e] font-bold"
                      : "text-[#a39886] hover:text-[#f4efe6]"
                  }`}
                >
                  Linear Disassembly
                </button>
                <button
                  onClick={() => setBytecodeSubView("cfg")}
                  className={`px-2.5 py-1 rounded text-[11px] font-mono transition-colors flex items-center gap-1 ${
                    bytecodeSubView === "cfg"
                      ? "bg-[#e8a54b] text-[#12110e] font-bold"
                      : "text-[#a39886] hover:text-[#f4efe6]"
                  }`}
                >
                  <GitBranch className="w-3 h-3" />
                  <span>Interactive CFG Graph</span>
                </button>
              </div>

              {bytecodeSubView === "stream" && (
                <input
                  type="text"
                  placeholder="Search opcode (e.g. JUMP, CALL)..."
                  value={disasmFilter}
                  onChange={(e) => setDisasmFilter(e.target.value)}
                  className="bg-[#12110e] border border-[#3a3428] rounded px-2 py-0.5 text-xs text-[#f4efe6] font-mono focus:outline-none focus:border-[#e8a54b]"
                />
              )}
            </div>

            {bytecodeSubView === "cfg" ? (
              <CfgViewer disassembly={cfgDisassembly} />
            ) : (
              <div className="max-h-96 overflow-y-auto bg-[#12110e] border border-[#3a3428] rounded-lg p-3 font-mono text-xs text-[#a39886] leading-relaxed">
                {disasmLines.length === 0 ? (
                  <p className="text-center py-6 text-[#746c60]">
                    No raw bytecode disassembly generated. Paste runtime hex (0x...) to view full
                    opcode streams.
                  </p>
                ) : (
                  disasmLines.map((line, idx) => {
                    const isDanger =
                      line.includes("DELEGATECALL") ||
                      line.includes("SELFDESTRUCT") ||
                      line.includes("ORIGIN");
                    const isCall = line.includes("CALL") || line.includes("STATICCALL");
                    return (
                      <div
                        key={idx}
                        className={`hover:bg-[#26231c] px-1 py-0.5 rounded ${
                          isDanger
                            ? "text-red-400 font-bold bg-red-950/20"
                            : isCall
                              ? "text-amber-300"
                              : "text-[#f4efe6]"
                        }`}
                      >
                        {line}
                      </div>
                    );
                  })
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
