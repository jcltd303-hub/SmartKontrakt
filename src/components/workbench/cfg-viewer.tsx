import { useState, useMemo } from "react";
import { GitBranch, AlertTriangle, ArrowRight, Search, Layers } from "lucide-react";

export type CfgBlock = {
  id: string;
  startPc: number;
  endPc: number;
  instructions: string[];
  terminator: string;
  isTerminal: boolean;
  isRevert: boolean;
  hasSensitiveOpcode: boolean;
  sensitiveOpcodes: string[];
  jumpTarget?: number;
};

const TERMINAL_OPS = new Set(["REVERT", "RETURN", "STOP", "SELFDESTRUCT", "INVALID"]);
const TERMINATOR_OPS = new Set(["JUMP", "JUMPI", "REVERT", "RETURN", "STOP", "SELFDESTRUCT", "INVALID"]);
const SENSITIVE_OPS = new Set(["DELEGATECALL", "SELFDESTRUCT", "ORIGIN", "CREATE2"]);

/**
 * Parse one disassembly line into { pc, op }.
 * formatDisassembly emits "0000  60  PUSH1 0x80" (pc, opcode byte, mnemonic,
 * immediate) — NOT the bracket form "[0000] PUSH1 0x80" this viewer used to
 * expect. The old regex never matched, so every op came back "" and the
 * whole program collapsed into a single block. Both forms are accepted.
 * Returns null for non-instruction lines (e.g. the "… N more truncated" footer).
 */
function parseDisassemblyLine(line: string): { pc: number; op: string } | null {
  let m = line.match(/^([0-9a-fA-F]+)\s+[0-9a-fA-F]{2}\s+([A-Z0-9]+)/);
  if (m && m[1] && m[2]) return { pc: parseInt(m[1], 16), op: m[2].toUpperCase() };
  m = line.match(/^\[([0-9a-fA-F]+)\]\s+([A-Z0-9]+)/);
  if (m && m[1] && m[2]) return { pc: parseInt(m[1], 16), op: m[2].toUpperCase() };
  return null;
}

interface CfgViewerProps {
  disassembly: string;
}

export function parseCfgBlocks(disassembly: string): CfgBlock[] {
  if (!disassembly || !disassembly.trim()) return [];

  const lines = disassembly.split("\n").filter((l) => Boolean(l.trim()));
  if (lines.length === 0) return [];

  const parsedBlocks: CfgBlock[] = [];
  let currentInstructions: string[] = [];
  let currentOps: string[] = [];
  let blockStartPc = 0;
  let blockEndPc = 0;
  let blockIndex = 0;

  const pushBlock = (endPc: number, terminator: string) => {
    if (currentInstructions.length === 0) return;
    const sensitive = [...new Set(currentOps.filter((o) => SENSITIVE_OPS.has(o)))];
    parsedBlocks.push({
      id: `block-${blockIndex++}`,
      startPc: blockStartPc,
      endPc,
      instructions: currentInstructions,
      terminator,
      isTerminal: TERMINAL_OPS.has(terminator),
      isRevert: terminator === "REVERT" || terminator === "INVALID",
      hasSensitiveOpcode: sensitive.length > 0,
      sensitiveOpcodes: sensitive,
    });
    currentInstructions = [];
    currentOps = [];
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const parsed = parseDisassemblyLine(line);
    if (!parsed) continue; // skips the "… N more instructions truncated" footer
    const { pc, op } = parsed;

    // JUMPDEST starts a new block: close the previous one (fall-through).
    if (op === "JUMPDEST" && currentInstructions.length > 0) {
      const lastOp = currentOps[currentOps.length - 1] ?? "FALLTHROUGH";
      pushBlock(blockEndPc, lastOp);
    }

    if (currentInstructions.length === 0) blockStartPc = pc;
    currentInstructions.push(line);
    currentOps.push(op);
    blockEndPc = pc;

    // Terminator opcodes trigger block completion.
    if (TERMINATOR_OPS.has(op)) pushBlock(pc, op);
  }
  // Flush a trailing block that ends without a terminator.
  if (currentInstructions.length > 0) {
    pushBlock(blockEndPc, currentOps[currentOps.length - 1] ?? "FALLTHROUGH");
  }

  return parsedBlocks;
}

export function CfgViewer({ disassembly }: CfgViewerProps) {
  const [selectedBlockId, setSelectedBlockId] = useState<string | null>(null);
  const [filterQuery, setFilterQuery] = useState<string>("");

  // Parse disassembly into EVM Basic Blocks
  const blocks: CfgBlock[] = useMemo(() => parseCfgBlocks(disassembly), [disassembly]);

  // Filter blocks
  const filteredBlocks = useMemo(() => {
    if (!filterQuery.trim()) return blocks;
    const q = filterQuery.toLowerCase().trim();
    return blocks.filter((b) =>
      b.instructions.some((inst) => inst.toLowerCase().includes(q)) ||
      b.id.toLowerCase().includes(q) ||
      b.terminator.toLowerCase().includes(q)
    );
  }, [blocks, filterQuery]);

  const activeBlock = blocks.find((b) => b.id === selectedBlockId) ?? blocks[0];

  if (blocks.length === 0) {
    return (
      <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-8 text-center text-xs font-mono text-[#746c60]">
        No bytecode disassembly available to construct Control Flow Graph. Paste raw runtime bytecode (0x...) or pull an on-chain address.
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4 font-mono text-xs">
      {/* CFG Header & Stats */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#1c1a16] p-3 rounded-lg border border-[#3a3428]">
        <div className="flex items-center gap-2">
          <GitBranch className="w-4 h-4 text-[#e8a54b]" />
          <span className="font-bold text-[#f4efe6]">Control Flow Graph (CFG)</span>
          <span className="text-[10px] px-2 py-0.5 rounded bg-[#26231c] text-[#a39886] border border-[#3a3428]">
            {blocks.length} Basic Blocks
          </span>
        </div>

        <div className="relative w-48">
          <Search className="w-3 h-3 text-[#746c60] absolute left-2 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search block/op..."
            value={filterQuery}
            onChange={(e) => setFilterQuery(e.target.value)}
            className="w-full bg-[#12110e] border border-[#3a3428] rounded pl-7 pr-2 py-1 text-[11px] text-[#f4efe6] focus:outline-none focus:border-[#e8a54b]"
          />
        </div>
      </div>

      {/* Two-Column CFG Layout: Block Graph Grid + Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Column: Visual Blocks Flow */}
        <div className="lg:col-span-7 bg-[#1c1a16] border border-[#3a3428] rounded-xl p-3 flex flex-col gap-2.5 max-h-[460px] overflow-y-auto">
          <div className="flex items-center justify-between text-[11px] text-[#a39886] pb-1 border-b border-[#3a3428]">
            <span>Block Flow ({filteredBlocks.length})</span>
            <span className="text-[10px] text-[#746c60]">Click block to inspect disassembly</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {filteredBlocks.map((block) => {
              const isSelected = (activeBlock && activeBlock.id === block.id);
              return (
                <button
                  key={block.id}
                  onClick={() => setSelectedBlockId(block.id)}
                  className={`text-left p-2.5 rounded-lg border transition-all flex flex-col gap-1.5 ${
                    isSelected
                      ? "bg-[#3a2c14] border-[#e8a54b] shadow-md ring-1 ring-[#e8a54b]/30"
                      : block.isRevert
                      ? "bg-red-950/20 border-red-900/50 hover:border-red-700"
                      : block.isTerminal
                      ? "bg-emerald-950/20 border-emerald-900/50 hover:border-emerald-700"
                      : block.hasSensitiveOpcode
                      ? "bg-amber-950/20 border-amber-900/50 hover:border-amber-700"
                      : "bg-[#26231c] border-[#3a3428] hover:border-[#4d4536]"
                  }`}
                >
                  <div className="flex items-center justify-between gap-1 w-full">
                    <span className="font-bold text-[#f4efe6] text-[11px] flex items-center gap-1">
                      <Layers className="w-3 h-3 text-[#e8a54b]" />
                      PC [0x{block.startPc.toString(16).padStart(4, "0")}..0x{block.endPc.toString(16).padStart(4, "0")}]
                    </span>
                    <span
                      className={`text-[9px] px-1.5 py-0.2 rounded font-bold uppercase ${
                        block.isRevert
                          ? "bg-red-950 text-red-300 border border-red-800"
                          : block.isTerminal
                          ? "bg-emerald-950 text-emerald-300 border border-emerald-800"
                          : "bg-[#12110e] text-[#a39886] border border-[#3a3428]"
                      }`}
                    >
                      {block.terminator}
                    </span>
                  </div>

                  <div className="text-[10px] text-[#a39886] line-clamp-2">
                    {block.instructions.slice(0, 3).join(" • ")}
                  </div>

                  {block.hasSensitiveOpcode && (
                    <div className="flex items-center gap-1 text-[9px] text-red-300 font-bold bg-red-950/60 px-1.5 py-0.5 rounded w-fit">
                      <AlertTriangle className="w-2.5 h-2.5 text-red-400" />
                      <span>{block.sensitiveOpcodes.join(", ")}</span>
                    </div>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Right Column: Block Disassembly Inspector */}
        <div className="lg:col-span-5 bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 flex flex-col gap-3">
          {activeBlock ? (
            <>
              <div className="flex items-center justify-between pb-2 border-b border-[#3a3428]">
                <div>
                  <h4 className="font-bold text-[#f4efe6] text-xs">
                    Basic Block: 0x{activeBlock.startPc.toString(16).padStart(4, "0")}
                  </h4>
                  <span className="text-[10px] text-[#a39886]">
                    Instructions: {activeBlock.instructions.length} • Exit: {activeBlock.terminator}
                  </span>
                </div>
                {activeBlock.isRevert ? (
                  <span className="px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-800 text-[10px] font-bold">
                    Terminal Revert
                  </span>
                ) : activeBlock.isTerminal ? (
                  <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-bold">
                    Terminal Exit
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 text-[10px] font-bold flex items-center gap-1">
                    <ArrowRight className="w-3 h-3" />
                    Branch
                  </span>
                )}
              </div>

              {/* Instructions stream */}
              <div className="bg-[#12110e] border border-[#3a3428] rounded-lg p-3 max-h-[340px] overflow-y-auto flex flex-col gap-1 leading-relaxed">
                {activeBlock.instructions.map((inst, idx) => {
                  const isCrit = /DELEGATECALL|SELFDESTRUCT|ORIGIN/.test(inst);
                  const isJump = /JUMP|JUMPI/.test(inst);
                  return (
                    <div
                      key={idx}
                      className={`px-1.5 py-0.5 rounded ${
                        isCrit
                          ? "bg-red-950/50 text-red-300 font-bold"
                          : isJump
                          ? "text-[#e8a54b] font-bold"
                          : "text-[#f4efe6]"
                      }`}
                    >
                      {inst}
                    </div>
                  );
                })}
              </div>
            </>
          ) : (
            <div className="text-center py-10 text-[#746c60]">Select a block to inspect its disassembly.</div>
          )}
        </div>
      </div>
    </div>
  );
}
