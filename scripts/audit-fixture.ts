import type { ComprehensiveRecordInput } from "../src/lib/audit/persist.server.ts";
import type { Report } from "../src/lib/audit/types.ts";

export function record(id: string): ComprehensiveRecordInput {
  const report: Report = {
    label: id, inputKind: "source", riskScore: 50, summary: "Synthetic audit",
    aiNarrative: null, aiStatus: "unavailable",
    inventory: {
      inputKind: "source", contractNames: [id], kindNote: "test", pragma: null,
      compiler: null, functions: [], stateVars: [], events: [], inheritance: [],
      selectors: [], reconstructed: "", opcodes: [], signals: [], bytecodeBytes: null,
      basicBlocks: null, proxy: null, notes: [], disassembly: "",
    },
    findings: [0, 1].map((n) => ({
      id: `finding-${n}`, severity: "high", swc: null, title: `Finding ${n}`,
      confidence: "high", detector: "test", summary: "Test finding", walkthrough: "Details",
      exploitSolidity: "", remediationSolidity: "", locationFn: null, locationLine: null, snippet: "",
    })),
  };
  return { id, label: id, report, body: "contract Test {}", chainId: "ethereum", indexToRag: true };
}

