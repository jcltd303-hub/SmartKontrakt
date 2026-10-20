import type { Instruction } from "./disassemble.ts";

export type GasEstimate = {
  total: number;
  unboundedStorageWarning: boolean;
  warnings: string[];
};

// Simplified gas costs for common high-impact opcodes
const GAS_COSTS: Record<string, number> = {
  SLOAD: 2100,
  SSTORE: 5000, // Update cost as a baseline
  DELEGATECALL: 2600,
  CALL: 2600,
  CREATE: 32000,
  CREATE2: 32000,
};

/**
 * Heuristically detects unbounded loops with storage access.
 * This is a static analysis heuristic, not a formal verification.
 */
export function estimateGasAndDetectDos(ins: Instruction[]): GasEstimate {
  let totalGas = 0;
  const warnings: string[] = [];
  let unboundedStorageWarning = false;

  // Track JUMPDESTs
  const jumpDestinations = new Map<number, number>();
  for (let i = 0; i < ins.length; i++) {
    if (ins[i]!.name === "JUMPDEST") {
      jumpDestinations.set(ins[i]!.pc, i);
    }
  }

  // Very simple loop detection: scan for jump-backs
  for (let i = 0; i < ins.length; i++) {
    const cur = ins[i]!;
    totalGas += GAS_COSTS[cur.name] ?? 3; // 3 is default low gas

    if ((cur.name === "JUMP" || cur.name === "JUMPI") && cur.imm) {
      const targetPc = parseInt(cur.imm, 16);
      const targetIndex = jumpDestinations.get(targetPc);
      
      // If jump points to an earlier instruction, it's a loop
      if (targetIndex !== undefined && targetIndex < i) {
        let storageInLoop = 0;
        for (let j = targetIndex; j <= i; j++) {
          if (ins[j]!.name === "SLOAD" || ins[j]!.name === "SSTORE") {
            storageInLoop++;
          }
        }
        if (storageInLoop > 0) {
          unboundedStorageWarning = true;
          warnings.push(`Loop detected from ${cur.pc.toString(16)} to ${targetPc.toString(16)} contains ${storageInLoop} storage operations.`);
        }
      }
    }
  }

  return { total: totalGas, unboundedStorageWarning, warnings };
}
