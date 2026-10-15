import { opcodeName, pushWidth } from "./opcodes";

export type Instruction = {
  pc: number;
  op: number;
  name: string;
  imm?: string;
};

export function disassemble(code: Uint8Array): Instruction[] {
  const out: Instruction[] = [];
  let pc = 0;
  while (pc < code.length) {
    const op = code[pc] ?? 0;
    const width = pushWidth(op);
    if (width > 0) {
      const bytes = code.slice(pc + 1, pc + 1 + width);
      const imm = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
      out.push({ pc, op, name: opcodeName(op), imm });
      pc += 1 + width;
    } else {
      out.push({ pc, op, name: opcodeName(op) });
      pc += 1;
    }
  }
  return out;
}

export function formatDisassembly(ins: Instruction[], limit: number): { text: string; truncated: boolean } {
  const slice = ins.slice(0, limit);
  const lines = slice.map((i) => {
    const pc = i.pc.toString(16).padStart(4, "0");
    const op = i.op.toString(16).padStart(2, "0");
    const imm = i.imm ? ` 0x${i.imm}` : "";
    return `${pc}  ${op}  ${i.name}${imm}`;
  });
  if (ins.length > limit) {
    lines.push(`… ${ins.length - limit} more instructions truncated`);
  }
  return { text: lines.join("\n"), truncated: ins.length > limit };
}
