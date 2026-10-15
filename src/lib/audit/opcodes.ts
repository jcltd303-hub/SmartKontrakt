const NAMES: (string | undefined)[] = [];

function set(op: number, name: string) {
  NAMES[op] = name;
}

set(0x00, "STOP");
set(0x01, "ADD");
set(0x02, "MUL");
set(0x03, "SUB");
set(0x04, "DIV");
set(0x05, "SDIV");
set(0x06, "MOD");
set(0x07, "SMOD");
set(0x08, "ADDMOD");
set(0x09, "MULMOD");
set(0x0a, "EXP");
set(0x0b, "SIGNEXTEND");
set(0x10, "LT");
set(0x11, "GT");
set(0x12, "SLT");
set(0x13, "SGT");
set(0x14, "EQ");
set(0x15, "ISZERO");
set(0x16, "AND");
set(0x17, "OR");
set(0x18, "XOR");
set(0x19, "NOT");
set(0x1a, "BYTE");
set(0x1b, "SHL");
set(0x1c, "SHR");
set(0x1d, "SAR");
set(0x20, "KECCAK256");
set(0x30, "ADDRESS");
set(0x31, "BALANCE");
set(0x32, "ORIGIN");
set(0x33, "CALLER");
set(0x34, "CALLVALUE");
set(0x35, "CALLDATALOAD");
set(0x36, "CALLDATASIZE");
set(0x37, "CALLDATACOPY");
set(0x38, "CODESIZE");
set(0x39, "CODECOPY");
set(0x3a, "GASPRICE");
set(0x3b, "EXTCODESIZE");
set(0x3c, "EXTCODECOPY");
set(0x3d, "RETURNDATASIZE");
set(0x3e, "RETURNDATACOPY");
set(0x3f, "EXTCODEHASH");
set(0x40, "BLOCKHASH");
set(0x41, "COINBASE");
set(0x42, "TIMESTAMP");
set(0x43, "NUMBER");
set(0x44, "PREVRANDAO");
set(0x45, "GASLIMIT");
set(0x46, "CHAINID");
set(0x47, "SELFBALANCE");
set(0x48, "BASEFEE");
set(0x49, "BLOBHASH");
set(0x4a, "BLOBBASEFEE");
set(0x50, "POP");
set(0x51, "MLOAD");
set(0x52, "MSTORE");
set(0x53, "MSTORE8");
set(0x54, "SLOAD");
set(0x55, "SSTORE");
set(0x56, "JUMP");
set(0x57, "JUMPI");
set(0x58, "PC");
set(0x59, "MSIZE");
set(0x5a, "GAS");
set(0x5b, "JUMPDEST");
set(0x5c, "TLOAD");
set(0x5d, "TSTORE");
set(0x5e, "MCOPY");
set(0x5f, "PUSH0");
for (let i = 0; i < 32; i += 1) set(0x60 + i, `PUSH${i + 1}`);
for (let i = 0; i < 16; i += 1) set(0x80 + i, `DUP${i + 1}`);
for (let i = 0; i < 16; i += 1) set(0x90 + i, `SWAP${i + 1}`);
for (let i = 0; i < 5; i += 1) set(0xa0 + i, `LOG${i}`);
set(0xf0, "CREATE");
set(0xf1, "CALL");
set(0xf2, "CALLCODE");
set(0xf3, "RETURN");
set(0xf4, "DELEGATECALL");
set(0xf5, "CREATE2");
set(0xfa, "STATICCALL");
set(0xfd, "REVERT");
set(0xfe, "INVALID");
set(0xff, "SELFDESTRUCT");

export function opcodeName(op: number): string {
  return NAMES[op] ?? `UNKNOWN_${op.toString(16).padStart(2, "0")}`;
}

export function pushWidth(op: number): number {
  if (op >= 0x60 && op <= 0x7f) return op - 0x5f;
  return 0;
}
