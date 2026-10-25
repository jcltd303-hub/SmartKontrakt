/**
 * Source-box state machine for the Interactive Audit & PoC tab.
 *
 * The interactive sandbox works on an editable Solidity box. Three ways
 * code gets into it: the user pastes/types (unchanged behaviour), the
 * user loads a contract by address (the same analyzeAddress fetch the
 * audit tab uses), or — on entering the tab — a prefill offers the
 * source the workbench already holds for its selected address.
 *
 * The load-bearing rule: the automatic prefill NEVER overwrites user
 * work. It fills the box only while the box is pristine — never edited,
 * and holding either the starter sample or an untouched load for the
 * SAME address. The explicit Load action is the opposite: it always
 * replaces, because the user asked for that contract's source. Keeping
 * the distinction in pure transitions (instead of component glue) is
 * what makes the rule testable.
 */

export type InteractiveLoadStatus =
  | "idle"
  | "loading"
  | "loaded"
  | "bytecode-only"
  | "error";

export interface InteractiveSourceState {
  /** Current box content. */
  code: string;
  /**
   * The address `code` was loaded for (by Load or by prefill). Null when
   * the content is the starter sample or an un-attributed paste. Kept
   * after user edits: provenance says where the code CAME from, the
   * `edited` flag says it no longer matches that source byte-for-byte.
   */
  codeForAddress: string | null;
  /** True once the user has typed into the box since the last fill. */
  edited: boolean;
  status: InteractiveLoadStatus;
  /** Fetch failure message (status === "error"). */
  error: string | null;
  /** Non-fatal explanation (bytecode-only results, bytecode prefill). */
  notice: string | null;
}

/** The demo contract the interactive tab has always opened with. */
export const INTERACTIVE_SAMPLE_CODE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

contract Vault {
    mapping(address => uint256) public balances;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount; // Vulnerability: State update after external call!
    }
}
`;

export function initialInteractiveSource(): InteractiveSourceState {
  return {
    code: INTERACTIVE_SAMPLE_CODE,
    codeForAddress: null,
    edited: false,
    status: "idle",
    error: null,
    notice: null,
  };
}

const EVM_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

export function isEvmAddressShape(value: string | null | undefined): boolean {
  return typeof value === "string" && EVM_ADDRESS_RE.test(value.trim());
}

/** Case-insensitive address identity; false unless both are addresses. */
export function sameEvmAddress(
  a: string | null | undefined,
  b: string | null | undefined,
): boolean {
  if (!isEvmAddressShape(a) || !isEvmAddressShape(b)) return false;
  return (a as string).trim().toLowerCase() === (b as string).trim().toLowerCase();
}

/** The user typed in the box. Only a real change marks it edited. */
export function applyInteractiveEdit(
  state: InteractiveSourceState,
  code: string,
): InteractiveSourceState {
  if (code === state.code) return state;
  return { ...state, code, edited: true };
}

/**
 * Offer the workbench's held source when the interactive tab is entered.
 *
 * `heldBody` is the body the workbench currently holds FOR `address`
 * (the caller vouches for the pairing — a typed-but-never-fetched
 * address passes null, so the sample/paste can never be dressed up as a
 * fetched contract's source). `heldBodyIsBytecode` marks the pairing
 * holding runtime bytecode instead of source: the address is real but
 * there is no source to fill, so the box is left alone and the notice
 * says why.
 *
 * Fills only a pristine box — see the module header for the rule.
 */
export function applyWorkbenchPrefill(
  state: InteractiveSourceState,
  input: { address: string; heldBody: string | null; heldBodyIsBytecode: boolean },
): InteractiveSourceState {
  const address = input.address.trim();
  if (!isEvmAddressShape(address)) return state;
  if (state.status === "loading") return state;
  const pristine =
    !state.edited &&
    (state.codeForAddress === null || sameEvmAddress(state.codeForAddress, address));
  if (!pristine) return state;
  if (input.heldBody === null) return state;
  if (input.heldBodyIsBytecode) {
    return {
      ...state,
      status: "idle",
      error: null,
      notice: `The workbench holds runtime bytecode for ${address} — no verified source. Paste source into the box, or Load to fetch again.`,
    };
  }
  return {
    code: input.heldBody,
    codeForAddress: address,
    edited: false,
    status: "loaded",
    error: null,
    notice: null,
  };
}

/** A Load was requested for the shared address. */
export function beginInteractiveLoad(
  state: InteractiveSourceState,
): InteractiveSourceState {
  return { ...state, status: "loading", error: null, notice: null };
}

/** Structural subset of analyzeAddress's result the box cares about. */
export interface InteractiveFetchResult {
  rawBody: string;
  inputKind: "source" | "bytecode";
}

/**
 * Settle a finished Load. Unlike the prefill, a successful load ALWAYS
 * replaces the box — it is the explicit user action. A bytecode-only
 * result replaces nothing: the honest state is a notice and the box
 * left usable for paste, still attributed to whatever it held before.
 */
export function settleInteractiveLoad(
  state: InteractiveSourceState,
  address: string,
  result: InteractiveFetchResult,
): InteractiveSourceState {
  const clean = address.trim();
  if (result.inputKind === "bytecode") {
    return {
      ...state,
      status: "bytecode-only",
      error: null,
      notice: `No verified source for ${clean} — the fetch returned runtime bytecode only, so the box was left unchanged. Paste the contract source to test against this address.`,
    };
  }
  return {
    code: result.rawBody,
    codeForAddress: clean,
    edited: false,
    status: "loaded",
    error: null,
    notice: null,
  };
}

/** A Load failed (bad address or a fetch error). The box is untouched. */
export function applyInteractiveLoadError(
  state: InteractiveSourceState,
  message: string,
): InteractiveSourceState {
  return { ...state, status: "error", error: message, notice: null };
}

/**
 * The visible mismatch: the box holds an untouched-or-edited load for a
 * different address than the one now selected. Returns the explanatory
 * line, or null when the box and the selection agree (or the box holds
 * no attributed load at all).
 */
export function interactiveBoxMismatch(
  state: InteractiveSourceState,
  currentAddress: string | null | undefined,
): string | null {
  if (!state.codeForAddress) return null;
  if (!isEvmAddressShape(currentAddress)) return null;
  if (sameEvmAddress(state.codeForAddress, currentAddress)) return null;
  return `The box holds source loaded for ${state.codeForAddress}. Loading replaces it with source for ${(currentAddress as string).trim()}.`;
}
