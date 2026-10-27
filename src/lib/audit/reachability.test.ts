import test from "node:test";
import assert from "node:assert/strict";

import {
  classifyFunction,
  classifyReachability,
  inferEtherRecipients,
  isExplicitGuardModifierName,
  isGuardModifierName,
  isReportable,
  reachabilityLabel,
  type ReachabilityInput,
} from "./reachability.ts";

/**
 * Phase 4 regression fixtures. Every shape below is drawn from the
 * engagement's measured failures: the 480-hit corpus where 227 hits were
 * false positives, and every one of those was gated, internal,
 * self-addressed or unreachable. The REACHABLE positives are the control —
 * a classifier that calls everything BOUNDED is worse than no classifier.
 */

const base: ReachabilityInput = { visibility: "public", bodySource: "", modifiers: [] };

function cls(over: Partial<ReachabilityInput>) {
  return classifyReachability({ ...base, ...over }).class;
}

// ------------------------------------------------------------------
// INTERNAL
// ------------------------------------------------------------------

test("internal helper with no public entry is INTERNAL", () => {
  assert.equal(cls({ visibility: "internal", bodySource: "balances[msg.sender] -= amt;" }), "INTERNAL");
});

test("private helper is INTERNAL", () => {
  assert.equal(cls({ visibility: "private", bodySource: "" }), "INTERNAL");
});

test("internal helper reached from a public entry is not INTERNAL", () => {
  assert.equal(
    cls({ visibility: "internal", bodySource: "", reachableFromPublicEntry: true }),
    "REACHABLE",
  );
});

test("internal site with derived contracts in the compilation needs a read", () => {
  assert.equal(cls({ visibility: "internal", bodySource: "", hasDerivedContracts: true }), "NEEDS_READ");
});

test("constructor is INTERNAL (one-shot, no caller entry)", () => {
  assert.equal(cls({ visibility: "public", isConstructor: true, bodySource: "owner = msg.sender;" }), "INTERNAL");
});

// ------------------------------------------------------------------
// GATED — P7, P6, P8
// ------------------------------------------------------------------

test("onlyOwner modifier gates", () => {
  assert.equal(cls({ modifiers: ["onlyOwner"], bodySource: "owner.transfer(address(this).balance);" }), "GATED");
});

test("custom modifier ownerOnly gates (Bancor, P7)", () => {
  assert.equal(cls({ modifiers: ["ownerOnly"] }), "GATED");
});

test("hasMintPermission / isPlayer / treasuryOnly / oraclizeAction gate (P7)", () => {
  for (const m of ["hasMintPermission", "isPlayer", "treasuryOnly", "oraclizeAction", "checkAdmin", "restricted"]) {
    assert.equal(cls({ modifiers: [m] }), "GATED", `${m} should gate`);
  }
});

test("onlyActive is a STATE gate, not access control (P7)", () => {
  assert.equal(isGuardModifierName("onlyActive"), false);
  assert.equal(cls({ modifiers: ["onlyActive"] }), "REACHABLE");
});

test("nonReentrant is not access control", () => {
  assert.equal(cls({ modifiers: ["nonReentrant"], bodySource: "x = 1;" }), "REACHABLE");
});

test("multi-line require guard gates (KydyCore, P6)", () => {
  const body = "require(\n        msg.sender == owner,\n        \"not owner\"\n    );\n    payable(msg.sender).transfer(address(this).balance);";
  assert.equal(cls({ bodySource: body }), "GATED");
});

test("if-revert guard gates", () => {
  assert.equal(cls({ bodySource: "if (msg.sender != treasury) revert NotTreasury();" }), "GATED");
});

test("OZ _checkOwner and hasRole gate", () => {
  assert.equal(cls({ bodySource: "_checkOwner();" }), "GATED");
  assert.equal(cls({ bodySource: "require(hasRole(MINTER_ROLE, msg.sender), \"role\");" }), "GATED");
});

test("an imported modifier with an unknown name needs a read, never REACHABLE", () => {
  assert.equal(cls({ modifiers: ["validPlayer"] }), "NEEDS_READ");
});

// ------------------------------------------------------------------
// BOUNDED — E5, refunds, self-addressed sends
// ------------------------------------------------------------------

test("withdraw of the caller's own accounting is BOUNDED", () => {
  assert.equal(
    cls({
      movesValue: true,
      sendTargets: ["msg.sender"],
      callerOwnedAccounting: true,
      bodySource: "uint amt = balances[msg.sender]; balances[msg.sender] = 0; payable(msg.sender).transfer(amt);",
    }),
    "BOUNDED",
  );
});

test("send to a fixed recipient is BOUNDED", () => {
  assert.equal(
    cls({ movesValue: true, sendTargets: ["treasury"], stateVars: [{ name: "treasury", constOrImmutable: true }] }),
    "BOUNDED",
  );
});

test("send to the contract itself is BOUNDED (Burn self-burn)", () => {
  assert.equal(cls({ movesValue: true, sendTargets: ["address(this)"], callerOwnedAccounting: true }), "BOUNDED");
});

test("per-asset ownership bounds the flow without gating it", () => {
  assert.equal(
    cls({
      movesValue: true,
      sendTargets: ["msg.sender"],
      bodySource: "require(items[id].owner == msg.sender, \"not owner\");",
    }),
    "BOUNDED",
  );
});

// ------------------------------------------------------------------
// REACHABLE — the positives
// ------------------------------------------------------------------

test("unauthenticated full-balance send to the caller is REACHABLE", () => {
  assert.equal(
    cls({ movesValue: true, sendTargets: ["msg.sender"], bodySource: "payable(msg.sender).transfer(address(this).balance);" }),
    "REACHABLE",
  );
});

test("unauthenticated send to a caller-supplied parameter is REACHABLE", () => {
  assert.equal(
    cls({ movesValue: true, sendTargets: ["to"], paramNames: ["to"], bodySource: "to.transfer(address(this).balance);" }),
    "REACHABLE",
  );
});

test("no value flow and no gate is REACHABLE", () => {
  assert.equal(cls({ bodySource: "totalSupply += 1;" }), "REACHABLE");
});

test("isReportable / labels", () => {
  assert.equal(isReportable("REACHABLE"), true);
  assert.equal(isReportable("BOUNDED"), false);
  assert.equal(reachabilityLabel("NEEDS_READ"), "Needs read");
});

// ------------------------------------------------------------------
// FnModel adapter — P9, P10
// ------------------------------------------------------------------

function fn(over: Partial<Parameters<typeof classifyFunction>[0]>) {
  return {
    name: "f",
    visibility: "public",
    mutability: "nonpayable",
    modifiers: [],
    source: "",
    isConstructor: false,
    params: [],
    ...over,
  };
}

test("view function calling token.transfer is not a value mover (P9)", () => {
  const verdict = classifyFunction(fn({ mutability: "view", source: "return token.transfer(to, 1);" }));
  assert.equal(verdict.class, "REACHABLE");
  assert.deepEqual(inferEtherRecipients("return token.transfer(to, 1);"), []);
});

test("super.transfer is not an ether send (P10)", () => {
  assert.deepEqual(inferEtherRecipients("super.transfer(to, amt);"), []);
});

test("ERC-20 transfer with two args is not an ether send", () => {
  assert.deepEqual(inferEtherRecipients("token.transfer(to, amt);"), []);
});

test("a payable drain is inferred as a value mover", () => {
  assert.deepEqual(inferEtherRecipients("payable(msg.sender).transfer(address(this).balance);"), ["payable(msg.sender)"]);
  const verdict = classifyFunction(fn({ source: "payable(msg.sender).transfer(address(this).balance);" }));
  assert.equal(verdict.class, "REACHABLE");
});

test("call{value:} is a value move to its base", () => {
  assert.deepEqual(inferEtherRecipients("to.call{value: amt}(\"\");"), ["to"]);
});

test("owner-gated payable function is GATED even though it moves value", () => {
  const verdict = classifyFunction(
    fn({ modifiers: ["onlyOwner"], source: "payable(msg.sender).transfer(address(this).balance);" }),
  );
  assert.equal(verdict.class, "GATED");
});

// ------------------------------------------------------------------
// Proven vs possible guards (Fix 38 discipline preserved)
// ------------------------------------------------------------------

test("explicit learned names are PROVEN guards; a bare onlyXxx convention is not", () => {
  for (const name of ["ownerOnly", "isPlayer", "hasMintPermission", "treasuryOnly", "oraclizeAction"]) {
    assert.equal(isExplicitGuardModifierName(name), true, `${name} should be a proven guard`);
  }
  // onlyBeacon gates Cub's fix appliers but nobody has read it: POSSIBLE,
  // so the detector caps at high with a note instead of clearing it.
  assert.equal(isExplicitGuardModifierName("onlyBeacon"), false);
  assert.equal(isGuardModifierName("onlyBeacon"), true);
});
