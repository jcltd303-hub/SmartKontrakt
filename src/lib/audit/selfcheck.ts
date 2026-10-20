// Explicit `.ts` extensions: this file is run directly by Node's type-stripping
// test runner (`npm run check:detectors`), which requires ESM-visible extensions.
import { analyzeInput } from "./engine.ts";
import { SAMPLES } from "./samples.ts";

function must(label: string, detectors: string[], forbidden: string[] = []) {
  const sample = SAMPLES.find((s) => s.label === label);
  if (!sample) throw new Error(`missing sample ${label}`);
  const report = analyzeInput(sample.body, sample.label);
  const have = new Set(report.findings.map((f) => f.detector));
  const missing = detectors.filter((d) => !have.has(d));
  const bad = forbidden.filter((d) => have.has(d));
  if (missing.length || bad.length) {
    console.error(label, "score", report.riskScore);
    console.error(
      "have",
      report.findings.map((f) => `${f.severity}:${f.detector}:${f.title}`),
    );
    console.error("missing", missing, "forbidden", bad);
    process.exit(1);
  }
  console.log(label, "ok", report.findings.length, "score", report.riskScore);
}

must("RelicVault", [
  "reentrancy",
  "read-only-reentrancy",
  "delegatecall",
  "tx-origin",
  "old-compiler",
  "floating-pragma",
  "unprotected-ether",
  "eth-gas-stipend",
  "balance-as-price",
]);

must("PermitDesk", [
  "unprotected-initializer",
  "encode-packed",
  "signature-malleability",
  "signature-replay",
  "reentrancy",
  "oracle-spot",
  "div-before-mul",
  "floating-pragma",
]);

must("GuardedVault", ["centralization"], ["reentrancy", "old-compiler", "delegatecall", "tx-origin", "unprotected-ether"]);

must("Hostile runtime", ["bytecode-selfdestruct", "bytecode-delegatecall", "bytecode-origin", "bytecode-unchecked-call"]);

const proxy = analyzeInput(SAMPLES.find((s) => s.id === "proxy")!.body, "proxy");
if (!proxy.inventory.proxy?.includes("EIP-1167")) {
  console.error("proxy not detected", proxy.inventory.proxy, proxy.inventory.notes);
  process.exit(1);
}
if (!proxy.inventory.selectors.length && !proxy.inventory.proxy) {
  console.error("empty proxy inference");
  process.exit(1);
}
console.log("proxy ok", proxy.inventory.proxy);
console.log("selfcheck passed");
