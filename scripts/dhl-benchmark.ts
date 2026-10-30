// scripts/dhl-benchmark.ts — does the analyser flag contracts that were ACTUALLY exploited?
//
//   node --experimental-strip-types scripts/dhl-benchmark.ts <DeFiHackLabs clone> [limit]
//
// The repo (github.com/SunWeb3Sec/DeFiHackLabs) holds 898 Foundry reproductions of real
// DeFi hacks. Each file's header names the vulnerable contract:
//
//   // Vulnerable Contract : 0xBEc591De75b8699A3Ba52F073428822d0Bfc0D7e
//   // Attack Tx : https://etherscan.io/tx/0x...
//
// That is a labelled corpus of contracts that were demonstrably exploitable, which is the
// recall test this analyser has never had. The existing incident-benchmark has 25 cases;
// this has hundreds.
//
// The metric is deliberately label-FREE: "did the analyser raise >= 1 high/critical on a
// contract that was in fact exploited?" No class taxonomy, no judgement call, no way to
// argue with the number. Class-level matching can come later, once the recall figure is
// known.
//
// Known limits, stated rather than discovered:
//   * The reproduction files do not inline the vulnerable source — they fork mainnet and
//     call it through an interface. So the source has to be fetched, and only VERIFIED
//     contracts can be fetched at all. Unverified exploits are skipped and counted.
//   * A hit is not a proof of understanding: a contract can be flagged for an unrelated
//     reason. This measures whether the analyser says anything at all, not whether it
//     says the right thing.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { analyzeAddress, canonicalChainId } from "../src/lib/audit/address-fetcher.ts";

const ADDR = /0x[0-9a-fA-F]{40}/;

/** Explorer host in the Attack Tx URL -> chain id we can fetch. */
const CHAIN_BY_HOST: Record<string, string> = {
  "etherscan.io": "ethereum",
  "bscscan.com": "bsc",
  "arbiscan.io": "arbitrum",
  "basescan.org": "base",
  "polygonscan.com": "polygon",
  "optimistic.etherscan.io": "optimism",
};

type Case = { file: string; vulnerable: string; chain: string; lost: string | null };

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, out);
    else if (name.endsWith("_exp.sol")) out.push(p);
  }
  return out;
}

function parseCase(file: string): Case | null {
  const txt = readFileSync(file, "utf8");
  const head = txt.split("contract ")[0]!.split("interface ")[0]!;
  const vuln = head.match(/\/\/\s*@?Vulnerable Contract\s*:\s*(.+)/)?.[1];
  if (!vuln) return null;
  const addr = vuln.match(ADDR)?.[0];
  if (!addr) return null;
  const tx = head.match(/\/\/\s*@?Attack Tx\s*:\s*(https?:\/\/[^\s]+)/)?.[1] ?? "";
  const host = Object.keys(CHAIN_BY_HOST).find((h) => tx.includes(h)) ?? "etherscan.io";
  const lost = head.match(/\/\/\s*@?KeyInfo\s*-\s*Total Lost\s*:\s*(.+)/)?.[1]?.trim() ?? null;
  return { file, vulnerable: addr.toLowerCase(), chain: CHAIN_BY_HOST[host]!, lost };
}

async function main() {
  const clone = process.argv[2];
  const limit = Number(process.argv[3] ?? 25);
  if (!clone) {
    console.error("usage: node --experimental-strip-types scripts/dhl-benchmark.ts <clone> [limit]");
    process.exit(2);
  }

  const all = walk(join(clone, "src", "test"));
  const cases = all.map(parseCase).filter((c): c is Case => c !== null);
  console.log(`reproductions: ${all.length}   with a named vulnerable contract: ${cases.length}`);

  // Spread the sample across the corpus rather than taking the first N, which would all
  // be from one month.
  const step = Math.max(1, Math.floor(cases.length / limit));
  const sample = cases.filter((_, i) => i % step === 0).slice(0, limit);

  let hit = 0, missed = 0, unfetchable = 0;
  const rows: string[] = [];

  for (const c of sample) {
    const chainId = canonicalChainId(c.chain);
    let verdict: string, detail = "";
    try {
      const { report } = await analyzeAddress(c.vulnerable, chainId);
      const strong = report.findings.filter((f) => f.severity === "critical" || f.severity === "high");
      if (report.findings.length === 0 && !report.inventory?.bytecodeBytes) {
        unfetchable++; verdict = "NO SOURCE";
      } else if (strong.length > 0) {
        hit++; verdict = "FLAGGED";
        detail = `${strong.length}x ${[...new Set(strong.map((f) => f.detector))].slice(0, 2).join(",")}`;
      } else {
        missed++; verdict = "clean";
        detail = `${report.findings.length} lower findings`;
      }
    } catch (err) {
      unfetchable++; verdict = "ERROR";
      detail = (err instanceof Error ? err.message : String(err)).slice(0, 40);
    }
    rows.push(
      `${verdict.padEnd(10)} ${c.vulnerable}  ${c.chain.padEnd(9)} ${(c.lost ?? "").slice(0, 22).padEnd(22)} ${detail}`,
    );
  }

  console.log();
  for (const r of rows) console.log(r);
  console.log();
  const scored = hit + missed;
  console.log(`FLAGGED ${hit} / ${scored} scored  (${scored ? ((100 * hit) / scored).toFixed(0) : 0}%)`);
  console.log(`clean   ${missed}`);
  console.log(`skipped ${unfetchable}  (unverified, unreachable, or unsupported chain)`);
  console.log();
  console.log("A low FLAGGED rate on exploited contracts is the finding: it means the detectors");
  console.log("describe shapes that were NOT what got these contracts drained.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
