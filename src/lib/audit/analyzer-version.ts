/**
 * What produced a saved record — so "already saved" can mean "already saved by
 * the CURRENT analyzer" rather than "already saved by anything".
 *
 * The pipeline's skip/resume treats a saved (chain, address) as done. That is
 * correct only while the analyzer is unchanged: after the scoring redo, the
 * balance guard, the value-at-risk pass, ABI gathering, SmartPoC, or the
 * SmartBugs alignment, every earlier row is a record of *older* behaviour —
 * its findings, risk score and value are stale, and skipping it preserves the
 * staleness. Storing a stamp on each row makes resume version-aware: a run
 * refreshes exactly what is out of date and still skips the rest.
 *
 * Two mechanisms, deliberately:
 *
 *  - The FINGERPRINT is computed, not written by hand, from the things that
 *    define the analyzer's output: the detector set and its category mapping
 *    (which `npm run check:detectors` already forces to stay complete) and the
 *    scoring model's constants. Add a detector or change a weight and the
 *    fingerprint moves on its own — it cannot silently rot.
 *
 *  - The BASELINE is a hand-bumped string for changes the fingerprint cannot
 *    see: a detector's *logic* being corrected, a prompt or template changing,
 *    a new pipeline stage. Bump it when the same input would now produce a
 *    different record.
 *
 * Its own module with no server imports, so the worker, the browser and the
 * tests all agree on the same stamp.
 */
import { sha3_256 } from "js-sha3";

import { SMARTBUGS_BY_DETECTOR } from "./smartbugs.ts";
import {
  CONFIRMED_EXPLOIT_BONUS,
  MAX_COMPOUND_BONUS,
  MAX_RESNET_BONUS,
  MAX_VOLUME_BONUS,
  SEVERITY_FLOOR,
} from "./risk.ts";

/**
 * Bump when the same input would now produce a different record but the
 * detector set and scoring constants are unchanged.
 *
 * 2026-10-21.1 — scoring model redo (dominance-first), balance guard,
 *                value-at-risk, ABI gathering, SmartPoC, SmartBugs alignment.
 * 2026-10-23.1 — FP-pattern batch from the live-archive poll (Fixes
 *                32-36): solc-metadata + opcode-presence findings
 *                demoted (bytecode DELEGATECALL/SELFDESTRUCT/CALLCODE
 *                presence and compiler-version notes are low, never
 *                critical/high), unparsed regex hits are info,
 *                read-only reentrancy with a getter-only consumer is
 *                low, and the standard proxy upgrade/initialize
 *                surface no longer raises criticals. Same inputs now
 *                produce different records, so the archive refreshes.
 * 2026-10-24.1 — ResNet1D screening runs inside the audit for every
 *                entry (new pipeline stage): the record gains
 *                resnet_json (migration 0018) and risk scores gain
 *                the bounded ML term (MAX_RESNET_BONUS, also hashed
 *                into the fingerprint below). Same inputs now produce
 *                different records, so the archive refreshes.
 * 2026-10-25.2 — Initializer gate (Fix 37): unprotected-initializer
 *                candidates must be externally reachable functions of
 *                a contract (internal/private and library/interface
 *                members no longer flag), the source pattern alone
 *                caps at high, and critical + corroborated require
 *                positive live evidence from the address-path probe
 *                (initializer-gate.ts) — the fork proof showed all
 *                15 stored criticals of this type were false
 *                positives. Same inputs now produce different
 *                records, so the archive refreshes.
 * 2026-10-25.3 — Gate generalization (Fix 38): the Fix 37 discipline
 *                extended to delegatecall, reentrancy and
 *                selfdestruct after fork-proof sweep #2 showed 37/37
 *                stored criticals in those classes were false
 *                positives. Delegatecall sites are judged through
 *                their public entry chain (proven-unreachable sites
 *                drop, fixed/stored targets reclassify low, guards
 *                and unverifiable modifiers on the entries cap);
 *                reentrancy reads the mechanics (failure-rollback
 *                writes are CEI-clean, low gas caps close the window,
 *                hand-rolled mutexes count as guards, fixed-router
 *                payout legs are low) and attributes helper findings
 *                to their public entries; selfdestruct credits deep
 *                custom-modifier checks (onlymanyowners) and
 *                requires external reachability. Source-only: no
 *                finding is newly corroborated. Same inputs now
 *                produce different records, so the archive refreshes.
 * 2026-10-25.4 — Bytecode-family fix (Fix 39): opcode presence is now
 *                instruction-proven — the auxdata tail is stripped by
 *                structural CBOR parsing (iterated, so embedded
 *                contracts' tails go too) and the solc trailing-
 *                constant word is excluded as data — after the
 *                presence proof showed 21/72 stored bytecode-callcode
 *                highs had no CALLCODE instruction at all. DELEGATECALL
 *                and CALLCODE are separate findings whose severity
 *                comes from operand resolution: calldata-derived
 *                target high, fixed constant / proxy-slot target
 *                informational, unresolvable target stays low with
 *                the gap named (delegatecall sample 30/30 and
 *                callcode 72/72 were FP-as-high). SELFDESTRUCT and
 *                metadata severities are NOT recalibrated — presence
 *                correctness only. Same inputs now produce different
 *                records, so the archive refreshes.
 * 2026-10-27.1 — Detection upgrade from the measured engagement (480
 *                hits → 1 real issue, 47% FP rate). Precision: the
 *                learned guard-name list (P7) credits ownerOnly /
 *                hasMintPermission / isPlayer / treasuryOnly /
 *                oraclizeAction as proven access control, while a bare
 *                onlyXxx convention stays a possible guard (cap +
 *                note). Recall: the Team Just five-field block mixer
 *                (R1) and derived-value entropy — a hash of block data
 *                whose OUTPUT is later selected on (R2) — now flag,
 *                with the identifier-only suppression preserved.
 *                Coverage/identity: Blockscout is a second verified-
 *                source registry (C1) and a bytecode-only audit is
 *                labelled analysed, not unreadable (C2), with the
 *                verified name and a label check recorded (C3).
 *                Adjudication: every finding whose function the model
 *                resolves carries a reachability class (Phase 4). Same
 *                inputs now produce different records, so the archive
 *                refreshes.
 * 2026-10-27.2 — 2026 incident classes: six detectors derived from
 *                published post-mortems (hook-callback-auth,
 *                calldata-offset-auth, eoa-only-guard,
 *                public-key-account-trust, unauthenticated-batch-call,
 *                self-attested-auth), each with a modelled Foundry
 *                harness (47-52). New findings on inputs that
 *                previously produced none, so the archive refreshes.
 * 2026-10-27.3 — Games work (plan §3b). The gate now reports its KIND
 *                (GATED_MODIFIER / GATED_REQUIRE / GATED_PRECONDITION /
 *                UNGATED) and a precondition site carries its text, so
 *                "reachable at a cost" stops reading as "unguarded";
 *                contract-only callers are preconditions, not privilege.
 *                Two new detectors: settlement-optionality (D2, the free
 *                option that made BlockChainCasino profitable with sound
 *                randomness) and registry-dispatched-logic (D3, the win rule
 *                lives in a sub-contract and is SEMANTICS_UNVERIFIED until
 *                read). Same inputs now produce different records, so the
 *                archive refreshes.
 * 2026-10-27.4 — Six-year incident sweep (2021-2026). Five detectors for
 *                classes the 2026 wave did not cover: arbitrary-dispatch-call
 *                (Poly Network 2021), bridge-message-auth (Nomad 2022, BNB
 *                2022, KelpDAO 2026), governance-live-voting-power (Beanstalk
 *                2022), ecrecover-zero (the 2021-2022 signature class) and
 *                oracle-staleness (the 2021-2024 price plumbing). Dispatch is
 *                followed through one internal helper, which is the shape Poly
 *                actually used. Same inputs now produce different records, so
 *                the archive refreshes.
 * 2026-10-27.5 — Detection quality (plan items 1-8). Findings now carry a
 *                mechanism family, an evidence-derived confidence basis, and
 *                an economic-claim marker for any published money figure; the
 *                report sorts by severity then reachability, and
 *                sortFindingsForTriage/reportableFindings expose the queue
 *                order. `tx.origin == msg.sender` is no longer read as a
 *                privileged gate (it is the caller, so it is a precondition).
 *                Same inputs now produce different records, so the archive
 *                refreshes.
 * 2026-10-27.6 — LLM output contract. The narrative fields are coerced to
 *                text instead of cast (an object reply used to become
 *                "[object Object]" in the stored narrative and in the next
 *                call's prompt), prose is bounded and marked when truncated,
 *                a missing economic summary says so instead of claiming the
 *                review "completed", test code over the bound or without a
 *                pragma is rejected before a backend run, and the Deep Agent
 *                proposal parser no longer crashes when `hypotheses` is not
 *                an array. Saved AI narratives differ for the same input, so
 *                the archive refreshes.
 * 2026-10-27.7 — The four measured weaknesses. (1) Pre-0.5 call syntax is
 *                normalised: `.call.value(x)()` and `.call.gas(g).value(x)()`
 *                parse as a member access named `value`/`gas`, so the walker
 *                classified them as ordinary member calls and every rule
 *                keyed on kind "call" missed them — reentrancy recall on the
 *                SmartBugs corpus went 0.065 -> 0.710 and precision 0.071 ->
 *                0.407. (2) eth-gas-stipend and locked-ether are info and no
 *                longer vote for denial_of_service. (3) A pre-0.8 arithmetic
 *                rule (compound assignment on stored state with no SafeMath)
 *                took arithmetic recall 0.000 -> 0.867. (4) front-running has
 *                a rule at last (approve race, answer-in-the-mempool) and is
 *                no longer a phantom detector. Same inputs now produce
 *                different records, so the archive refreshes.
 * 2026-10-27.8 — The four DEFERRED classes, implemented. Each is keyed to an
 *                invariant a correct implementation must satisfy rather than to
 *                a shape: share-accounting-double-debit (a share field debited
 *                from a total by two paths and never cleared), shared-unlock-
 *                delta-netting (a callback that takes and settles with no
 *                settled-delta check), idle-gap-interest-accrual (elapsed-blocks
 *                interest whose checkpoint is not advanced on every path) and
 *                signature-field-omission (a digest that omits a parameter
 *                steering value). Also: an ECDSA claim is no longer reported as
 *                an unverified bridge handler. Same inputs now produce
 *                different records, so the archive refreshes.
 * 2026-10-27.9 — The 2026-era incident corpus, and the two bugs it found on its
 *                first run. unchecked-block's pre-0.8 gate compared
 *                versionFloor (encoded 8024 for 0.8.24) against 8_000_000, so
 *                it was always true and the rule fired on modern code where the
 *                compiler already emits the check; self-attested-auth's span ran
 *                from `if (` into the block body and matched
 *                payable(msg.sender).transfer(...), reading a payout as a
 *                self-attestation. Same inputs now produce different records,
 *                so the archive refreshes.
 * 2026-10-27.10 — Recall-first loosening, driven by the real PoCs. The vendored
 *                KolanHook transcript calls accept(), not beforeSwap, so
 *                hook-callback-auth now also fires on an ungated settlement
 *                entry in a hook contract (low confidence); self-attested-auth
 *                accepts the assigned-boolean form; settlement-optionality
 *                accepts a refund-with-timeout plus any unguarded payout;
 *                registry-dispatched-logic accepts a non-parameter index. Same
 *                inputs now produce different records, so the archive refreshes.
 * 2026-10-31.13 — The proxy-shell gate judged the RAW source, so a doc comment could
 *                switch it off. Measured on a fresh 2026-10-30.12 run: 0x38872fad went
 *                29 -> 0 while 0x0c0388e4 stayed at 29, because its flattened body
 *                mentions `selfdestruct(` in a comment and `looksLikeProxyShell`
 *                returned false on that alone — leaving 17 delegatecall and 6
 *                arbitrary-dispatch findings critical on a contract that is a shell.
 *                The gate now judges the comment/string-stripped view, the same one the
 *                selfdestruct detector had to adopt for the identical reason. The
 *                stripper moved to strip-source.ts so both consumers share one copy
 *                instead of two that drift.
 *
 *                Same inputs now produce different records, so the archive refreshes.
 *
 * 2026-10-30.12 — Seven semantic fixes, none of which changed the detector NAME list,
 *                which is why the fingerprint below did not move and why `refresh:
 *                "stale"` kept skipping rows written by the previous build. The
 *                archive held 88 criticals from 2026-10-27.11 that a fresh run no
 *                longer produces:
 *
 *                  selfdestruct        matched `src`, so a COMMENT mentioning
 *                                      selfdestruct( produced a critical — five per
 *                                      contract on an OZ proxy that has none.
 *                  signature-replay    fired on recovery primitives (recoverAddress…
 *                                      tryRecover, checkNSignatures) and on view
 *                                      helpers, which cannot be replayed.
 *                  bridge-message-auth fired on self-service claims paying the caller
 *                                      their own accrued balance.
 *                  delegatecall /      the proxy mechanism itself, now discounted by
 *                  unprotected-admin   the proxy-shell gate.
 *                  arbitrary-dispatch  ignored proven access control; a fixed-caller
 *                                      `if (msg.sender != X) revert` now caps it.
 *                  initializer gate    corroborated criticals against an address with
 *                                      no code, and against a payable fallback that
 *                                      accepts every unknown selector.
 *                  value               a misread token `decimals` of 1 inflated one
 *                                      holding to $26.7B.
 *
 *                Three detectors were also added (vault-inflation-donation,
 *                signature-threshold-no-dedupe, unbacked-mint) and are now registered
 *                in SMARTBUGS_BY_DETECTOR so the fingerprint tracks them.
 *
 *                Same inputs now produce different records, so the archive refreshes.
 */
export const ANALYZER_BASELINE = "2026-10-31.13";

/** A stable digest of the detector set + scoring constants. */
export function analyzerFingerprint(): string {
  const detectors = Object.keys(SMARTBUGS_BY_DETECTOR).sort();
  const material = JSON.stringify({
    detectors,
    categories: detectors.map((d) => SMARTBUGS_BY_DETECTOR[d]),
    scoring: { SEVERITY_FLOOR, MAX_VOLUME_BONUS, CONFIRMED_EXPLOIT_BONUS, MAX_COMPOUND_BONUS, MAX_RESNET_BONUS },
  });
  return sha3_256(material).slice(0, 16);
}

/** The stamp written on every saved record: baseline + fingerprint. */
export function analyzerStamp(): string {
  return `${ANALYZER_BASELINE}+${analyzerFingerprint()}`;
}

/**
 * Is a saved record's stamp out of date? A missing stamp (every row written
 * before this column existed) is stale by definition — that is what makes the
 * first run after this change refresh the whole archive instead of skipping it.
 */
export function isStaleVersion(saved?: string | null): boolean {
  return !saved || saved !== analyzerStamp();
}
