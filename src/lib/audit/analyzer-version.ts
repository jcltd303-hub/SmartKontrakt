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
 * 2026-11-01.18 — bridge-message-auth, the three escapes the .17 shape gate left,
 *                measured on a hand-vetted archive pull (10 of 10 stored criticals
 *                in the class were false positives; 1 of the 10 still fired after
 *                .17). (1) A message is DYNAMIC bytes: /^bytes/ also matched
 *                bytes32, which was the whole case against
 *                YieldContract.claimYieldContract(bytes32 _contractId) — a stored
 *                record id, not a payload. (2) namesPeer is scoped to the
 *                function's own contract (its declarations), not the whole
 *                parsed unit — a sibling file's trustedRemote is not this
 *                contract's peer. (3) payoutIsSelfService credits the bound
 *                payee: a require equating a stored owner field with msg.sender,
 *                where every value-out leg pays that same field, is self-service
 *                even though the payee is not textually msg.sender. And the
 *                zero-root half now requires bridge context — a handler-named
 *                function taking a message, a message-taking function consuming
 *                the root, or cross-chain vocabulary in the contract's own
 *                declarations — after MondaiAnimeGirls' whitelist root
 *                (merkleRoot_WL, leaf = keccak(msg.sender)) scored high as a
 *                Nomad shape with no bridge anywhere in the contract. A bare
 *                bytes parameter is not context: every ERC721 safeTransferFrom
 *                override carries one. Five regression fixtures pin each escape
 *                and the surviving Nomad positive. Same inputs now produce
 *                different records, so the archive refreshes.
 * 2026-11-01.19 — Live gates + the detector scoreboard (the improvement batch
 *                Jer approved in full). Every address analysis path in the
 *                fetcher now runs post-passes after value/ABI attachment:
 *                (1) value exposure — unprotected-ether, selfdestruct and
 *                token-drain findings carry the address's LIVE value as
 *                their economicClaim (basis "live"), replacing the
 *                text-figure assumption; a completely-read $0 is stated
 *                as $0, an incomplete $0 is never stated. (2) Live-state
 *                annotations — the decisive reads already probed (owner,
 *                paused) are written into the confidenceBasis of the
 *                findings they bear on; annotation only, no re-scoring.
 *                (3) Scoreboard demotions, when the caller supplies the
 *                archive's track record: a detector running ≥90%
 *                false-positive over ≥20 dispositioned findings has its
 *                criticals capped at high and its high confidence dropped
 *                to medium, with the scoreboard line in confidenceBasis.
 *                Same inputs now produce different records, so the archive
 *                refreshes.
 * 2026-11-01.19 — (2b86fdbf, the parallel claim) reentrancy scored a CRITICAL
 *                on a reserve-then-rollback accumulator. Measured from the
 *                archive: Halo3D.payCharity, E25_Booster.payCharity and
 *                DailyDivs.payFund — one template in three contracts — all
 *                stored critical. Each increments its accumulator BEFORE
 *                the external call and decrements it only in the failure
 *                branch, so a reentrant call observes the reserved value
 *                and the entry require(amount > 1) fails.
 *                rollbackSettledVar already described this exact pattern
 *                in its own summary, but both of its loops gated on
 *                `creditVars` — per-user credit — so an aggregate
 *                accumulator was skipped and the rule fell through to the
 *                generic call-then-write branch at critical. Now every
 *                post-call write must be a failure-only decrement, and the
 *                rolled-back variable is any variable reserved before the
 *                call, whatever it is named. Critical -> low on all three.
 * 2026-11-01.20 — The two .19s above shipped from parallel bases on two
 *                machines (7dd0223b and 2b86fdbf); the second push's copy
 *                of this file also dropped the baseline-ordering helpers
 *                (baselineOf / compareBaselines / isBaselineOlder) that
 *                the stale-worker gate builds on — restored here from
 *                7dd0223b. .20 supersedes both .19 flavors: every .19
 *                stamp reads stale, so the archive refreshes past the
 *                collision. Also in this push: the Sourcify scoping
 *                block is extracted verbatim into the exported pure
 *                scopeSourcifyFiles so the frozen bundle regression
 *                corpus (bundle-scope.test.ts, improvement #10) tests
 *                the exact production scoping. Same inputs now produce
 *                different records, so the archive refreshes.
 *
 * 2026-11-01.17 — bridge-message-auth fired on the NAME `claim`. Measured on a real
 *                archive pull: LootChubby.claim(uint256 tokenId) — an NFT claim bounded
 *                by a supply cap and an id range — scored the only CRITICAL in 136
 *                findings. It takes no message: no bytes, no chain id, no proof. The
 *                name was in BRIDGE_HANDLER and `_mint` was in BRIDGE_EFFECT, which was
 *                the entire case.
 *
 *                A cross-chain handler by definition receives a message, so the rule now
 *                requires one: a bytes/bytes32 parameter, or a contract naming a
 *                peer/remote/endpoint. Nomad, Qubit and KelpDAO all take a payload.
 *
 *                The old test asserted this false positive as correct behaviour
 *                ("minting to the caller still fires"), so it was rewritten — a fixture
 *                that encodes a bug keeps it alive.
 *
 *                Same inputs now produce different records, so the archive refreshes.
 *
 * 2026-10-31.16 — New detector: liquidation-without-health-check.
 *
 *                It encodes the soda-2020 INVARIANT ("collateral seized exceeds amount
 *                authorized by an independent position-health model"), not that incident's
 *                mechanism — the source material marks the mechanism provisional and asks
 *                for primary-code verification, so a detector built on it would be
 *                inventing. sushiswap-2020 is not implemented at all: its cited source
 *                describes an exploit that was FOILED, and the class it names is already
 *                covered by fee-on-transfer and strict-balance.
 *
 *                The rule is deliberately narrow: an externally callable liquidation-style
 *                function that moves collateral, carries NO modifier, calls nothing
 *                health-shaped, and sits in a contract with no health helper either.
 *                `onlyUnderwater` / `isUnderwater` proved that chasing synonyms produces
 *                false positives, so any modifier suppresses the finding instead.
 *
 *                Same inputs now produce different records, so the archive refreshes.
 *
 * 2026-10-31.15 — Probe answers are now bound to the code they describe. Ported from the
 *                Perplexity incident harness (createIncidentModule), whose detect() refuses
 *                any probe result whose runtimeSha256 does not match the one it recorded.
 *
 *                initializer-gate: the runtime code is hashed before probing and re-read
 *                after. If it changed, every corroboration made in that window is
 *                withdrawn and the finding returns to high, uncorroborated, with a note.
 *                InitializerGateOutcome now carries codeHash and codeChanged.
 *
 *                live-state: the probe refuses to run when there is no runtime code (a
 *                getter "failure" against a codeless address is not evidence — the same
 *                mistake as corroborating an initializer against one), and
 *                LiveStateReport.codeHash records which code its reads belong to.
 *
 *                Neither change alters what the detectors match, but both alter which
 *                records carry live evidence, so the archive refreshes.
 *
 * 2026-10-31.14 — The analysis was not scoped to the deployed contract. Sourcify returns
 *                every file in the COMPILATION UNIT, and `fetchSourcifySource` joined
 *                them all. 0x0c0388e4 is an ERC1967Proxy — a few hundred bytes — whose
 *                bundle is 91,621 characters, because that unit also contained
 *                @openzeppelin/upgrades-core's deliberately-unsafe TEST FIXTURES:
 *                HasSelfDestructNatspec1/2/3 (function d), explode, extremelyUnsafe,
 *                publicDelegateCall, externalDelegateCall, internalDelegateCall,
 *                privateDelegateCall, _functionDelegateCall. All 29 of its criticals
 *                were fixtures; the deployed contract was not among them.
 *
 *                The fetch now reads `compilation.fullyQualifiedName` — Sourcify's own
 *                statement of which contract it verified — and analyses only that
 *                contract's import closure. This also explains the earlier finding that
 *                landed on a contract which did not contain the function.
 *
 *                Same inputs now produce different records, so the archive refreshes.
 *
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
 * 2026-11-06.24 — Ledger-driven detector calibration (Fixes 39-44), from the
 *                6,831-row adjudicated vet ledger (rounds 1-5, every stored
 *                critical/high fork- or live-probed). New detector:
 *                pseudo-constructor (SWC-118) — a function named as (or
 *                nearly as) its contract that the compiler does not treat
 *                as a constructor (ALIVA's AlivaToken, fork-confirmed:
 *                repeatable owner takeover + mint). tx-origin: the
 *                != EOA-gate form (TinfunReserve's onlyEOA) now strips
 *                like the == form, and EOA-gate findings are info, not
 *                low (239 rows, 0 confirmed). read-only-reentrancy: a
 *                state-changing in-window consumer that does not feed a
 *                value decision demotes high → info (453 rows, 0
 *                confirmed). delegatecall: fixed target + fixed calldata
 *                is info; a fixed/const target with caller-supplied
 *                calldata is high (the old const → medium tier retired;
 *                679 rows, 0 confirmed). unchecked-call: severity lowered
 *                one notch across the board (210 rows, 0 confirmed).
 *                erc20-unchecked: a state write after the unchecked
 *                transfer raises confidence to high and blocks the
 *                Fix 25 downgrade (the WBTCSwap/ZRX shape — the one
 *                shape in 1,347 rows that produced confirmed exploits).
 *                Same inputs now produce different records, so the
 *                archive refreshes. (This bump also re-pins the
 *                detector-source digest, which had drifted stale on
 *                main through the 2026-11-02..06 detector commits.)
 * 2026-11-06.25 — SWC coverage batch, first half (Fixes 45-51): the
 *                registry classes the engine had no rule for. Fix 45:
 *                old-compiler re-stamped SWC-101 → SWC-102 (it IS the
 *                outdated-compiler finding; 101 belongs to
 *                unchecked-block). New detectors: state-var-default-
 *                visibility (SWC-108), uninitialized-storage-pointer
 *                (SWC-109 — the CryptoRoulette shape, version-gated to
 *                pre-0.5 where the compiler allows it),
 *                deprecated-solidity (SWC-111), dos-failed-call
 *                (SWC-113), dos-block-gas-limit (SWC-128, the source
 *                shape next to bytecode gas-estimator-dos) and
 *                unused-variable (SWC-131, state variables and function
 *                parameters). All six registered in smartbugs.ts and
 *                detector-registry.ts. The remaining registry classes
 *                (SWC-110, 123, 125, 126, 127, 129, 135) are specced in
 *                the coverage brief for a follow-up batch. Same inputs
 *                now produce different records, so the archive
 *                refreshes.
 * 2026-11-06.26 — SWC coverage batch, second half (Fixes 52-58),
 *                implementing the brief the .25 entry pointed at:
 *                assert-violation (SWC-110, caller-controlled or
 *                tautological assert conditions), requirement-
 *                violation (SWC-123, constant or self-comparing
 *                require — the two provable shapes only),
 *                inheritance-order (SWC-125, contested in-source base
 *                functions the derived contract does not override),
 *                gas-griefing (SWC-126, unstipulated call followed by
 *                state bookkeeping — a bare require after the call was
 *                excluded after the corpus flagged OZ's sendValue),
 *                typographical-error (SWC-129, =+ / =- in an
 *                accumulator context only — the bare pattern is a
 *                false-positive fountain), function-type-jump
 *                (SWC-127, function-type variable + inline assembly,
 *                presence-class) and code-no-effects (SWC-135, an AST
 *                rule in walkFn: a statement that computes and
 *                discards). All seven registered in smartbugs.ts and
 *                detector-registry.ts. With this batch every SWC id
 *                100-136 carries a detector or a stamped finding.
 *                Same inputs now produce different records, so the
 *                archive refreshes.
 * 2026-11-07.27 — Benchmark-driven batch (Fixes 59-60), from the
 *                SmartBugs Curated run against .26 (143 contracts,
 *                207 labeled instances): SWC-118 recall was 1 of 5
 *                exemplars and SWC-124 had no source-level rule at
 *                all. Fix 59 widens pseudo-constructor: containment
 *                (IamMissing in Missing, initWallet in Wallet), a
 *                function literally named Constructor, creator added
 *                to the gate's privileged set (rubixi, wallet_03),
 *                and the absent-constructor shape — pre-0.5, no
 *                constructor in the contract or its in-source bases
 *                — at one tier below the name-matched shapes,
 *                privileged assignment required. Corpus refinements:
 *                the name shapes require NO working constructor
 *                (Dust's convertEtherToDust / convertDustToEther are
 *                ordinary converters in a contract with a real
 *                `function Dust()`), the constructor test is
 *                case-sensitive like the compiler's (missing() in
 *                Missing stays caught), and a weak hit is withdrawn
 *                when the function delegates through super to an
 *                authed base initializer (Marketplace → registry-
 *                gated Upgradeable.initialize). SWC-118 is now 5/5
 *                on the exemplars; the corpus smoke over the round
 *                4/5 vet sources (4,291 files) yields exactly ALIVA
 *                plus two true shapes the widening was built for —
 *                HGToken's `Constructor` in Owned and VoipToken's
 *                typo'd VoipTken. Fix 60 adds arbitrary-storage-write
 *                (SWC-124, source level): a state-array element write
 *                through a parameter-derived index where the array's
 *                length is directly mutable from unauthenticated
 *                code (grown to fit the key — mapping_write — or
 *                decremented toward underflow —
 *                arbitrary_location_write_simple). Mapping writes,
 *                bounded setters with an immovable length, constant
 *                indices, authed functions and member-of-element
 *                writes stay silent; 0 corpus hits. Benchmark after:
 *                Pass A 94.2% → 94.7%, Pass B 93.6% → 94.6%, SWC-124
 *                0 → 2 of 2 exemplars. Same inputs now produce
 *                different records, so the archive refreshes.
 * 2026-11-08.28 — Fix 61: the pre-0.8 arithmetic rule
 *                (unchecked-block, SWC-101) gains its third
 *                shape — the BECToken product. A raw
 *                multiplication of caller-controlled inputs
 *                into a LOCAL that a guard afterwards checks:
 *                batchTransfer computes amount = cnt * _value
 *                and requires balances[msg.sender] >= amount,
 *                so the require validates the WRAPPED product
 *                while each receiver is credited the full
 *                _value. The rule's two older shapes cannot see
 *                it (no compound assignment on stored state —
 *                the balance updates are plain `=`; the require
 *                is a balance comparison, not a subtraction
 *                guard). Caller-controlled means a parameter,
 *                msg.value, a parameter array's .length, or a
 *                local assigned from one of those (cnt =
 *                _receivers.length). SafeMath elsewhere in the
 *                function does NOT disarm — BECToken's balances
 *                are .sub()/.add()-guarded and the product wraps
 *                first; what disarms is checked arithmetic on
 *                the product itself (a .mul computation, or a
 *                guard that divides the product back by an
 *                operand — SafeMath.mul's require(c / a == b),
 *                which keeps every vendored SafeMath silent).
 *                Literal and named-constant products, `**`
 *                exponent terms, products nobody guard-reads,
 *                view/pure/constant functions and post-0.8 code
 *                stay silent; the shape reports only when the
 *                older shapes did not, so a function yields at
 *                most one unchecked-block finding. SmartBugs
 *                Curated: BECToken gains SWC-101 at its labeled
 *                line (264); SWC-101 21/23 → 22/23 (the
 *                remaining miss is the dataset's benign variant,
 *                a true negative); Pass A 94.7% → 95.2%,
 *                Pass B 94.6% → 95.1%, no category regressed.
 *                Corpus smoke over the round-4/5 vet sources
 *                (4,291 files: 4,221 parsed, 67 pre-existing
 *                parse skips, 3 Predeploys.sol heap-OOMs
 *                identical on the .27 baseline, 0 detector
 *                exceptions): the older shapes are unchanged at
 *                1,278 SWC-101 hits and the product shape adds
 *                exactly 7 — four distinct functions (a
 *                crowdsale buy, the ERC20CrowdsaleToken
 *                buyTokens template ×3, a fee setter whose
 *                require equates msg.value with the product
 *                ×2, and a fallback that is the archetype
 *                verbatim: amount = msg.value * buyPrice,
 *                require(balances[owner] >= amount)). Same
 *                inputs now produce different records, so the
 *                archive refreshes.
  * 2026-11-09.29 — Fix 62: the walkFn IfStatement branch merge
 *                OOM. Both branch snapshots start as copies of
 *                the pre-if flow, so left and right already
 *                contain every pre-branch read/send/call; the
 *                merge concatenated before + left + right,
 *                tripling the pre-branch entries at every if
 *                (~3^k growth over k sequential ifs in the
 *                readLines / sendTargets / sendDetails /
 *                calleeCalls lists). ConfidentialPool._settle
 *                (dozens of sequential ifs over 83 state vars)
 *                grew those lists past a 4GB heap and killed
 *                the analyzer with no result — the contract
 *                could not be scanned at all. The merge now
 *                unions the two branch results with dedupe;
 *                every consumer of these lists is
 *                multiplicity-insensitive (some/every/find), so
 *                findings are unchanged — only the memory is
 *                bounded. ConfidentialPool now completes:
 *                40 findings at the report cap, ~113MB heap.
 *                (This bump also re-pins the detector-source
 *                digest, which the caller-supplied-identity
 *                commit left stale.) Same inputs now produce
 *                records where the process previously died, so
 *                the archive refreshes.
 */
export const ANALYZER_BASELINE = "2026-11-09.29";

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

/** The baseline part of a stamp (or a bare baseline): text before \"+\". */
export function baselineOf(stamp?: string | null): string | null {
  if (!stamp) return null;
  const base = stamp.split("+")[0]?.trim();
  return base ? base : null;
}

/**
 * Order two baselines (\"2026-11-01.18\"). The date part is zero-padded ISO,
 * so it compares lexicographically; the counter after the last dot compares
 * numerically (\".9\" < \".10\"). Returns -1 / 0 / 1, or null when either side
 * is not a recognizable baseline — callers treat null as \"cannot judge\",
 * never as \"older\".
 */
export function compareBaselines(a?: string | null, b?: string | null): number | null {
  const parse = (s?: string | null): { date: string; n: number } | null => {
    const base = baselineOf(s);
    if (!base) return null;
    const dot = base.lastIndexOf(".");
    if (dot < 0) return null;
    const n = Number.parseInt(base.slice(dot + 1), 10);
    if (!Number.isFinite(n)) return null;
    return { date: base.slice(0, dot), n };
  };
  const pa = parse(a);
  const pb = parse(b);
  if (!pa || !pb) return null;
  if (pa.date !== pb.date) return pa.date < pb.date ? -1 : 1;
  if (pa.n !== pb.n) return pa.n < pb.n ? -1 : 1;
  return 0;
}

/** True when baseline `own` is strictly older than baseline `other`. */
export function isBaselineOlder(own?: string | null, other?: string | null): boolean {
  const cmp = compareBaselines(own, other);
  return cmp !== null && cmp < 0;
}
