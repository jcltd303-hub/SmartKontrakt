import test from "node:test";
import assert from "node:assert/strict";

import { analyzeInput } from "./engine.ts";
import { SMARTBUGS_BY_DETECTOR } from "./smartbugs.ts";
import type { Finding } from "./types.ts";

/**
 * The six-year incident corpus: 2021-2026.
 *
 * Every entry is a real loss with a published root cause, minimised to the
 * decisive structure. The point is not that each contract is byte-identical to
 * the original — it is that the MECHANISM that lost the money is the mechanism
 * the detector fires on, so a future rule change that breaks one is told which
 * incident it re-breaks.
 *
 * Three expectations, and the third one matters as much as the first two:
 *   "fires"           — a rule covers the class; the fixture must trip it.
 *   "clean"           — a control: the correct implementation must NOT trip it.
 *   "documented-only" — no source rule can see this class (key compromise,
 *                       frontend supply chain, social engineering, a compiler
 *                       bug, a Rust program bug, share-accounting logic). The
 *                       corpus records it with the reason instead of pretending
 *                       to cover it.
 *
 * Sources for the mechanisms are in docs/incidents-2021-2026.md.
 */

type Entry = {
  year: 2021 | 2022 | 2023 | 2024 | 2025 | 2026;
  incident: string;
  loss: string;
  /** Detector expected to fire, or null for documented-only. */
  detector: string | null;
  expect: "fires" | "clean" | "documented-only";
  mechanism: string;
  reason?: string;
  source?: string;
};

const ENTRIES: Entry[] = [
  // ------------------------------------------------------------------
  // 2021
  // ------------------------------------------------------------------
  {
    year: 2021,
    incident: "Poly Network",
    loss: "$611M",
    detector: "arbitrary-dispatch-call",
    expect: "fires",
    mechanism:
      "EthCrossChainManager validated a message then handed a caller-supplied target + method to _executeCrossChainTx, which called it",
    source: `pragma solidity ^0.8.0;
contract EthCrossChainManager {
    address public owner;
    function verifyHeaderAndExecuteTx(
        address contractAddr,
        string memory method,
        bytes memory args,
        bytes memory proof
    ) external {
        // proof / header validation passed in the real exploit
        _executeCrossChainTx(contractAddr, method, args);
    }
    function _executeCrossChainTx(address contractAddr, string memory method, bytes memory args) internal {
        bytes4 sel = bytes4(keccak256(abi.encodePacked(method, "(bytes,bytes,uint64)")));
        (bool ok,) = contractAddr.call(abi.encodeWithSelector(sel, args, args, uint64(0)));
        require(ok, "exec failed");
    }
}`,
  },
  {
    year: 2021,
    incident: "Cream Finance",
    loss: "$130M",
    detector: "reentrancy",
    expect: "fires",
    mechanism: "ERC-777 tokensReceived hook re-entered the borrow path before collateral was booked",
    source: `pragma solidity ^0.8.0;
interface IERC777 { function send(address to, uint256 amount, bytes calldata data) external; }
contract CreamMarket {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrowed;
    IERC777 public amp;
    function borrow(uint256 amount) external {
        require(collateral[msg.sender] >= amount, "collateral");
        amp.send(msg.sender, amount, "");      // callback fires here
        borrowed[msg.sender] += amount;
    }
}`,
  },
  {
    year: 2021,
    incident: "Yearn yDAI vault",
    loss: "$11M",
    detector: "oracle-spot",
    expect: "fires",
    mechanism: "the strategy priced assets from a live Curve pool balance rather than a TWAP",
    source: `pragma solidity ^0.8.0;
interface ICurvePool { function getReserves() external view returns (uint256, uint256, uint256); }
contract YDaiStrategy {
    ICurvePool public pool;
    uint256 public lastReport;
    function harvest() external {
        (uint256 r0, uint256 r1,) = pool.getReserves(); // spot, movable in one block
        lastReport = (r1 * 1e18) / r0;
    }
}`,
  },

  // ------------------------------------------------------------------
  // 2022
  // ------------------------------------------------------------------
  {
    year: 2022,
    incident: "Nomad Bridge",
    loss: "$190M",
    detector: "bridge-message-auth",
    expect: "fires",
    mechanism: "an upgrade initialised committedRoot to 0x00, so every proof verified and process() became public",
    source: `pragma solidity ^0.8.0;
library MerkleLib { function verify(bytes32[32] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) { return true; } }
contract NomadReplica {
    bytes32 public committedRoot;
    function process(bytes32 leaf, bytes32[32] calldata proof) external {
        require(MerkleLib.verify(proof, committedRoot, leaf), "!prove");
        payable(msg.sender).transfer(1 ether);
    }
}`,
  },
  {
    year: 2022,
    incident: "Beanstalk Farms",
    loss: "$182M",
    detector: "governance-live-voting-power",
    expect: "fires",
    mechanism: "emergencyCommit read voting weight from the live Silo balance, so a flash loan rented a 2/3 majority in one transaction",
    source: `pragma solidity ^0.8.0;
interface ISilo { function balanceOf(address) external view returns (uint256); function totalSupply() external view returns (uint256); }
contract GovernanceFacet {
    ISilo public silo;
    mapping(uint256 => uint256) public votesFor;
    mapping(uint256 => uint256) public proposedAt;
    function emergencyCommit(uint256 bip) external {
        require(block.timestamp >= proposedAt[bip] + 1 days, "too early");
        // live weight: a deposit made seconds ago counts exactly like a deposit held for months
        require(votesFor[bip] * 3 >= silo.totalSupply() * 2, "super majority");
        _execute(bip);
    }
    function _execute(uint256) internal {}
}`,
  },
  {
    year: 2022,
    incident: "BNB Bridge (BSC Token Hub)",
    loss: "$586M",
    detector: "bridge-message-auth",
    expect: "fires",
    mechanism: "a forged IAVL proof released funds: the handler trusted a caller-supplied proof with no root/peer anchor",
    source: `pragma solidity ^0.8.0;
contract TokenHub {
    mapping(address => uint256) public balances;
    function handlePackage(bytes calldata payload, bytes calldata proof) external {
        // the proof is accepted with no anchor: no stored root, no source chain, no peer
        require(proof.length > 0, "proof");
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        balances[to] += amount;
        payable(to).transfer(amount);
    }
}`,
  },
  {
    year: 2022,
    incident: "Mango Markets",
    loss: "$114M",
    detector: "oracle-spot",
    expect: "fires",
    mechanism: "the perp market's price was taken from a thin order book the attacker moved with their own positions",
    source: `pragma solidity ^0.8.0;
interface IPerpMarket { function getReserves() external view returns (uint256, uint256, uint256); }
contract MangoMargin {
    IPerpMarket public perp;
    mapping(address => uint256) public collateralValue;
    function borrow(uint256 amount) external {
        (uint256 base, uint256 quote,) = perp.getReserves(); // attacker-movable price
        collateralValue[msg.sender] = (quote * 1e18) / base;
        require(collateralValue[msg.sender] > amount, "undercollateralised");
    }
}`,
  },
  {
    year: 2022,
    incident: "Qubit Finance",
    loss: "$80M",
    detector: null,
    expect: "documented-only",
    mechanism: "the deposit path accepted a zero-amount / unvalidated token deposit and minted qXETH against it",
    reason:
      "The entry point is a plain deposit(), not an inbound-message handler, so bridge-message-auth deliberately does not match it — widening the handler vocabulary to cover deposit() would fire on every vault in existence. The class is 'missing input validation on a mint path', which no current rule owns.",
  },
  {
    year: 2022,
    incident: "Wormhole",
    loss: "$326M",
    detector: null,
    expect: "documented-only",
    mechanism: "a Solana program skipped a sysvar/account-ownership check in guardian signature verification",
    reason: "Rust program bug on Solana; outside a Solidity source analyzer entirely.",
  },

  // ------------------------------------------------------------------
  // 2023
  // ------------------------------------------------------------------
  {
    year: 2023,
    incident: "Euler Finance",
    loss: "$197M",
    detector: "balance-as-price",
    expect: "fires",
    mechanism: "donateToReserves let the attacker burn collateral without reducing debt, then liquidate the undercollateralised position",
    source: `pragma solidity ^0.8.0;
contract EulerVault {
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public debt;
    uint256 public totalReserves;
    // The health check prices collateral off balances the donation below moves.
    function collateralPrice(address who) external view returns (uint256) {
        return (address(this).balance + totalReserves) / (balanceOf[who] + 1);
    }
    function donateToReserves(uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        totalReserves += amount;
    }
    function liquidate(address who) external {
        require(collateralPrice(who) < debt[who], "healthy");
        balanceOf[who] = 0;
    }
}`,
  },
  {
    year: 2023,
    incident: "KyberSwap",
    loss: "$47M",
    detector: "div-before-mul",
    expect: "fires",
    mechanism: "concentrated-liquidity tick math rounded in the attacker's favour, doubling the position each swap",
    source: `pragma solidity ^0.8.0;
contract KyberElastic {
    uint256 public price;
    function swap(uint256 amountIn) external returns (uint256 out) {
        out = (amountIn / price) * 1e18;      // divide then multiply: precision loss
        price = price - 1;
    }
}`,
  },
  {
    year: 2023,
    incident: "BonqDAO",
    loss: "$120M",
    detector: "oracle-spot",
    expect: "fires",
    mechanism: "the collateral price came from a single manipulable source, so a donated price spike minted unbacked debt",
    source: `pragma solidity ^0.8.0;
interface ITellor { function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80); }
contract Bonq {
    ITellor public oracle;
    mapping(address => uint256) public debt;
    function mint(uint256 amount) external {
        (, int256 answer,,,) = oracle.latestRoundData(); // single manipulable source
        require(answer > 0, "price");
        debt[msg.sender] += amount; // the price is the only collateral check
    }
}`,
  },
  {
    year: 2023,
    incident: "Curve Finance (Vyper)",
    loss: "$70M",
    detector: null,
    expect: "documented-only",
    mechanism: "a Vyper compiler bug (0.2.15-0.3.0) assigned different storage slots to the reentrancy locks, so the guard never engaged",
    reason:
      "The SOURCE was correct — the compiled bytecode was not. No source analyzer can flag it; the fix is a compiler-version policy, which is what old-compiler/floating-pragma already report as hygiene.",
  },

  // ------------------------------------------------------------------
  // 2024
  // ------------------------------------------------------------------
  {
    year: 2024,
    incident: "Shezmu",
    loss: "$4.9M",
    detector: "unprotected-initializer",
    expect: "fires",
    mechanism: "a proxy's initialize() was callable by anyone, so the attacker took the implementation's ownership",
    source: `pragma solidity ^0.8.0;
contract ShezmuVault {
    address public owner;
    bool private initialized;
    function initialize(address _owner) external {
        owner = _owner;
        initialized = true;
    }
}`,
  },
  {
    year: 2024,
    incident: "Radiant Capital",
    loss: "$50M",
    detector: null,
    expect: "documented-only",
    mechanism: "malware on signer machines let the attacker submit a malicious multisig payload that looked benign in the UI",
    reason: "Off-chain signing-infrastructure compromise; nothing in the contract source distinguishes the payload.",
  },
  {
    year: 2024,
    incident: "Orbit Chain / Orbit Bridge",
    loss: "$82M",
    detector: null,
    expect: "documented-only",
    mechanism: "compromised MPC/validator signing keys authorised withdrawals",
    reason: "Key compromise. A source rule can flag a low validator threshold (centralization), not a stolen key.",
  },
  {
    year: 2024,
    incident: "Hedgey Finance",
    loss: "$45M",
    detector: null,
    expect: "documented-only",
    mechanism: "claim/refund accounting let a caller withdraw more than the position held",
    reason:
      "Per-position share accounting across two functions — the class this repo deliberately left to a human read (see docs/recent-exploits-2026.md), because a pattern match on share debits fires on every correct vault.",
  },

  // ------------------------------------------------------------------
  // 2025
  // ------------------------------------------------------------------
  {
    year: 2025,
    incident: "Bybit",
    loss: "$1.46B",
    detector: null,
    expect: "documented-only",
    mechanism: "the Safe{Wallet} frontend was compromised so signers approved a delegatecall substitution",
    reason: "Supply-chain / UI compromise. The signed transaction was malicious; the contract behaved correctly.",
  },
  {
    year: 2025,
    incident: "Cetus",
    loss: "$223M",
    detector: "unchecked-block",
    expect: "fires",
    mechanism: "an arithmetic overflow in concentrated-liquidity math (Move in reality; the Solidity shape is an unchecked multiply)",
    source: `pragma solidity ^0.8.0;
contract CetusClmm {
    uint256 public sqrtPrice;
    function swap(uint256 amountIn) external returns (uint256) {
        unchecked {
            uint256 delta = amountIn * sqrtPrice; // wraps instead of reverting
            sqrtPrice = sqrtPrice + delta;
            return delta;
        }
    }
}`,
  },
  {
    year: 2025,
    incident: "Cork Protocol",
    loss: "$12M",
    detector: "hook-callback-auth",
    expect: "fires",
    mechanism: "CorkHook.beforeSwap never checked msg.sender was the PoolManager, so a direct call ran the FlashSwap decomposition",
    source: `pragma solidity ^0.8.4;
interface IPoolManager { function take(address, address, uint256) external; }
contract CorkHook {
    IPoolManager public poolManager;
    function beforeSwap(address sender, bytes calldata key, bytes calldata params, bytes calldata hookData)
        external
        returns (bytes4, int128, uint24)
    {
        uint256 amount = abi.decode(hookData, (uint256));
        poolManager.take(address(0), sender, amount);
        return (this.beforeSwap.selector, int128(uint128(amount)), 0);
    }
}`,
  },
  {
    year: 2025,
    incident: "Abracadabra Money",
    loss: "$13M",
    detector: "reentrancy",
    expect: "fires",
    mechanism: "a GMX cauldron integration re-entered before the position's debt was written",
    source: `pragma solidity ^0.8.0;
interface IGmxRouter { function claimFees() external; }
contract Cauldron {
    IGmxRouter public router;
    mapping(address => uint256) public debt;
    function borrow(uint256 amount) external {
        router.claimFees();            // external call first
        debt[msg.sender] += amount;    // booked after
        payable(msg.sender).transfer(amount);
    }
}`,
  },

  // ------------------------------------------------------------------
  // 2026 (already covered by the previous commits; pinned here so the
  // six-year table is complete and one edit cannot silently drop a year)
  // ------------------------------------------------------------------
  {
    year: 2026,
    incident: "BlockChainCasino",
    loss: "free option",
    detector: "settlement-optionality",
    expect: "fires",
    mechanism: "settle a win, refund a loss after BET_EXPIRATION_BLOCKS; nothing forces settlement",
    source: `pragma solidity ^0.8.0;
contract BlockChainCasino {
    uint256 public constant BET_EXPIRATION_BLOCKS = 250;
    mapping(address => uint256) public stakeOf;
    mapping(address => uint256) public placedAt;
    function placeBet(bytes32 commit) external payable {
        stakeOf[msg.sender] = msg.value;
        placedAt[msg.sender] = block.number;
    }
    function settleBet(bytes32 reveal) external {
        uint256 amount = stakeOf[msg.sender];
        delete stakeOf[msg.sender];
        payable(msg.sender).transfer(amount * 2);
    }
    function refundBet() external {
        require(block.number > placedAt[msg.sender] + BET_EXPIRATION_BLOCKS, "too early");
        uint256 amount = stakeOf[msg.sender];
        delete stakeOf[msg.sender];
        payable(msg.sender).transfer(amount);
    }
}`,
  },
  {
    year: 2026,
    incident: "AlpsCon AI Trade Hub",
    loss: "$152.8k",
    detector: "public-key-account-trust",
    expect: "fires",
    mechanism: "the reward gate whitelisted the canonical Hardhat account, whose private key is published",
    source: `pragma solidity ^0.8.0;
contract AlpsConRewardHub {
    mapping(address => bool) public onlyVerified;
    constructor() {
        onlyVerified[0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266] = true;
    }
    function claim() external {
        require(onlyVerified[msg.sender], "not verified");
    }
}`,
  },

  // ------------------------------------------------------------------
  // Class fixtures: mechanisms whose incident is a family, not one name.
  // ------------------------------------------------------------------
  {
    year: 2022,
    incident: "ecrecover-zero (2021-2022 signature class)",
    loss: "family",
    detector: "ecrecover-zero",
    expect: "fires",
    mechanism: "ecrecover returns address(0) on a malformed signature, and the code compares it without rejecting zero",
    source: `pragma solidity ^0.8.0;
contract ClaimDesk {
    address public signer;
    mapping(address => bool) public claimed;
    function claim(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(msg.sender, amount));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered == signer, "bad signature");
        claimed[msg.sender] = true;
        payable(msg.sender).transfer(amount);
    }
}`,
  },
  {
    year: 2023,
    incident: "oracle-staleness (2021-2024 price plumbing)",
    loss: "family",
    detector: "oracle-staleness",
    expect: "fires",
    mechanism: "latestRoundData is consumed without updatedAt/answeredInRound, so a halted feed keeps pricing collateral",
    source: `pragma solidity ^0.8.0;
interface IFeed { function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80); }
contract LendingPool {
    IFeed public feed;
    mapping(address => uint256) public collateral;
    function borrow(uint256 amount) external {
        (, int256 answer,,,) = feed.latestRoundData();
        require(uint256(answer) > 0, "price");
        collateral[msg.sender] = uint256(answer);
        require(collateral[msg.sender] > amount, "undercollateralised");
    }
}`,
  },

  // ------------------------------------------------------------------
  // Controls — the correct implementation must stay quiet.
  // ------------------------------------------------------------------
  {
    year: 2025,
    incident: "control: a dispatcher with an allowlist",
    loss: "-",
    detector: "arbitrary-dispatch-call",
    expect: "clean",
    mechanism: "the target is allowlisted before dispatch",
    source: `pragma solidity ^0.8.0;
contract SafeRouter {
    mapping(address => bool) public allowedTarget;
    function dispatch(address target, bytes calldata data) external {
        require(allowedTarget[target], "target not allowed");
        (bool ok,) = target.call(data);
        require(ok, "failed");
    }
}`,
  },
  {
    year: 2022,
    incident: "control: governance with checkpointed weight",
    loss: "-",
    detector: "governance-live-voting-power",
    expect: "clean",
    mechanism: "weight is read at a prior block and execution is timelocked",
    source: `pragma solidity ^0.8.0;
interface IVotes { function getPastVotes(address, uint256) external view returns (uint256); }
contract SafeGovernor {
    IVotes public token;
    mapping(uint256 => uint256) public snapshotBlock;
    mapping(uint256 => uint256) public eta;
    function execute(uint256 proposalId) external {
        require(block.timestamp >= eta[proposalId], "timelock");
        require(token.getPastVotes(msg.sender, snapshotBlock[proposalId]) > 0, "no votes");
    }
}`,
  },
  {
    year: 2022,
    incident: "control: ecrecover with the zero check",
    loss: "-",
    detector: "ecrecover-zero",
    expect: "clean",
    mechanism: "the recovered signer is rejected when it is address(0)",
    source: `pragma solidity ^0.8.0;
contract SafeClaim {
    address public signer;
    function claim(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(msg.sender, amount));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0), "invalid signature");
        require(recovered == signer, "wrong signer");
    }
}`,
  },
  {
    year: 2023,
    incident: "control: a feed with a heartbeat check",
    loss: "-",
    detector: "oracle-staleness",
    expect: "clean",
    mechanism: "updatedAt and answeredInRound are both checked",
    source: `pragma solidity ^0.8.0;
interface IFeed { function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80); }
contract SafeLending {
    IFeed public feed;
    uint256 public constant HEARTBEAT = 1 hours;
    function price() external view returns (int256) {
        (uint80 roundId, int256 answer,, uint256 updatedAt, uint80 answeredInRound) = feed.latestRoundData();
        require(answer > 0, "bad answer");
        require(updatedAt > 0 && block.timestamp - updatedAt <= HEARTBEAT, "stale");
        require(answeredInRound >= roundId, "incomplete round");
        return answer;
    }
}`,
  },
];

function findingsFor(source: string): Finding[] {
  return analyzeInput(source, "incidents-2021-2026").findings;
}

for (const e of ENTRIES) {
  if (e.expect === "documented-only") {
    test(`${e.year} ${e.incident} (${e.loss}): documented as not source-detectable`, () => {
      assert.equal(e.detector, null, "a documented-only entry must name no detector");
      assert.ok((e.reason ?? "").length > 40, `${e.incident} needs a real reason, not a placeholder`);
    });
    continue;
  }
  test(`${e.year} ${e.incident} (${e.loss}): ${e.expect} ${e.detector}`, () => {
    assert.ok(e.source, `${e.incident} needs a fixture`);
    const hits = findingsFor(e.source!).filter((f) => f.detector === e.detector);
    if (e.expect === "fires") {
      assert.ok(hits.length >= 1, `${e.incident}: expected ${e.detector} to fire, got ${findingsFor(e.source!).map((f) => f.detector).join(", ")}`);
    } else {
      assert.equal(hits.length, 0, `${e.incident}: ${e.detector} must stay quiet on the correct implementation`);
    }
  });
}

// ------------------------------------------------------------------
// Structural guarantees on the corpus itself
// ------------------------------------------------------------------

test("every year 2021-2026 has at least two entries", () => {
  for (const year of [2021, 2022, 2023, 2024, 2025, 2026] as const) {
    const n = ENTRIES.filter((e) => e.year === year).length;
    assert.ok(n >= 2, `year ${year} has only ${n} entries`);
  }
});

test("every detector named by the corpus exists in the SmartBugs registry", () => {
  for (const e of ENTRIES) {
    if (!e.detector) continue;
    assert.ok(
      SMARTBUGS_BY_DETECTOR[e.detector],
      `${e.incident} names ${e.detector}, which is not in SMARTBUGS_BY_DETECTOR`,
    );
  }
});

test("the corpus is honest about its boundary: off-chain and compiler classes are documented, not claimed", () => {
  const documented = ENTRIES.filter((e) => e.expect === "documented-only");
  assert.ok(documented.length >= 6, "the six-year history has several classes no source rule can see");
  // The specific ones a reader would expect to see named.
  for (const name of ["Radiant Capital", "Bybit", "Curve Finance (Vyper)", "Wormhole", "Orbit Chain / Orbit Bridge"]) {
    assert.ok(documented.some((e) => e.incident === name), `${name} must be recorded as documented-only`);
  }
});
