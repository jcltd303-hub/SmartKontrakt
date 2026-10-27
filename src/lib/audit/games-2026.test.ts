import test from "node:test";
import assert from "node:assert/strict";

import { analyzeInput } from "./engine.ts";
import { classifyReachability, isGatedAtCost } from "./reachability.ts";
import type { Finding } from "./types.ts";

/**
 * The games corpus (2026-10-27, plan §3b).
 *
 * Eight weak-randomness games were audited in depth and SEVEN were not
 * exploitable — not one of them for the reason the entropy detectors were
 * looking at. Each fixture below is that game's decisive structure, and the
 * assertion is the verdict the plan asks for: reachable or not, automatically.
 *
 * Two rules this file exists to enforce:
 *  - a precondition gate is reported as a gate, with its text, never as
 *    "unguarded" (six of the eight are gated this way);
 *  - a game whose satisfiability depends on live state (TwoCoins: moonLevel
 *    16 ETH against a 0.101 ETH balance) is classified by its live-threshold
 *    gate and the amount is left to a live read, never asserted from source.
 */

function findingsFor(source: string): Finding[] {
  return analyzeInput(source, "games-fixture").findings;
}

function detectorHits(source: string, detector: string): Finding[] {
  return findingsFor(source).filter((f) => f.detector === detector);
}

// ------------------------------------------------------------------
// The eight games — each asserts its class and gate kind
// ------------------------------------------------------------------

const GAMES: {
  game: string;
  entry: string;
  verdict: string;
  why: string;
  source: string;
  cls: string;
  gate: string;
}[] = [
  {
    game: "KatWalkerz",
    entry: "enter",
    verdict: "not profitable",
    why: "enter() requires holding BOTH KatMonstarz and KatWalkerz NFTs; prize pool was 0",
    cls: "GATED",
    gate: "GATED_PRECONDITION",
    source: `pragma solidity ^0.8.0;
interface IERC721 { function balanceOf(address) external view returns (uint256); }
contract KatWalkerzGame {
    IERC721 public katMonstarz;
    IERC721 public katWalkerz;
    uint256 public prizePool;
    function enter() external {
        require(katMonstarz.balanceOf(msg.sender) > 0, "need KatMonstarz");
        require(katWalkerz.balanceOf(msg.sender) > 0, "need KatWalkerz");
        prizePool += 0.01 ether;
    }
}`,
  },
  {
    game: "MyDice75",
    entry: "StartRollDice",
    verdict: "not attacker-reachable",
    why: "StartRollDice is onlyOwner — the HOUSE rolls",
    cls: "GATED",
    gate: "GATED_MODIFIER",
    source: `pragma solidity ^0.8.0;
contract MyDice75 {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }
    uint256 public lastRoll;
    function StartRollDice() external onlyOwner {
        lastRoll = uint256(keccak256(abi.encodePacked(block.timestamp))) % 6;
    }
}`,
  },
  {
    game: "TwoCoins",
    entry: "play",
    verdict: "dead",
    why: "moonLevel 16 ETH vs 0.101 ETH balance; parity is only a tie-break",
    cls: "GATED",
    gate: "GATED_PRECONDITION",
    source: `pragma solidity ^0.8.0;
contract TwoCoins {
    uint256 public moonLevel = 16 ether;
    function play() external payable {
        require(address(this).balance >= moonLevel, "moon not reached");
        require(msg.value > 0, "stake");
    }
}`,
  },
  {
    game: "TorpedoLaunchGame",
    entry: "submitScore",
    verdict: "not exploitable",
    why: "the score arrives with an ECDSA signature",
    cls: "GATED",
    gate: "GATED_PRECONDITION",
    source: `pragma solidity ^0.8.0;
contract TorpedoLaunchGame {
    address public signer;
    mapping(address => uint256) public score;
    function submitScore(uint256 value, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(msg.sender, value));
        require(ecrecover(digest, v, r, s) == signer, "bad signature");
        score[msg.sender] = value;
    }
}`,
  },
  {
    game: "Lottery1ETH",
    entry: "purchase",
    verdict: "dormant",
    why: "purchase() is require(msg.sender == game); needs 100 tickets",
    cls: "GATED",
    gate: "GATED_PRECONDITION",
    source: `pragma solidity ^0.8.0;
contract Lottery1ETH {
    address public game;
    address[] public tickets;
    function purchase() external payable {
        require(msg.sender == game, "only the game contract");
        require(tickets.length < 100, "full");
        tickets.push(msg.sender);
    }
}`,
  },
  {
    game: "HNDGame",
    entry: "addCommitRandom",
    verdict: "trust issue only",
    why: "addCommitRandom is admin-only",
    cls: "GATED",
    gate: "GATED_MODIFIER",
    source: `pragma solidity ^0.8.0;
contract HNDGame {
    address public admin;
    modifier onlyAdmin() { require(msg.sender == admin, "admin"); _; }
    bytes32 public commitRandom;
    function addCommitRandom(bytes32 c) external onlyAdmin {
        commitRandom = c;
    }
}`,
  },
  {
    game: "BlockChainCasino",
    entry: "settleBet",
    verdict: "REAL — risk-free",
    why: "entropy is fine; refundBet() returns the full stake, so the player settles only wins",
    cls: "REACHABLE",
    gate: "UNGATED",
    source: `pragma solidity ^0.8.0;
contract BlockChainCasino {
    uint256 public constant BET_EXPIRATION_BLOCKS = 250;
    struct Bet { address player; uint256 amount; uint256 block; bytes32 commit; }
    mapping(address => Bet) public bets;
    function placeBet(bytes32 commit) external payable {
        bets[msg.sender] = Bet(msg.sender, msg.value, block.number, commit);
    }
    function settleBet(bytes32 reveal) external {
        Bet memory b = bets[msg.sender];
        require(keccak256(abi.encodePacked(reveal)) == b.commit, "bad reveal");
        delete bets[msg.sender];
        payable(msg.sender).transfer(b.amount * 2);
    }
    function refundBet() external {
        Bet memory b = bets[msg.sender];
        require(block.number > b.block + BET_EXPIRATION_BLOCKS, "too early");
        delete bets[msg.sender];
        payable(msg.sender).transfer(b.amount);
    }
}`,
  },
  {
    game: "CoinAndRoulette",
    entry: "spin",
    verdict: "n/a",
    why: "the win rule had to be read from the game contract, not assumed",
    cls: "REACHABLE",
    gate: "UNGATED",
    source: `pragma solidity ^0.8.0;
contract CoinAndRoulette {
    mapping(uint256 => address) public gameAddress;
    function spin(uint256 gameId) external payable {
        address game = gameAddress[gameId];
        (bool ok,) = game.call{value: msg.value}(abi.encodeWithSignature("roll()"));
        require(ok, "game failed");
        payable(msg.sender).transfer(address(this).balance / 2);
    }
}`,
  },
];

for (const g of GAMES) {
  test(`${g.game}: classified ${g.cls}/${g.gate} (${g.why})`, () => {
    // Classified from the entry point's own body: a gated game produces no
    // finding at all, and that silence IS the result this corpus measures.
    const verdict = classifyFromSource(g.source, g.entry);
    assert.equal(verdict.class, g.cls, `${g.game}: class`);
    assert.equal(verdict.gate, g.gate, `${g.game}: gate kind`);
  });
}

/**
 * Re-derive the verdict for an entry point that produced no finding, by
 * re-classifying its body. Kept here (not in the engine) because the games
 * corpus must be able to assert on sites the detectors correctly stayed quiet
 * about — that silence IS the result.
 */
function classifyFromSource(source: string, fnName: string) {
  const start = source.indexOf(`function ${fnName}(`);
  assert.ok(start >= 0, `fixture is missing ${fnName}`);
  const open = source.indexOf("{", start);
  let depth = 0;
  let end = open;
  for (let i = open; i < source.length; i += 1) {
    if (source[i] === "{") depth += 1;
    else if (source[i] === "}") {
      depth -= 1;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }
  const body = source.slice(start, end);
  // The declaration header is everything before the body's opening brace.
  const header = body.slice(0, body.indexOf("{"));
  const visibility = /\b(external|public|internal|private)\b/.exec(header)?.[1] ?? "public";
  const afterParams = header.slice(header.lastIndexOf(")") + 1);
  const modifiers = (afterParams
    .replace(/\b(?:external|public|internal|private|payable|view|pure|virtual|override)\b/g, " ")
    .match(/[A-Za-z_]\w*/g) ?? []).filter(Boolean);
  const v = classifyReachability({
    visibility,
    modifiers,
    bodySource: body,
    movesValue: /\.transfer\(|\.call\{/.test(body),
    sendTargets: /\.transfer\(\s*msg\.sender/.test(body) ? ["msg.sender"] : [],
  });
  return { class: v.class, gate: v.gate };
}

// ------------------------------------------------------------------
// D1 gate kinds — the vocabulary itself
// ------------------------------------------------------------------

test("D1: a precondition gate carries its text, and is 'gated at cost'", () => {
  const v = classifyReachability({
    visibility: "public",
    bodySource: 'require(katMonstarz.balanceOf(msg.sender) > 0, "need NFT"); prizePool += 1;',
  });
  assert.equal(v.class, "GATED");
  assert.equal(v.gate, "GATED_PRECONDITION");
  assert.equal(isGatedAtCost(v), true);
  assert.match(v.preconditions[0] ?? "", /holding requirement/);
});

test("D1: a privileged modifier is not 'gated at cost'", () => {
  const v = classifyReachability({ visibility: "public", modifiers: ["onlyOwner"], bodySource: "x = 1;" });
  assert.equal(v.gate, "GATED_MODIFIER");
  assert.equal(isGatedAtCost(v), false);
});

test("D1: an allowlist slot is a precondition, not a privilege", () => {
  const v = classifyReachability({
    visibility: "public",
    bodySource: 'require(isExcludedFromFees[msg.sender], "not excluded"); buy();',
  });
  assert.equal(v.gate, "GATED_PRECONDITION");
  assert.match(v.preconditions.join(" "), /allowlist membership/);
});

test("D1: a round-fill threshold is a precondition", () => {
  const v = classifyReachability({
    visibility: "public",
    bodySource: 'require(players.length >= 2, "need two players"); _draw();',
  });
  assert.equal(v.gate, "GATED_PRECONDITION");
  assert.match(v.preconditions.join(" "), /round-fill threshold/);
});

test("D1: a plain unguarded function is UNGATED with no preconditions", () => {
  const v = classifyReachability({ visibility: "public", bodySource: "total += 1;" });
  assert.equal(v.class, "REACHABLE");
  assert.equal(v.gate, "UNGATED");
  assert.deepEqual(v.preconditions, []);
});

test("D1: a body read that is not a guard is not a precondition", () => {
  const v = classifyReachability({
    visibility: "public",
    bodySource: "emit Seen(balanceOf(msg.sender)); total += 1;",
  });
  assert.equal(v.gate, "UNGATED", "a balanceOf in an emit is not a gate");
});

// ------------------------------------------------------------------
// D2 — settlement optionality (BlockChainCasino)
// ------------------------------------------------------------------

test("D2: settle-a-win / refund-a-loss with no forced settlement is high", () => {
  const casino = GAMES.find((g) => g.game === "BlockChainCasino")!.source;
  const hits = detectorHits(casino, "settlement-optionality");
  assert.equal(hits.length, 1);
  assert.equal(hits[0]?.severity, "high");
  assert.match(hits[0]?.summary ?? "", /live read/);
});

test("D2: a house-side forced settlement closes the option (control)", () => {
  const src = `pragma solidity ^0.8.0;
contract ForcedSettle {
    uint256 public constant BET_EXPIRATION_BLOCKS = 250;
    address public admin;
    mapping(address => uint256) public stakeOf;
    mapping(address => uint256) public placedAt;
    modifier onlyAdmin() { require(msg.sender == admin, "admin"); _; }
    function placeBet() external payable {
        stakeOf[msg.sender] = msg.value;
        placedAt[msg.sender] = block.number;
    }
    function settleBet() external {
        uint256 amount = stakeOf[msg.sender];
        delete stakeOf[msg.sender];
        payable(msg.sender).transfer(amount * 2);
    }
    // The house resolves the round itself: the player cannot simply wait.
    function forceSettle(address player) external onlyAdmin {
        uint256 amount = stakeOf[player];
        delete stakeOf[player];
        if (amount > 0) payable(admin).transfer(amount);
    }
    function refundBet() external {
        require(block.number > placedAt[msg.sender] + BET_EXPIRATION_BLOCKS, "too early");
        uint256 amount = stakeOf[msg.sender];
        delete stakeOf[msg.sender];
        payable(msg.sender).transfer(amount);
    }
}`;
  assert.deepEqual(detectorHits(src, "settlement-optionality"), []);
});

test("D2: a refund with no timeout is not this pattern (control)", () => {
  const src = `pragma solidity ^0.8.0;
contract NoTimeout {
    mapping(address => uint256) public stakeOf;
    function settleBet() external {
        uint256 amount = stakeOf[msg.sender];
        delete stakeOf[msg.sender];
        payable(msg.sender).transfer(amount * 2);
    }
    function refundBet() external {
        uint256 amount = stakeOf[msg.sender];
        delete stakeOf[msg.sender];
        payable(msg.sender).transfer(amount);
    }
}`;
  assert.deepEqual(detectorHits(src, "settlement-optionality"), []);
});

test("D2: a game with only a settle path is not this pattern (control)", () => {
  const src = `pragma solidity ^0.8.0;
contract SettleOnly {
    mapping(address => uint256) public stakeOf;
    function settleBet() external {
        uint256 amount = stakeOf[msg.sender];
        delete stakeOf[msg.sender];
        payable(msg.sender).transfer(amount * 2);
    }
}`;
  assert.deepEqual(detectorHits(src, "settlement-optionality"), []);
});

// ------------------------------------------------------------------
// D3 — registry-dispatched logic (CoinAndRoulette)
// ------------------------------------------------------------------

test("D3: a payout decided by a registry-supplied callee is flagged unverified", () => {
  const src = GAMES.find((g) => g.game === "CoinAndRoulette")!.source;
  const hits = detectorHits(src, "registry-dispatched-logic");
  assert.equal(hits.length, 1);
  assert.match(hits[0]?.summary ?? "", /SEMANTICS_UNVERIFIED/);
});

test("D3: a direct call to a fixed callee is not this pattern (control)", () => {
  const src = `pragma solidity ^0.8.0;
interface IRoulette { function roll() external returns (bool); }
contract FixedGame {
    IRoulette public constant roulette = IRoulette(address(0x1234567890AbcdEF1234567890aBcdef12345678));
    function spin() external payable {
        bool won = roulette.roll();
        if (won) payable(msg.sender).transfer(msg.value * 2);
    }
}`;
  assert.deepEqual(detectorHits(src, "registry-dispatched-logic"), []);
});
