import test from "node:test";
import assert from "node:assert/strict";

import { analyzeInput } from "./engine.ts";
import type { Finding } from "./types.ts";

/**
 * Detection-upgrade regression corpus (2026-10-27).
 *
 * Every fixture is one measured failure from the engagement — the precision
 * failures P1–P10, the recall failures R1–R3, and the two positive controls
 * that must keep firing. The plan's Phase 6 rule is the reason this file
 * exists: no rule change ships without the corpus passing. Each test names
 * the failure it pins, so a future rule edit that re-breaks one is told
 * which contract it is re-breaking.
 */

function findings(source: string): Finding[] {
  return analyzeInput(source, "detection-upgrade-fixture").findings;
}

function detectors(source: string): string[] {
  return findings(source).map((f) => f.detector);
}

function has(source: string, detector: string): boolean {
  return detectors(source).includes(detector);
}

// ------------------------------------------------------------------
// P1 — comments scanned as code
// ------------------------------------------------------------------

test("P1: the word \"now\" inside a comment is not block entropy", () => {
  const src = `pragma solidity ^0.8.0;
contract Arborithms {
    uint256 public total;
    // now that the round is over, anyone may add to the pot
    function add(uint256 x) external {
        /* the winner is decided now, off-chain */
        total += x;
    }
}`;
  assert.equal(has(src, "weak-randomness"), false);
  assert.equal(has(src, "timestamp"), false);
});

// ------------------------------------------------------------------
// P2 — name-based taint too broad (EIP-712 permit)
// ------------------------------------------------------------------

test("P2: an EIP-712 permit hash is not entropy", () => {
  const src = `pragma solidity ^0.8.0;
contract VisionToken {
    bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    mapping(address => uint256) public nonces;
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\\x19\\x01", structHash));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered == owner, "invalid signature");
    }
}`;
  assert.equal(has(src, "weak-randomness"), false);
});

// ------------------------------------------------------------------
// P3 — interface declarations parsed as functions
// ------------------------------------------------------------------

test("P3: a bodiless interface declaration is not a function", () => {
  const src = `pragma solidity ^0.8.0;
interface IColdWallet {
    function transfer(address to, uint256 amount) external returns (bool);
    function owner() external view returns (address);
}`;
  assert.deepEqual(detectors(src).filter((d) => d === "unprotected-ether"), []);
});

// ------------------------------------------------------------------
// P4 — internal helpers treated as entry points
// ------------------------------------------------------------------

test("P4: an OZ sendValue helper with no public caller is not an entry point", () => {
  const src = `pragma solidity ^0.8.0;
library Address {
    function sendValue(address payable recipient, uint256 amount) internal {
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Address: unable to send value");
    }
}`;
  assert.equal(has(src, "unprotected-ether"), false);
});

// ------------------------------------------------------------------
// P5 — constructors matched by name
// ------------------------------------------------------------------

test("P5: a 0.5.x constructor named after the contract is a constructor", () => {
  const src = `pragma solidity ^0.5.0;
contract Phoenix {
    address public owner;
    function Phoenix() public {
        owner = msg.sender;
    }
}`;
  assert.equal(has(src, "unprotected-admin"), false);
});

// ------------------------------------------------------------------
// P6 — multi-line guards missed
// ------------------------------------------------------------------

test("P6: a guard split across lines still gates (KydyCore)", () => {
  const src = `pragma solidity ^0.8.0;
contract KydyCore {
    address public owner;
    function sweep() external {
        require(
            msg.sender == owner,
            "not owner"
        );
        payable(msg.sender).transfer(address(this).balance);
    }
}`;
  assert.equal(has(src, "unprotected-ether"), false);
});

// ------------------------------------------------------------------
// P7 — custom modifier names unknown
// ------------------------------------------------------------------

test("P7: an ownerOnly modifier declared elsewhere still gates (Bancor)", () => {
  const src = `pragma solidity ^0.8.0;
contract Bancor {
    address public owner;
    function withdrawAll() external ownerOnly {
        payable(msg.sender).transfer(address(this).balance);
    }
}`;
  assert.equal(has(src, "unprotected-ether"), false);
});

test("P7: isPlayer / treasuryOnly / hasMintPermission gate", () => {
  for (const mod of ["isPlayer", "treasuryOnly", "hasMintPermission"]) {
    const src = `pragma solidity ^0.8.0;
contract Gated {
    function drain() external ${mod} {
        payable(msg.sender).transfer(address(this).balance);
    }
}`;
    assert.equal(has(src, "unprotected-ether"), false, `${mod} should gate`);
  }
});

test("P7: onlyActive is a state gate and must NOT be credited as auth", () => {
  const src = `pragma solidity ^0.8.0;
contract StateGate {
    bool public active;
    function drain() external onlyActive {
        payable(msg.sender).transfer(address(this).balance);
    }
}`;
  assert.equal(has(src, "unprotected-ether"), true);
});

// ------------------------------------------------------------------
// P8 — inheritance not followed
// ------------------------------------------------------------------

test("P8: an initialize() guarded by a parent modifier is gated", () => {
  const src = `pragma solidity ^0.8.0;
contract Ownable {
    address public owner;
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }
}
contract VisionToken is Ownable {
    function initialize() public onlyOwner {
        owner = msg.sender;
    }
}`;
  assert.equal(has(src, "unprotected-initializer"), false);
});

// ------------------------------------------------------------------
// P9 — view functions with .transfer(
// ------------------------------------------------------------------

test("P9: a view function's .transfer( is not an ether send", () => {
  const src = `pragma solidity ^0.8.0;
interface IERC20 { function transfer(address to, uint256 amount) external returns (bool); }
contract TokenURI {
    IERC20 public token;
    function tokenURI(uint256) external view returns (bool) {
        return token.transfer(msg.sender, 1);
    }
}`;
  assert.equal(has(src, "unprotected-ether"), false);
});

// ------------------------------------------------------------------
// P10 — super.transfer( read as an ether transfer
// ------------------------------------------------------------------

test("P10: super.transfer is not an ether send (DirectCryptTokenPreSale)", () => {
  const src = `pragma solidity ^0.8.0;
contract Base {
    function transfer(address to, uint256 amount) public virtual returns (bool) {
        return true;
    }
}
contract DirectCryptTokenPreSale is Base {
    function pay(address to, uint256 amount) external returns (bool) {
        return super.transfer(to, amount);
    }
}`;
  assert.equal(has(src, "unprotected-ether"), false);
});

// ------------------------------------------------------------------
// R1 — the Team Just five-field mixer
// ------------------------------------------------------------------

test("R1: the five-field block mixer flags (F5D, FoMo3DSoon, FoMoJP, RobTheBank)", () => {
  const src = `pragma solidity ^0.5.0;
contract FoMo3DSoon {
    address[] public players;
    uint256 public airDropTracker_;
    function airDrop() public {
        airDropTracker_ = (uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty, block.coinbase, players.length)))) % 5;
    }
}`;
  const hits = findings(src).filter((f) => f.detector === "weak-randomness");
  assert.equal(hits.length, 1, "the mixer must flag exactly once");
  assert.equal(hits[0]?.confidence, "high", "the mixer fingerprint is high confidence");
});

// ------------------------------------------------------------------
// R2 — hash → derived value (trait derivation)
// ------------------------------------------------------------------

test("R2: a hash-derived value used in a later selection flags (NEOLASTICS, EulerBeats, Arborithms)", () => {
  const src = `pragma solidity ^0.8.0;
contract EulerBeats {
    mapping(address => uint256) public traitOf;
    function mintTrait() external {
        bytes32 h = keccak256(abi.encodePacked(block.timestamp, msg.sender));
        uint256 t = uint256(h) % 8;
        traitOf[msg.sender] = t;
    }
}`;
  assert.equal(has(src, "weak-randomness"), true);
});

test("R2: a hash-derived value compared in a branch flags", () => {
  const src = `pragma solidity ^0.8.0;
contract Arborithms {
    mapping(address => bool) public rare;
    function claim() external {
        uint256 h = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender)));
        if (h > 1e70) {
            rare[msg.sender] = true;
        }
    }
}`;
  assert.equal(has(src, "weak-randomness"), true);
});

test("R2 control: a hash used only as a mapping key is NOT randomness (Fix 20 preserved)", () => {
  const src = `pragma solidity ^0.8.0;
contract EtherHiLo {
    mapping(bytes32 => uint256) public games;
    function beginGame(uint256 bet) external payable {
        bytes32 gameId;
        gameId = keccak256(abi.encode(block.number, msg.sender, bet));
        games[gameId] = bet;
    }
}`;
  assert.equal(has(src, "weak-randomness"), false);
});

// ------------------------------------------------------------------
// R3 — prevrandao as a first-class seed
// ------------------------------------------------------------------

test("R3: block.prevrandao alone is entropy", () => {
  const src = `pragma solidity ^0.8.18;
contract Arborithms {
    uint256 public roll;
    function spin() external {
        roll = uint256(block.prevrandao) % 10;
    }
}`;
  assert.equal(has(src, "weak-randomness"), true);
});

// ------------------------------------------------------------------
// Positive controls — a gate that eats these is worse than the FP rate
// ------------------------------------------------------------------

test("control: an unauthenticated full-balance drain still flags, and is REACHABLE", () => {
  const src = `pragma solidity ^0.8.0;
contract OpenDrain {
    function sweep() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}`;
  const hits = findings(src).filter((f) => f.detector === "unprotected-ether");
  assert.equal(hits.length, 1);
  assert.equal(hits[0]?.reachability, "REACHABLE");
});

test("control: an owner-gated drain is tagged GATED, not REACHABLE", () => {
  const src = `pragma solidity ^0.8.0;
contract GatedDrain {
    address public owner;
    function sweep() external onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }
}`;
  for (const f of findings(src)) {
    if (f.locationFn !== "sweep") continue;
    assert.notEqual(f.reachability, "REACHABLE", `${f.detector} should not be tagged REACHABLE`);
  }
});

test("control: a caller-bounded withdrawal is tagged BOUNDED", () => {
  const src = `pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw() external {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amt);
    }
}`;
  const sweepish = findings(src).filter((f) => f.locationFn === "withdraw");
  for (const f of sweepish) {
    if (!f.reachability) continue;
    assert.equal(f.reachability, "BOUNDED", `${f.detector} should be BOUNDED`);
  }
});

// ------------------------------------------------------------------
// front-running (2026-10-27): the rule that used to be a phantom — a
// detector id with a PoC harness and a SmartBugs category but no rule.
// ------------------------------------------------------------------

test("front-running: an approve() that overwrites an allowance flags (ERC-20 race)", () => {
  const src = `pragma solidity ^0.8.0;
contract Token {
    mapping(address => mapping(address => uint256)) public allowed;
    mapping(address => uint256) public balanceOf;
    function approve(address spender, uint256 value) external returns (bool) {
        allowed[msg.sender][spender] = value;
        return true;
    }
    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        allowed[from][msg.sender] -= value;
        balanceOf[from] -= value;
        balanceOf[to] += value;
        return true;
    }
}`;
  assert.equal(has(src, "front-running"), true);
});

test("front-running: a payout for an answer revealed in the transaction flags", () => {
  const src = `pragma solidity ^0.4.24;
contract FindThisHash {
    bytes32 public constant hash = 0x1234567890123456789012345678901234567890123456789012345678901234;
    function solve(string solution) public {
        require(keccak256(abi.encodePacked(solution)) == hash);
        msg.sender.transfer(10 ether);
    }
}`;
  assert.equal(has(src, "front-running"), true);
});

test("front-running: a commit-reveal answer does not flag (control)", () => {
  const src = `pragma solidity ^0.8.0;
contract CommitReveal {
    mapping(address => bytes32) public commits;
    function commit(bytes32 h) external {
        commits[msg.sender] = h;
    }
    function reveal(uint256 answer, bytes32 salt) external {
        require(keccak256(abi.encode(answer, salt)) == commits[msg.sender], "no");
        payable(msg.sender).transfer(1 ether);
    }
}`;
  assert.equal(has(src, "front-running"), false);
});
