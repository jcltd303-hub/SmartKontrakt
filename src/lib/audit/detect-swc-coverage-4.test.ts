import test from "node:test";
import assert from "node:assert/strict";
import { parseSource } from "./model.ts";
import { detectSource } from "./detect.ts";
import type { Finding } from "./types.ts";

/**
 * Regression fixtures for Fix 61 (analyzer 2026-11-08.28), from the
 * SmartBugs Curated benchmark against .27: SWC-101 sat at 21/23 and
 * the one real miss left was BECToken's batchTransfer — a raw
 * product of caller-controlled inputs into a LOCAL, guard-checked
 * after it wraps. The dataset's other miss (integer_overflow_
 * benign_1) is a safe variant and must stay silent. Every shape
 * proves BOTH directions: the archetype flags AND the corrected /
 * legitimate shape stays silent.
 */

function analyze(src: string): Finding[] {
  const model = parseSource(src);
  assert.equal(model.parseError, null);
  return detectSource(model, src);
}

function arith(findings: Finding[]): Finding[] {
  return findings.filter((f) => f.detector === "unchecked-block" && f.swc === "SWC-101");
}

// ---------- Fix 61: the BECToken product shape ----------

test("SWC-101: BECToken batchTransfer shape flags — product into a local, guard checks the wrapped value", () => {
  const findings = analyze(`
    pragma solidity ^0.4.16;
    contract BecLike {
      mapping (address => uint256) balances;
      function batchTransfer(address[] _receivers, uint256 _value) public returns (bool) {
        uint cnt = _receivers.length;
        uint256 amount = uint256(cnt) * _value;
        require(cnt > 0 && cnt <= 20);
        require(_value > 0 && balances[msg.sender] >= amount);
        balances[msg.sender] = balances[msg.sender].sub(amount);
        for (uint i = 0; i < cnt; i++) {
          balances[_receivers[i]] = balances[_receivers[i]].add(_value);
        }
        return true;
      }
    }
  `);
  const hits = arith(findings);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-101");
  assert.equal(hits[0].severity, "medium");
  // The product statement is fixture line 7 (fn at 5, cnt at 6).
  assert.equal(hits[0].locationLine, 7);
  // Note the fixture's balances ARE SafeMath-guarded (.sub/.add) —
  // that must not disarm the shape: the product wraps first.
});

test("SWC-101: the same product computed with SafeMath .mul stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.4.16;
    contract BecFixed {
      mapping (address => uint256) balances;
      function batchTransfer(address[] _receivers, uint256 _value) public returns (bool) {
        uint cnt = _receivers.length;
        uint256 amount = uint256(cnt).mul(_value);
        require(cnt > 0 && cnt <= 20);
        require(_value > 0 && balances[msg.sender] >= amount);
        balances[msg.sender] = balances[msg.sender].sub(amount);
        for (uint i = 0; i < cnt; i++) {
          balances[_receivers[i]] = balances[_receivers[i]].add(_value);
        }
        return true;
      }
    }
  `);
  assert.equal(arith(findings).length, 0);
});

test("SWC-101: literal x literal product stays silent even when require-checked", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract ConstProduct {
      mapping (address => uint256) balances;
      function f() public {
        uint256 amount = 20 * 1000;
        require(balances[msg.sender] >= amount);
        balances[msg.sender] = balances[msg.sender] - amount;
      }
    }
  `);
  assert.equal(arith(findings).length, 0);
});

test("SWC-101: named-constant x literal product stays silent (no caller-controlled operand)", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract NamedConst {
      uint256 public constant RATE = 3;
      uint256 public total;
      function f() public {
        uint256 amount = RATE * 1000;
        require(amount > 0);
        total = amount;
      }
    }
  `);
  assert.equal(arith(findings).length, 0);
});

test("SWC-101: vendored SafeMath.mul stays silent — the guard divides the product back (sound check)", () => {
  // The corpus-forced disarm: this 0.4-era shape is verbatim from
  // BECToken.sol's own SafeMath library. `require(c / a == b)`
  // PROVES the product did not wrap — flagging it would fire on
  // every contract that vendors SafeMath.
  const findings = analyze(`
    pragma solidity ^0.4.16;
    library SafeMath {
      function mul(uint256 a, uint256 b) internal constant returns (uint256) {
        uint256 c = a * b;
        require(a == 0 || c / a == b);
        return c;
      }
    }
  `);
  assert.equal(arith(findings).length, 0);
});

test("SWC-101: a hand-rolled division-checked product in a regular contract stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract CheckedMul {
      uint256 public total;
      function mul(uint256 a, uint256 b) public returns (uint256) {
        uint256 c = a * b;
        require(c / a == b);
        total = c;
        return c;
      }
    }
  `);
  assert.equal(arith(findings).length, 0);
});

test("SWC-101: a SafeMath .mul product with a ** scaling term stays silent (exponent is not a product)", () => {
  // Corpus-forced (MoonFORCE Presale.userDeposit): the only `*`
  // characters in the statement belong to `10 ** decimals`, and
  // the multiplication itself is SafeMath's .mul — reading `**`
  // as two products flags a checked computation.
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract PresaleLike {
      uint256 public total;
      function userDeposit(uint256 _amount) public payable {
        uint256 amount_in = msg.value;
        uint256 tokensSold = amount_in.mul(5).div(10 ** uint256(18));
        require(tokensSold > 0);
        total = tokensSold;
      }
    }
  `);
  assert.equal(arith(findings).length, 0);
});

test("SWC-101: the BECToken shape on 0.8+ stays silent (the compiler checks the product)", () => {
  const findings = analyze(`
    pragma solidity ^0.8.24;
    contract BecModern {
      mapping (address => uint256) balances;
      function batchTransfer(address[] _receivers, uint256 _value) public returns (bool) {
        uint cnt = _receivers.length;
        uint256 amount = uint256(cnt) * _value;
        require(cnt > 0 && cnt <= 20);
        require(_value > 0 && balances[msg.sender] >= amount);
        balances[msg.sender] = balances[msg.sender] - amount;
        for (uint i = 0; i < cnt; i++) {
          balances[_receivers[i]] = balances[_receivers[i]] + _value;
        }
        return true;
      }
    }
  `);
  assert.equal(arith(findings).length, 0);
});

test("SWC-101: a product nobody guard-checks stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract UncheckedProduct {
      uint256 public total;
      function f(uint256 _count, uint256 _value) public {
        uint256 amount = _count * _value;
        total = amount;
      }
    }
  `);
  assert.equal(arith(findings).length, 0);
});

test("SWC-101: the benign dataset shape stays silent (subtraction into a dropped local)", () => {
  // integer_overflow_benign_1.sol, verbatim shape: the result never
  // escapes the function and is never read — a true negative the
  // benchmark scores as a miss, and the fleet's silence is correct.
  const findings = analyze(`
    pragma solidity ^0.4.19;
    contract IntegerOverflowBenign1 {
      uint public count = 1;
      function run(uint256 input) public {
        uint res = count - input;
      }
    }
  `);
  assert.equal(arith(findings).length, 0);
});

test("SWC-101: msg.value-derived product that a require checks flags", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract BuyUnits {
      uint256 public cap;
      function buy(uint256 _rate) public payable {
        uint256 total = msg.value * _rate;
        require(total <= cap);
        cap = total;
      }
    }
  `);
  const hits = arith(findings);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-101");
});

test("SWC-101: the product shape in a view function stays silent (mutability gate)", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract ViewCheck {
      mapping (address => uint256) balances;
      function check(address[] _receivers, uint256 _value) public view returns (bool) {
        uint cnt = _receivers.length;
        uint256 amount = uint256(cnt) * _value;
        return balances[msg.sender] >= amount;
      }
    }
  `);
  assert.equal(arith(findings).length, 0);
});

// ---------- composition with the pre-existing pre-0.8 shapes ----------

test("SWC-101: multiplication into stored state still fires via the compound gate, exactly once", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract StoredProduct {
      uint256 public total;
      function add(uint256 _value) public {
        total *= _value;
      }
    }
  `);
  const hits = arith(findings);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-101");
});

test("SWC-101: stored-state shape and product shape in one function yield ONE finding (no double report)", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract BothShapes {
      mapping (address => uint256) balances;
      function f(uint256 _count, uint256 _value) public {
        balances[msg.sender] -= _value;
        uint256 amount = _count * _value;
        require(balances[msg.sender] >= amount);
      }
    }
  `);
  const hits = arith(findings);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-101");
});
