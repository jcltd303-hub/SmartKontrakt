import test from "node:test";
import assert from "node:assert/strict";

import { analyzeInput } from "./engine.ts";

/**
 * bridge-message-auth (2026-10-28).
 *
 * Measured against the archive: the rule fired 7 times across KeepBonding x2,
 * Ahoolee Token Sale, Launchpad and CompoundTreasury — none of them bridges. It keys
 * on a function NAME prefix, and `claim` is one of the commonest names in DeFi for
 * "pay the caller what they are owed". Meanwhile `release(address to, uint amount)`,
 * the canonical bridge outflow, was not matched at all because `release` was absent
 * from the name list.
 *
 * The invariant is not the name. It is: does value leave to a party the CALLER names,
 * with no check on where the message came from?
 */

const hits = (src: string) =>
  analyzeInput(src, "probe", null).findings.filter((f) => f.detector === "bridge-message-auth");

const HEAD = `
pragma solidity ^0.8.0;
interface IERC20 { function transfer(address, uint256) external returns (bool); }
`;

test("a self-service claim that pays the caller what they accrued is not a bridge finding", () => {
  const src = `${HEAD}
contract Treasury {
    IERC20 public comp;
    mapping(address => uint256) public accrued;
    function claimComp() external {
        uint256 amount = accrued[msg.sender];
        accrued[msg.sender] = 0;
        require(comp.transfer(msg.sender, amount), "transfer failed");
    }
}`;
  assert.equal(hits(src).length, 0);
});

test("a message handler that releases to an arbitrary recipient is the finding", () => {
  const src = `${HEAD}
contract Bridge {
    IERC20 public token;
    // An inbound cross-chain handler: it takes a message and pays whoever the
    // caller names, with no provenance check.
    function processMessage(bytes calldata message) external {
        (address to, uint256 amount) = abi.decode(message, (address, uint256));
        require(token.transfer(to, amount), "transfer failed");
    }
}`;
  const found = hits(src);
  assert.equal(found.length, 1, "a message handler releasing to a named payee must be detected");
  assert.equal(found[0]!.severity, "critical");
  assert.match(found[0]!.title, /processMessage mints or releases/);
});

test("a bare release(address,uint256) is a vault withdrawal, not a bridge handler", () => {
  // Measured 2026-10-28: adding `release` to the handler names produced cross-talk on
  // share-accounting-double-debit, whose ERC4626-style release is a redemption. With no
  // message parameter there is nothing cross-chain to authenticate, so it is not this
  // class — and the rule must not claim it is.
  const src = `${HEAD}
contract Vault {
    IERC20 public asset;
    mapping(address => uint256) public shares;
    function release(address to, uint256 amount) external {
        require(shares[msg.sender] >= amount, "insufficient");
        shares[msg.sender] -= amount;
        require(asset.transfer(to, amount), "transfer failed");
    }
}`;
  assert.equal(hits(src).length, 0);
});

test("minting to the caller still fires — that is Qubit, not self-service", () => {
  const src = `
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public deposited;
    function claim() external {
        // mints new value to the caller, backed by nothing verified
        balances[msg.sender] += 1e18;
        _mint(msg.sender, 1e18);
    }
    function _mint(address to, uint256 amount) internal {}
}`;
  assert.equal(hits(src).length, 1, "an unverified mint to msg.sender is the 2022 class");
});

test("verification vocabulary and access control still suppress, as before", () => {
  const verified = `${HEAD}
contract Bridge {
    IERC20 public token;
    address public endpoint;
    function release(uint16 srcChainId, bytes calldata srcAddress, address to, uint256 amount) external {
        require(msg.sender == endpoint, "not endpoint");
        require(srcChainId == 1, "untrusted source");
        require(token.transfer(to, amount), "transfer failed");
    }
}`;
  assert.equal(hits(verified).length, 0, "provenance checks suppress");

  const authed = `${HEAD}
contract Bridge {
    IERC20 public token;
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function release(address to, uint256 amount) external onlyOwner {
        require(token.transfer(to, amount), "transfer failed");
    }
}`;
  assert.equal(hits(authed).length, 0, "auth suppresses");
});
