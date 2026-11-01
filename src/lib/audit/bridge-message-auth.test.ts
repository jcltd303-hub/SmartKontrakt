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

test("a bare claim() is unbacked-mint, not a bridge handler", () => {
  // This fixture used to assert a bridge-message-auth hit, and that was the bug: a
  // function with NO parameters, no message and no peer is not a cross-chain handler.
  // Measured on mainnet 2026-11-01 as LootChubby.claim(uint256) scoring a CRITICAL.
  // The class this fixture means to cover — an unverified mint to the caller — is
  // unbacked-mint's job, and that detector still fires here.
  const src = `
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public deposited;
    function claim() external {
        balances[msg.sender] += 1e18;
        _mint(msg.sender, 1e18);
    }
    function _mint(address to, uint256 amount) internal {}
}`;
  assert.equal(hits(src).length, 0, "no message means no cross-chain handler");
  // Note: unbacked-mint does not cover this either — it requires an amount PARAMETER, and
  // claim() takes none. That is a real gap in that rule, left alone here rather than
  // widened under pressure: it is a different detector and deserves its own measurement.
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

test("an NFT claim is not a cross-chain handler", () => {
  // Measured 2026-11-01: LootChubby.claim(uint256 tokenId) scored a CRITICAL. It takes a
  // token id — no bytes, no chain id, no proof — because it is an NFT claim bounded by a
  // supply cap and an id range. The name `claim` is in the handler list and `_mint` is in
  // the effect list, so it fired on the name alone.
  const nft = `
pragma solidity ^0.8.0;
contract LootChubby is ERC721 {
    uint256 public totalClaimed;
    uint256 constant LOOT_RESERVED = 5000;
    uint256 constant MAX_LOOT_ID = 8000;
    function claim(uint256 tokenId) public nonReentrant returns (uint256) {
        require(totalClaimed < LOOT_RESERVED, "claims no longer available");
        require(tokenId > 0 && tokenId <= MAX_LOOT_ID, "invalid token id");
        totalClaimed++;
        _mint(msg.sender, tokenId);
        return tokenId;
    }
}`;
  const found = analyzeInput(nft, "nft").findings.filter((f) => f.detector === "bridge-message-auth");
  assert.equal(found.length, 0, "a tokenId is not a message");
});

test("a real inbound handler still fires — it takes a payload", () => {
  // A payload with NO verification vocabulary: this is the shape the rule exists for.
  const bridge = `
pragma solidity ^0.8.0;
contract Bridge {
    function claim(bytes calldata payload) external {
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        _mint(to, amount);
    }
    function _mint(address, uint256) internal {}
}`;
  const found = analyzeInput(bridge, "bridge").findings.filter((f) => f.detector === "bridge-message-auth");
  assert.ok(found.length >= 1, "a bytes payload handler must still be flagged");
});
