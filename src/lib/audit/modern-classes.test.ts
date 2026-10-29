import test from "node:test";
import assert from "node:assert/strict";

import { analyzeInput } from "./engine.ts";

/**
 * 2022-2026 loss categories (2026-10-29).
 *
 * Reentrancy — the SmartBugs-era flagship — fell from 23 incidents in 2023 to one in
 * 2026, while vault inflation, signature threshold bypass and unbacked mints kept
 * producing eight-figure losses with no rule covering them.
 */

const hits = (src: string, detector: string) =>
  analyzeInput(src, "probe", null).findings.filter((f) => f.detector === detector);

test("totalAssets read from balanceOf(this) is the donation attack", () => {
  const src = `
pragma solidity ^0.8.0;
interface IERC20 { function balanceOf(address) external view returns (uint256); }
contract Vault {
    IERC20 public asset;
    uint256 public totalSupply;
    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }
    function deposit(uint256 a) external returns (uint256) { totalSupply += a; return a; }
}`;
  const found = hits(src, "vault-inflation-donation");
  assert.equal(found.length, 1);
  assert.equal(found[0]!.severity, "high");
  assert.match(found[0]!.title, /anyone can inflate/);
});

test("a vault tracking assets internally is not flagged", () => {
  const src = `
pragma solidity ^0.8.0;
contract Vault {
    uint256 private _totalAssets;
    function totalAssets() public view returns (uint256) { return _totalAssets; }
}`;
  assert.equal(hits(src, "vault-inflation-donation").length, 0);
});

test("convertToShares without a virtual offset is flagged", () => {
  const src = `
pragma solidity ^0.8.0;
contract Vault {
    uint256 public totalSupply;
    function totalAssets() public view returns (uint256) { return 0; }
    function convertToShares(uint256 assets) public view returns (uint256) {
        return assets * totalSupply / totalAssets();
    }
}`;
  const found = hits(src, "vault-inflation-donation");
  assert.ok(found.length >= 1);
  assert.ok(found.some((f) => /virtual offset/.test(f.title)));
});

test("convertToShares with the ERC-4626 offset is not flagged", () => {
  const src = `
pragma solidity ^0.8.0;
contract Vault {
    uint256 public totalSupply;
    function totalAssets() public view returns (uint256) { return 0; }
    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply;
        return supply == 0 ? assets : assets * (supply + 1) / (totalAssets() + 1);
    }
}`;
  assert.equal(hits(src, "vault-inflation-donation").length, 0);
});

test("a signature loop with no duplicate rejection is the Wormhole shape", () => {
  const src = `
pragma solidity ^0.8.0;
contract Bridge {
    mapping(address => bool) public guardians;
    uint256 public threshold;
    function recover(bytes32 h, bytes memory sig) internal pure returns (address) { return address(0); }
    function verify(bytes32 message, bytes[] calldata signatures) external view returns (bool) {
        uint256 valid = 0;
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = recover(message, signatures[i]);
            if (guardians[signer]) { valid++; }
        }
        require(valid >= threshold, "threshold not met");
        return true;
    }
}`;
  const found = hits(src, "signature-threshold-no-dedupe");
  assert.equal(found.length, 1);
  assert.equal(found[0]!.severity, "critical");
  assert.match(found[0]!.summary, /Wormhole/);
});

test("a signature loop that rejects duplicates is not flagged", () => {
  const src = `
pragma solidity ^0.8.0;
contract Bridge {
    mapping(address => bool) public guardians;
    uint256 public threshold;
    mapping(address => bool) seen;
    function recover(bytes32 h, bytes memory sig) internal pure returns (address) { return address(0); }
    function verify(bytes32 message, bytes[] calldata signatures) external view returns (bool) {
        uint256 valid = 0;
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = recover(message, signatures[i]);
            require(!seen[signer], "duplicate signer");
            seen[signer] = true;
            if (guardians[signer]) { valid++; }
        }
        require(valid >= threshold, "threshold not met");
        return true;
    }
}`;
  assert.equal(hits(src, "signature-threshold-no-dedupe").length, 0);
});

test("a permissionless mint of a caller-chosen amount is unbacked", () => {
  const src = `
pragma solidity ^0.8.0;
contract Token {
    mapping(address => uint256) public balanceOf;
    function _mint(address to, uint256 amount) internal { balanceOf[to] += amount; }
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}`;
  const found = hits(src, "unbacked-mint");
  assert.equal(found.length, 1);
  // high, not critical: the backing check could live in a modifier or an inherited
  // function this scan cannot see, which is medium confidence, and a critical
  // requires high confidence.
  assert.equal(found[0]!.severity, "high");
  assert.equal(found[0]!.confidence, "medium");
});

test("an owner-gated mint is not flagged", () => {
  const src = `
pragma solidity ^0.8.0;
contract Token {
    address public owner;
    mapping(address => uint256) public balanceOf;
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    function _mint(address to, uint256 amount) internal { balanceOf[to] += amount; }
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }
}`;
  assert.equal(hits(src, "unbacked-mint").length, 0);
});
