export type Sample = {
  id: string;
  label: string;
  blurb: string;
  body: string;
};

export const SAMPLES: Sample[] = [
  {
    id: "relic",
    label: "RelicVault",
    blurb: "0.7 vault — reentrancy, delegatecall, tx.origin",
    body: `// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract RelicVault {
    mapping(address => uint256) public balances;
    address public owner;
    address public implementation;

    constructor() public {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
    }

    function migrate(address impl, bytes calldata data) external {
        implementation = impl;
        (bool ok, ) = impl.delegatecall(data);
        require(ok);
    }

    function ownerPull(address payable to) external {
        require(tx.origin == owner, "auth");
        to.transfer(address(this).balance);
    }

    function price() public view returns (uint256) {
        return address(this).balance;
    }
}
`,
  },
  {
    id: "permit",
    label: "PermitDesk",
    blurb: "Initializers, signatures, spot price, packed hashes",
    body: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract PermitDesk {
    mapping(address => uint256) public stakes;
    address public oracle;
    bool public initialized;

    function initialize(address _oracle) external {
        oracle = _oracle;
        initialized = true;
    }

    function claim(
        string calldata id,
        string calldata note,
        uint256 amount,
        bytes32 r,
        bytes32 s,
        uint8 v
    ) external {
        bytes32 hash = keccak256(abi.encodePacked(id, note));
        address signer = ecrecover(hash, v, r, s);
        require(signer == oracle, "sig");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "pay");
        stakes[msg.sender] += amount;
    }

    function quote(address pair) external view returns (uint256) {
        (uint112 reserve0, uint112 reserve1, ) = IPair(pair).getReserves();
        return (uint256(reserve0) / uint256(reserve1)) * 1e18;
    }
}
`,
  },
  {
    id: "guarded",
    label: "GuardedVault",
    blurb: "Checks-effects-interactions, for comparison",
    body: `// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract GuardedVault {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 private locked;

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    modifier nonReentrant() {
        require(locked == 0, "reenter");
        locked = 1;
        _;
        locked = 0;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }

    function rescue(address payable to) external onlyOwner {
        uint256 amount = address(this).balance;
        (bool ok, ) = to.call{value: amount}("");
        require(ok);
    }
}
`,
  },
  {
    id: "opcodes",
    label: "Hostile runtime",
    blurb: "Hand-assembled bytecode — origin, selfdestruct, delegatecall",
    body: "0x633ccfd60b32331460125733ff00000000005b600060006000600060006000f450600060006000600060006000f150420600",
  },
  {
    id: "proxy",
    label: "EIP-1167 clone",
    blurb: "Minimal proxy pointing at a placeholder implementation",
    body: "0x363d3d373d3d3d363d73bebebebebebebebebebebebebebebebebebebebe5af43d82803e903d91602b57fd5bf3",
  },
];
