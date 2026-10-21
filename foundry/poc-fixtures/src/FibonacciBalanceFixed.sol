// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 *   Dataset repo     : smartbugs/smartbugs-curated
 *   Dataset path     : dataset/access_control/FibonacciBalance.sol
 *   @source          : https://github.com/sigp/solidity-security-blog
 *   Original pragma  : pragma solidity ^0.4.22;
 *   Vulnerable lines : 31, 38
 *
 *   FIXED variant of FibonacciBalance. Standard remediation for the unprotected
 *   fallback delegatecall (SWC-112): a real owner is recorded at deployment and the
 *   fallback only forwards data for that owner (owner/role check). `withdraw` is left
 *   unchanged.
 */
pragma solidity ^0.8.24;

contract FibonacciBalanceFixed {

    address public fibonacciLibrary;
    uint256 public calculatedFibNumber;
    uint256 public start = 3;
    uint256 public withdrawalCounter;
    bytes4 constant fibSig = bytes4(keccak256("setFibonacci(uint256)"));
    // FIX: owner used to guard the generic fallback delegatecall
    address public owner;

    constructor(address _fibonacciLibrary) payable {
        fibonacciLibrary = _fibonacciLibrary;
        owner = msg.sender;
    }

    function withdraw() public {
        withdrawalCounter += 1;
        (bool ok, ) = fibonacciLibrary.delegatecall(abi.encodeWithSelector(fibSig, withdrawalCounter));
        require(ok);
        payable(msg.sender).transfer(calculatedFibNumber * 1 ether);
    }

    // FIX: only the owner may forward arbitrary data into the library
    fallback() external {
        require(msg.sender == owner, "FibonacciBalanceFixed: not owner");
        (bool ok, ) = fibonacciLibrary.delegatecall(msg.data);
        require(ok);
    }
}

contract FibonacciBalanceFixedLib {
    uint256 public start;
    uint256 public calculatedFibNumber;

    function setStart(uint256 _start) public {
        start = _start;
    }

    function setFibonacci(uint256 n) public {
        calculatedFibNumber = fibonacci(n);
    }

    function fibonacci(uint256 n) internal returns (uint256) {
        if (n == 0) return start;
        else if (n == 1) return start + 1;
        else return fibonacci(n - 1) + fibonacci(n - 2);
    }
}
