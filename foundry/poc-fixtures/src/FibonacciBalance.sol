// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 *   Dataset repo     : smartbugs/smartbugs-curated
 *   Dataset path     : dataset/access_control/FibonacciBalance.sol
 *   @source          : https://github.com/sigp/solidity-security-blog
 *   Original pragma  : pragma solidity ^0.4.22;
 *   Vulnerable lines : 31 (withdraw's delegatecall) and 38 (the fallback delegatecall)
 *
 *   Port: Solidity ^0.8.24.
 *     - bytes4(sha3("setFibonacci(uint256)")) -> bytes4(keccak256("setFibonacci(uint256)"))
 *     - fibonacciLibrary.delegatecall(fibSig, withdrawalCounter) -> delegatecall(abi.encodeWithSelector(fibSig, withdrawalCounter))
 *       (0.4 allowed delegatecall(bytes4, ...args); 0.8 takes a single bytes argument)
 *     - require(delegatecall(...)) -> destructure (bool ok,) and require(ok)
 *     - msg.sender.transfer(x) -> payable(msg.sender).transfer(x)
 *     - function() public -> fallback() external
 *   The vulnerable ordering is preserved verbatim: the fallback delegatecalls ANY
 *   caller-supplied data into the library, executing it in FibonacciBalance's storage
 *   context (SWC-112), so anyone can overwrite the contract's own storage slots
 *   (e.g. slot 0 == fibonacciLibrary).
 */
pragma solidity ^0.8.24;

contract FibonacciBalance {

    address public fibonacciLibrary;
    // the current fibonacci number to withdraw
    uint256 public calculatedFibNumber;
    // the starting fibonacci sequence number
    uint256 public start = 3;
    uint256 public withdrawalCounter;
    // the fibonancci function selector
    bytes4 constant fibSig = bytes4(keccak256("setFibonacci(uint256)"));

    // constructor - loads the contract with ether
    constructor(address _fibonacciLibrary) payable {
        fibonacciLibrary = _fibonacciLibrary;
    }

    function withdraw() public {
        withdrawalCounter += 1;
        // calculate the fibonacci number for the current withdrawal user
        // this sets calculatedFibNumber
        // <yes> <report> ACCESS_CONTROL   (vulnerable line 31)
        (bool ok, ) = fibonacciLibrary.delegatecall(abi.encodeWithSelector(fibSig, withdrawalCounter));
        require(ok);
        payable(msg.sender).transfer(calculatedFibNumber * 1 ether);
    }

    // allow users to call fibonacci library functions
    fallback() external {
        // <yes> <report> ACCESS_CONTROL   (vulnerable line 38)
        (bool ok, ) = fibonacciLibrary.delegatecall(msg.data);
        require(ok);
    }
}

// library contract - calculates fibonacci-like numbers;
contract FibonacciBalanceLib {
    // initializing the standard fibonacci sequence;
    uint256 public start;
    uint256 public calculatedFibNumber;

    // modify the zeroth number in the sequence
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
