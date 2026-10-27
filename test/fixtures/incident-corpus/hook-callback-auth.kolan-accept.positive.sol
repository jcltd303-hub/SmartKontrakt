// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
// The REAL KolanHook shape, from the vendored PoC
// (test/fixtures/incident-corpus/real/KolanHook_exp.sol, victim
// 0x...HOOK on Ethereum): the v4 callback is guarded, and the exploit goes
// through accept(), an ungated settlement entry for expired buy-windows.
// This case exists because the name-keyed rule missed exactly this incident.
contract KolanishHook {
    struct Window { address owner; uint256 eth; uint256 expiry; bool closed; }
    mapping(uint256 => Window) public windows;
    uint256 public recordedSpot;
    modifier onlyPoolManager() {
        require(msg.sender == address(0x1), "not pool manager");
        _;
    }
    function beforeSwap(address, bytes calldata, bytes calldata, bytes calldata hookData) external onlyPoolManager returns (bytes4) {
        recordedSpot = abi.decode(hookData, (uint256));
        return this.beforeSwap.selector;
    }
    // Ungated: anyone may settle ANY expired window at the manipulated spot.
    function accept(uint256 windowId) external {
        Window storage w = windows[windowId];
        require(!w.closed, "closed");
        require(block.timestamp > w.expiry, "not expired");
        w.closed = true;
        _closeWindow(windowId);
        payable(msg.sender).transfer(w.eth);
    }
    function _closeWindow(uint256 windowId) internal {
        // places the window's escrowed ETH as single-sided liquidity at recordedSpot
    }
}
