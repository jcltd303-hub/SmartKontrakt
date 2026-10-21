/*
 * PROVENANCE
 * -------------------------------------------------------------------
 * Dataset repo : smartbugs/smartbugs-curated
 * Dataset path : dataset/front_running/ERC20.sol
 * Upstream @source: https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/transaction_order_dependence/ERC20.sol
 * Original pragma: ^0.4.24
 * Original vulnerable line(s): 110,113  (FRONT_RUNNING / SWC-114)
 * Port pragma  : ^0.8.24
 *
 * Migration edits (mechanical 0.4 -> 0.8 only):
 *   - `uint` -> `uint256`; `require(b != 0)` kept verbatim.
 *   - library `SafeMath` renamed `FrontRunningErc20SafeMath` (namespacing only).
 *   - `constructor(uint totalSupply)` -> `constructor(uint256 totalSupply)`.
 * NOTE: 0.8 checked arithmetic makes SafeMath's overflow `require`s redundant
 * (overflow now reverts natively) - identical observable behaviour (revert), so
 * the original semantics are preserved. `approve` overwrites the allowance
 * verbatim, which is the front-running bug.
 *
 * VULNERABILITY: `approve` overwrites the previous allowance. An attacker who
 * observes a pending allowance change (100 -> 50) can spend the OLD allowance of
 * 100 first, then spend the NEW allowance of 50 after the change lands, taking
 * 150 in total.
 */
pragma solidity ^0.8.24;

library FrontRunningErc20SafeMath {

  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    require(c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b > 0);
    uint256 c = a / b;
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b <= a);
    uint256 c = a - b;
    return c;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    require(c >= a);
    return c;
  }

  function mod(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b != 0);
    return a % b;
  }
}

contract FrontRunningErc20 {

  event Transfer( address indexed from, address indexed to, uint256 value );
  event Approval( address indexed owner, address indexed spender, uint256 value);
  using FrontRunningErc20SafeMath for uint256;

  mapping (address => uint256) private _balances;

  mapping (address => mapping (address => uint256)) private _allowed;

  uint256 private _totalSupply;

  constructor(uint256 totalSupply){
    _balances[msg.sender] = totalSupply;
  }

  function balanceOf(address owner) public view returns (uint256) {
    return _balances[owner];
  }

  function allowance(address owner, address spender) public view returns (uint256)
  {
    return _allowed[owner][spender];
  }

  function transfer(address to, uint256 value) public returns (bool) {
    require(value <= _balances[msg.sender]);
    require(to != address(0));

    _balances[msg.sender] = _balances[msg.sender].sub(value);
    _balances[to] = _balances[to].add(value);
    emit Transfer(msg.sender, to, value);
    return true;
  }
  // <yes> <report> FRONT_RUNNING
  function approve(address spender, uint256 value) public returns (bool) {
    require(spender != address(0));
     // <yes> <report> FRONT_RUNNING
    _allowed[msg.sender][spender] = value;
    emit Approval(msg.sender, spender, value);
    return true;
  }

  function transferFrom(address from, address to, uint256 value) public returns (bool) {
    require(value <= _balances[from]);
    require(value <= _allowed[from][msg.sender]);
    require(to != address(0));

    _balances[from] = _balances[from].sub(value);
    _balances[to] = _balances[to].add(value);
    _allowed[from][msg.sender] = _allowed[from][msg.sender].sub(value);
    emit Transfer(from, to, value);
    return true;
  }
}
