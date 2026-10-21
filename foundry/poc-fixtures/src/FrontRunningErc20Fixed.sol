/*
 * PROVENANCE
 * -------------------------------------------------------------------
 * Dataset repo : smartbugs/smartbugs-curated
 * Dataset path : dataset/front_running/ERC20.sol
 * Upstream @source: https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/transaction_order_dependence/ERC20.sol
 * Original pragma: ^0.4.24
 * Original vulnerable line(s): 110,113
 * Fixed variant: FrontRunningErc20Fixed
 *
 * REMEDIATION (front-running the allowance change): allowances are changed
 * RELATIVELY via increaseAllowance/decreaseAllowance instead of being
 * overwritten. A relative change cannot be double-spent (there is no "old value"
 * left for the attacker to race against), so the old+new exploit disappears.
 * `approve` is kept only for the initial grant / reset to zero.
 */
pragma solidity ^0.8.24;

library FrontRunningErc20FixedSafeMath {
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b <= a);
    return a - b;
  }
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    require(c >= a);
    return c;
  }
}

contract FrontRunningErc20Fixed {

  event Transfer( address indexed from, address indexed to, uint256 value );
  event Approval( address indexed owner, address indexed spender, uint256 value);
  using FrontRunningErc20FixedSafeMath for uint256;

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

  // `approve` is only for the initial grant or a reset to zero; any other change
  // must go through the relative helpers below.
  function approve(address spender, uint256 value) public returns (bool) {
    require(spender != address(0));
    require(value == 0 || _allowed[msg.sender][spender] == 0, "use increase/decreaseAllowance");
    _allowed[msg.sender][spender] = value;
    emit Approval(msg.sender, spender, value);
    return true;
  }

  // FIX: relative change - cannot be front-run into a double spend.
  function increaseAllowance(address spender, uint256 added) public returns (bool) {
    require(spender != address(0));
    _allowed[msg.sender][spender] = _allowed[msg.sender][spender].add(added);
    emit Approval(msg.sender, spender, _allowed[msg.sender][spender]);
    return true;
  }

  // FIX: relative change - cannot be front-run into a double spend.
  function decreaseAllowance(address spender, uint256 subtracted) public returns (bool) {
    require(spender != address(0));
    _allowed[msg.sender][spender] = _allowed[msg.sender][spender].sub(subtracted);
    emit Approval(msg.sender, spender, _allowed[msg.sender][spender]);
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
