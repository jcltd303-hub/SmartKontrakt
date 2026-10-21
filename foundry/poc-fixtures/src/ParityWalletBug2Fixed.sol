// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 *   Dataset repo     : smartbugs/smartbugs-curated
 *   Dataset path     : dataset/access_control/parity_wallet_bug_2.sol
 *   @source          : https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-106#walletlibrarysol
 *   Original pragma  : pragma solidity ^0.4.9;
 *   Vulnerable lines : 226, 233
 *
 *   FIXED variant of ParityWalletBug2. Standard remediation: mark the deployed library
 *   as already initialised in its own constructor (`m_numOwners = 1`). The `only_uninitialized`
 *   guard on `initWallet` therefore fails for a standalone library, so an attacker can no
 *   longer take it over; with no owners, `kill`'s onlymanyowners check is also never satisfied.
 *   Same 0.4 -> 0.8 migration edits as the vulnerable port.
 */
pragma solidity ^0.8.24;

contract ParityWalletBug2FixedWalletEvents {
  event Confirmation(address owner, bytes32 operation);
  event Revoke(address owner, bytes32 operation);
  event OwnerChanged(address oldOwner, address newOwner);
  event OwnerAdded(address newOwner);
  event OwnerRemoved(address oldOwner);
  event RequirementChanged(uint256 newRequirement);
  event Deposit(address _from, uint256 value);
  event SingleTransact(address owner, uint256 value, address to, bytes data, address created);
  event MultiTransact(address owner, bytes32 operation, uint256 value, address to, bytes data, address created);
  event ConfirmationNeeded(bytes32 operation, address initiator, uint256 value, address to, bytes data);
}

abstract contract ParityWalletBug2FixedWalletAbi {
  function revoke(bytes32 _operation) external virtual;
  function changeOwner(address _from, address _to) external virtual;
  function addOwner(address _owner) external virtual;
  function removeOwner(address _owner) external virtual;
  function changeRequirement(uint256 _newRequired) external virtual;
  function isOwner(address _addr) external view virtual returns (bool);
  function hasConfirmed(bytes32 _operation, address _owner) external view virtual returns (bool);
  function setDailyLimit(uint256 _newLimit) external virtual;
  function execute(address _to, uint256 _value, bytes memory _data) external virtual returns (bytes32 o_hash);
  function confirm(bytes32 _h) external virtual returns (bool o_success);
}

contract ParityWalletBug2Fixed is ParityWalletBug2FixedWalletEvents {
  struct PendingState {
    uint256 yetNeeded;
    uint256 ownersDone;
    uint256 index;
  }

  struct Transaction {
    address to;
    uint256 value;
    bytes data;
  }

  modifier onlyowner {
    if (isOwner(msg.sender))
      _;
  }
  modifier onlymanyowners(bytes32 _operation) {
    if (confirmAndCheck(_operation))
      _;
  }

  // throw unless the contract is not yet initialized.
  modifier only_uninitialized { if (m_numOwners > 0) revert(); _; }

  // FIX: the library is marked initialised at deployment so it can never be taken over.
  constructor() {
    m_numOwners = 1;
  }

  fallback() external payable {
    if (msg.value > 0)
      emit Deposit(msg.sender, msg.value);
  }

  function initMultiowned(address[] memory _owners, uint256 _required) only_uninitialized public {
    m_numOwners = _owners.length + 1;
    m_owners[1] = uint256(uint160(msg.sender));
    m_ownerIndex[uint256(uint160(msg.sender))] = 1;
    for (uint256 i = 0; i < _owners.length; ++i)
    {
      m_owners[2 + i] = uint256(uint160(_owners[i]));
      m_ownerIndex[uint256(uint160(_owners[i]))] = 2 + i;
    }
    m_required = _required;
  }

  function revoke(bytes32 _operation) external {
    uint256 ownerIndex = m_ownerIndex[uint256(uint160(msg.sender))];
    if (ownerIndex == 0) return;
    uint256 ownerIndexBit = 2**ownerIndex;
    PendingState storage pending = m_pending[_operation];
    if (pending.ownersDone & ownerIndexBit > 0) {
      pending.yetNeeded++;
      pending.ownersDone -= ownerIndexBit;
      emit Revoke(msg.sender, _operation);
    }
  }

  function changeOwner(address _from, address _to) onlymanyowners(keccak256(msg.data)) external {
    if (isOwner(_to)) return;
    uint256 ownerIndex = m_ownerIndex[uint256(uint160(_from))];
    if (ownerIndex == 0) return;

    clearPending();
    m_owners[ownerIndex] = uint256(uint160(_to));
    m_ownerIndex[uint256(uint160(_from))] = 0;
    m_ownerIndex[uint256(uint160(_to))] = ownerIndex;
    emit OwnerChanged(_from, _to);
  }

  function addOwner(address _owner) onlymanyowners(keccak256(msg.data)) external {
    if (isOwner(_owner)) return;

    clearPending();
    if (m_numOwners >= c_maxOwners)
      reorganizeOwners();
    if (m_numOwners >= c_maxOwners)
      return;
    m_numOwners++;
    m_owners[m_numOwners] = uint256(uint160(_owner));
    m_ownerIndex[uint256(uint160(_owner))] = m_numOwners;
    emit OwnerAdded(_owner);
  }

  function removeOwner(address _owner) onlymanyowners(keccak256(msg.data)) external {
    uint256 ownerIndex = m_ownerIndex[uint256(uint160(_owner))];
    if (ownerIndex == 0) return;
    if (m_required > m_numOwners - 1) return;

    m_owners[ownerIndex] = 0;
    m_ownerIndex[uint256(uint160(_owner))] = 0;
    clearPending();
    reorganizeOwners();
    emit OwnerRemoved(_owner);
  }

  function changeRequirement(uint256 _newRequired) onlymanyowners(keccak256(msg.data)) external {
    if (_newRequired > m_numOwners) return;
    m_required = _newRequired;
    clearPending();
    emit RequirementChanged(_newRequired);
  }

  function getOwner(uint256 ownerIndex) external view returns (address) {
    return address(uint160(m_owners[ownerIndex + 1]));
  }

  function isOwner(address _addr) public view returns (bool) {
    return m_ownerIndex[uint256(uint160(_addr))] > 0;
  }

  function hasConfirmed(bytes32 _operation, address _owner) external view returns (bool) {
    PendingState storage pending = m_pending[_operation];
    uint256 ownerIndex = m_ownerIndex[uint256(uint160(_owner))];
    if (ownerIndex == 0) return false;
    uint256 ownerIndexBit = 2**ownerIndex;
    return !(pending.ownersDone & ownerIndexBit == 0);
  }

  function initDaylimit(uint256 _limit) only_uninitialized public {
    m_dailyLimit = _limit;
    m_lastDay = today();
  }
  function setDailyLimit(uint256 _newLimit) onlymanyowners(keccak256(msg.data)) external {
    m_dailyLimit = _newLimit;
  }
  function resetSpentToday() onlymanyowners(keccak256(msg.data)) external {
    m_spentToday = 0;
  }

  function initWallet(address[] memory _owners, uint256 _required, uint256 _daylimit) only_uninitialized public {
    initDaylimit(_daylimit);
    initMultiowned(_owners, _required);
  }

  function kill(address _to) onlymanyowners(keccak256(msg.data)) external {
    selfdestruct(payable(_to));
  }

  function execute(address _to, uint256 _value, bytes memory _data) external onlyowner returns (bytes32 o_hash) {
    if ((_data.length == 0 && underLimit(_value)) || m_required == 1) {
      address created;
      if (_to == address(0)) {
        created = create(_value, _data);
      } else {
        (bool ok, ) = _to.call{value: _value}(_data);
        if (!ok)
          revert();
      }
      emit SingleTransact(msg.sender, _value, _to, _data, created);
    } else {
      o_hash = keccak256(abi.encodePacked(msg.data, block.number));
      if (m_txs[o_hash].to == address(0) && m_txs[o_hash].value == 0 && m_txs[o_hash].data.length == 0) {
        m_txs[o_hash].to = _to;
        m_txs[o_hash].value = _value;
        m_txs[o_hash].data = _data;
      }
      if (!confirm(o_hash)) {
        emit ConfirmationNeeded(o_hash, msg.sender, _value, _to, _data);
      }
    }
  }

  function create(uint256 _value, bytes memory _code) internal returns (address o_addr) {
    /*
    assembly {
      o_addr := create(_value, add(_code, 0x20), mload(_code))
      jumpi(invalidJumpLabel, iszero(extcodesize(o_addr)))
    }
    */
  }

  function confirm(bytes32 _h) onlymanyowners(_h) public returns (bool o_success) {
    if (m_txs[_h].to != address(0) || m_txs[_h].value != 0 || m_txs[_h].data.length != 0) {
      address created;
      if (m_txs[_h].to == address(0)) {
        created = create(m_txs[_h].value, m_txs[_h].data);
      } else {
        (bool ok, ) = m_txs[_h].to.call{value: m_txs[_h].value}(m_txs[_h].data);
        if (!ok)
          revert();
      }
      emit MultiTransact(msg.sender, _h, m_txs[_h].value, m_txs[_h].to, m_txs[_h].data, created);
      delete m_txs[_h];
      return true;
    }
    return false;
  }

  function confirmAndCheck(bytes32 _operation) internal returns (bool) {
    uint256 ownerIndex = m_ownerIndex[uint256(uint160(msg.sender))];
    if (ownerIndex == 0) return false;

    PendingState storage pending = m_pending[_operation];
    if (pending.yetNeeded == 0) {
      pending.yetNeeded = m_required;
      pending.ownersDone = 0;
      pending.index = m_pendingIndex.length;
      m_pendingIndex.push(_operation);
    }
    uint256 ownerIndexBit = 2**ownerIndex;
    if (pending.ownersDone & ownerIndexBit == 0) {
      emit Confirmation(msg.sender, _operation);
      if (pending.yetNeeded <= 1) {
        delete m_pendingIndex[m_pending[_operation].index];
        delete m_pending[_operation];
        return true;
      }
      else
      {
        pending.yetNeeded--;
        pending.ownersDone |= ownerIndexBit;
      }
    }
    return false;
  }

  function reorganizeOwners() private {
    uint256 free = 1;
    while (free < m_numOwners)
    {
      while (free < m_numOwners && m_owners[free] != 0) free++;
      while (m_numOwners > 1 && m_owners[m_numOwners] == 0) m_numOwners--;
      if (free < m_numOwners && m_owners[m_numOwners] != 0 && m_owners[free] == 0)
      {
        m_owners[free] = m_owners[m_numOwners];
        m_ownerIndex[m_owners[free]] = free;
        m_owners[m_numOwners] = 0;
      }
    }
  }

  function underLimit(uint256 _value) internal onlyowner returns (bool) {
    if (today() > m_lastDay) {
      m_spentToday = 0;
      m_lastDay = today();
    }
    if (m_spentToday + _value >= m_spentToday && m_spentToday + _value <= m_dailyLimit) {
      m_spentToday += _value;
      return true;
    }
    return false;
  }

  function today() private view returns (uint256) { return block.timestamp / 1 days; }

  function clearPending() internal {
    uint256 length = m_pendingIndex.length;

    for (uint256 i = 0; i < length; ++i) {
      delete m_txs[m_pendingIndex[i]];

      if (m_pendingIndex[i] != 0)
        delete m_pending[m_pendingIndex[i]];
    }

    delete m_pendingIndex;
  }

  address constant _walletLibrary = 0xCAfEcAfeCAfECaFeCaFecaFecaFECafECafeCaFe;

  uint256 public m_required;
  uint256 public m_numOwners;
  uint256 public m_dailyLimit;
  uint256 public m_spentToday;
  uint256 public m_lastDay;
  uint256[256] m_owners;
  uint256 constant c_maxOwners = 250;
  mapping(uint256 => uint256) m_ownerIndex;
  mapping(bytes32 => PendingState) m_pending;
  bytes32[] m_pendingIndex;
  mapping (bytes32 => Transaction) m_txs;
}
