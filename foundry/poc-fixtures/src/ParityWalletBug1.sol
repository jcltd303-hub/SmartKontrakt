// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 *   Dataset repo     : smartbugs/smartbugs-curated
 *   Dataset path     : dataset/access_control/parity_wallet_bug_1.sol
 *   @source          : https://github.com/paritytech/parity-ethereum/blob/4d08e7b0aec46443bf26547b17d10cb302672835/js/src/contracts/snippets/enhanced-wallet.sol#L216
 *   Original pragma  : pragma solidity 0.4.9;   /* originally ^0.4.9, but doesn't compile with ^0.4.11 *\/
 *   Vulnerable lines : 223 (Wallet fallback `_walletLibrary.delegatecall(msg.data)`) and 437 (WalletLibrary.initWallet, unprotected)
 *
 *   Port: Solidity ^0.8.24. Migration edits:
 *     - sha3 -> keccak256 ; now -> block.timestamp ; constant -> view ; uint -> uint256 ; var -> explicit storage type
 *     - suicide(_to) -> selfdestruct(payable(_to)) ; throw -> revert()
 *     - x.call.value(v)(d) -> (bool ok,) = x.call{value:v}(d); if(!ok) revert()
 *     - address(uintN) -> address(uint160(uintN)) ; uintN(address) -> uint256(uint160(address))
 *     - function Wallet(...) -> constructor(...) ; function() payable -> fallback() external payable
 *     - create(): the 0.4-only `jumpi(invalidJumpLabel, ...)` has no 0.8 equivalent; rewritten
 *       as an explicit `if (o_addr.code.length == 0) revert();` after the CREATE (same semantics).
 *     - the Wallet's hasConfirmed()/isOwner() returned the raw `delegatecall` success flag; in 0.8
 *       `delegatecall` returns (bool, bytes), so the flag is destructured and returned. These two
 *       functions are NOT marked `view`: 0.8 would compile a `view` external call into STATICCALL,
 *       and a `view` function may not perform a delegatecall at all (it would be a compile error).
 *       Marking them non-view is required to preserve the original DELEGATECALL semantics.
 *     - confirmAndCheck() relied on 0.4's implicit "return default false"; an explicit
 *       `return false;` is added on the fall-through path (0.8 rejects a missing return).
 *   The vulnerable ordering is preserved verbatim: the Wallet's payable fallback forwards ANY
 *   caller-supplied calldata to the library via delegatecall, and WalletLibrary.initWallet has no
 *   guard, so anyone can (re)initialise the wallet as owner (SWC-105/SWC-112).
 */
pragma solidity ^0.8.24;

contract ParityWalletBug1WalletEvents {
  // EVENTS

  // this contract only has six types of events: it can accept a confirmation, in which case
  // we record owner and operation (hash) alongside it.
  event Confirmation(address owner, bytes32 operation);
  event Revoke(address owner, bytes32 operation);

  // some others are in the case of an owner changing.
  event OwnerChanged(address oldOwner, address newOwner);
  event OwnerAdded(address newOwner);
  event OwnerRemoved(address oldOwner);

  // the last one is emitted if the required signatures change
  event RequirementChanged(uint256 newRequirement);

  // Funds has arrived into the wallet (record how much).
  event Deposit(address _from, uint256 value);
  // Single transaction going out of the wallet (record who signed for it, how much, and to whom it's going).
  event SingleTransact(address owner, uint256 value, address to, bytes data, address created);
  // Multi-sig transaction going out of the wallet (record who signed for it last, the operation hash, how much, and to whom it's going).
  event MultiTransact(address owner, bytes32 operation, uint256 value, address to, bytes data, address created);
  // Confirmation still needed for a transaction.
  event ConfirmationNeeded(bytes32 operation, address initiator, uint256 value, address to, bytes data);
}

abstract contract ParityWalletBug1WalletAbi {
  // Revokes a prior confirmation of the given operation
  function revoke(bytes32 _operation) external virtual;

  // Replaces an owner `_from` with another `_to`.
  function changeOwner(address _from, address _to) external virtual;

  function addOwner(address _owner) external virtual;

  function removeOwner(address _owner) external virtual;

  function changeRequirement(uint256 _newRequired) external virtual;

  function isOwner(address _addr) external view virtual returns (bool);

  function hasConfirmed(bytes32 _operation, address _owner) external view virtual returns (bool);

  // (re)sets the daily limit. needs many of the owners to confirm. doesn't alter the amount already spent today.
  function setDailyLimit(uint256 _newLimit) external virtual;

  function execute(address _to, uint256 _value, bytes memory _data) external virtual returns (bytes32 o_hash);
  function confirm(bytes32 _h) external virtual returns (bool o_success);
}

contract ParityWalletBug1WalletLibrary is ParityWalletBug1WalletEvents {
  // TYPES

  // struct for the status of a pending operation.
  struct PendingState {
    uint256 yetNeeded;
    uint256 ownersDone;
    uint256 index;
  }

  // Transaction structure to remember details of transaction lest it need be saved for a later call.
  struct Transaction {
    address to;
    uint256 value;
    bytes data;
  }

  // MODIFIERS

  // simple single-sig function modifier.
  modifier onlyowner {
    if (isOwner(msg.sender))
      _;
  }
  // multi-sig function modifier: the operation must have an intrinsic hash in order
  // that later attempts can be realised as the same underlying operation and
  // thus count as confirmations.
  modifier onlymanyowners(bytes32 _operation) {
    if (confirmAndCheck(_operation))
      _;
  }

  // METHODS

  // gets called when no other function matches
  fallback() external payable {
    // just being sent some cash?
    if (msg.value > 0)
      emit Deposit(msg.sender, msg.value);
  }

  // constructor is given number of sigs required to do protected "onlymanyowners" transactions
  // as well as the selection of addresses capable of confirming them.
  function initMultiowned(address[] memory _owners, uint256 _required) public {
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

  // Revokes a prior confirmation of the given operation
  function revoke(bytes32 _operation) external {
    uint256 ownerIndex = m_ownerIndex[uint256(uint160(msg.sender))];
    // make sure they're an owner
    if (ownerIndex == 0) return;
    uint256 ownerIndexBit = 2**ownerIndex;
    PendingState storage pending = m_pending[_operation];
    if (pending.ownersDone & ownerIndexBit > 0) {
      pending.yetNeeded++;
      pending.ownersDone -= ownerIndexBit;
      emit Revoke(msg.sender, _operation);
    }
  }

  // Replaces an owner `_from` with another `_to`.
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
    reorganizeOwners(); //make sure m_numOwner is equal to the number of owners and always points to the optimal free slot
    emit OwnerRemoved(_owner);
  }

  function changeRequirement(uint256 _newRequired) onlymanyowners(keccak256(msg.data)) external {
    if (_newRequired > m_numOwners) return;
    m_required = _newRequired;
    clearPending();
    emit RequirementChanged(_newRequired);
  }

  // Gets an owner by 0-indexed position (using numOwners as the count)
  function getOwner(uint256 ownerIndex) external view returns (address) {
    return address(uint160(m_owners[ownerIndex + 1]));
  }

  function isOwner(address _addr) public view returns (bool) {
    return m_ownerIndex[uint256(uint160(_addr))] > 0;
  }

  function hasConfirmed(bytes32 _operation, address _owner) external view returns (bool) {
    PendingState storage pending = m_pending[_operation];
    uint256 ownerIndex = m_ownerIndex[uint256(uint160(_owner))];

    // make sure they're an owner
    if (ownerIndex == 0) return false;

    // determine the bit to set for this owner.
    uint256 ownerIndexBit = 2**ownerIndex;
    return !(pending.ownersDone & ownerIndexBit == 0);
  }

  // constructor - stores initial daily limit and records the present day's index.
  function initDaylimit(uint256 _limit) public {
    m_dailyLimit = _limit;
    m_lastDay = today();
  }
  // (re)sets the daily limit. needs many of the owners to confirm. doesn't alter the amount already spent today.
  function setDailyLimit(uint256 _newLimit) onlymanyowners(keccak256(msg.data)) external {
    m_dailyLimit = _newLimit;
  }
  // resets the amount already spent today. needs many of the owners to confirm.
  function resetSpentToday() onlymanyowners(keccak256(msg.data)) external {
    m_spentToday = 0;
  }

  // constructor - just pass on the owner array to the multiowned and
  // the limit to daylimit
  // <yes> <report> ACCESS_CONTROL   (vulnerable line 437: initWallet has no guard)
  function initWallet(address[] memory _owners, uint256 _required, uint256 _daylimit) public {
    initDaylimit(_daylimit);
    initMultiowned(_owners, _required);
  }

  // kills the contract sending everything to `_to`.
  function kill(address _to) onlymanyowners(keccak256(msg.data)) external {
    selfdestruct(payable(_to));
  }

  // Outside-visible transact entry point. Executes transaction immediately if below daily spend limit.
  // If not, goes into multisig process. We provide a hash on return to allow the sender to provide
  // shortcuts for the other confirmations (allowing them to avoid replicating the _to, _value
  // and _data arguments). They still get the option of using them if they want, anyways.
  function execute(address _to, uint256 _value, bytes memory _data) external onlyowner returns (bytes32 o_hash) {
    // first, take the opportunity to check that we're under the daily limit.
    if ((_data.length == 0 && underLimit(_value)) || m_required == 1) {
      // yes - just execute the call.
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
      // determine our operation hash.
      o_hash = keccak256(abi.encodePacked(msg.data, block.number));
      // store if it's new
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
    assembly {
      o_addr := create(_value, add(_code, 0x20), mload(_code))
    }
    if (o_addr.code.length == 0)
      revert();
  }

  // confirm a transaction through just the hash. we use the previous transactions map, m_txs, in order
  // to determine the body of the transaction from the hash provided.
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

  // INTERNAL METHODS

  function confirmAndCheck(bytes32 _operation) internal returns (bool) {
    // determine what index the present sender is:
    uint256 ownerIndex = m_ownerIndex[uint256(uint160(msg.sender))];
    // make sure they're an owner
    if (ownerIndex == 0) return false;

    PendingState storage pending = m_pending[_operation];
    // if we're not yet working on this operation, switch over and reset the confirmation status.
    if (pending.yetNeeded == 0) {
      // reset count of confirmations needed.
      pending.yetNeeded = m_required;
      // reset which owners have confirmed (none) - set our bitmap to 0.
      pending.ownersDone = 0;
      pending.index = m_pendingIndex.length;
      m_pendingIndex.push(_operation);
    }
    // determine the bit to set for this owner.
    uint256 ownerIndexBit = 2**ownerIndex;
    // make sure we (the message sender) haven't confirmed this operation previously.
    if (pending.ownersDone & ownerIndexBit == 0) {
      emit Confirmation(msg.sender, _operation);
      // ok - check if count is enough to go ahead.
      if (pending.yetNeeded <= 1) {
        // enough confirmations: reset and run interior.
        delete m_pendingIndex[m_pending[_operation].index];
        delete m_pending[_operation];
        return true;
      }
      else
      {
        // not enough: record that this owner in particular confirmed.
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

  // checks to see if there is at least `_value` left from the daily limit today. if there is, subtracts it and
  // returns true. otherwise just returns false.
  function underLimit(uint256 _value) internal onlyowner returns (bool) {
    // reset the spend limit if we're on a different day to last time.
    if (today() > m_lastDay) {
      m_spentToday = 0;
      m_lastDay = today();
    }
    // check to see if there's enough left - if so, subtract and return true.
    // overflow protection                    // dailyLimit check
    if (m_spentToday + _value >= m_spentToday && m_spentToday + _value <= m_dailyLimit) {
      m_spentToday += _value;
      return true;
    }
    return false;
  }

  // determines today's index.
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

  // FIELDS
  address constant _walletLibrary = 0xCAfEcAfeCAfECaFeCaFecaFecaFECafECafeCaFe;

  // the number of owners that must confirm the same operation before it is run.
  uint256 public m_required;
  // pointer used to find a free slot in m_owners
  uint256 public m_numOwners;

  uint256 public m_dailyLimit;
  uint256 public m_spentToday;
  uint256 public m_lastDay;

  // list of owners
  uint256[256] m_owners;

  uint256 constant c_maxOwners = 250;
  // index on the list of owners to allow reverse lookup
  mapping(uint256 => uint256) m_ownerIndex;
  // the ongoing operations.
  mapping(bytes32 => PendingState) m_pending;
  bytes32[] m_pendingIndex;

  // pending transactions we have at present.
  mapping (bytes32 => Transaction) m_txs;
}

contract ParityWalletBug1 is ParityWalletBug1WalletEvents {

  // WALLET CONSTRUCTOR
  //   calls the `initWallet` method of the Library in this context
  constructor(address[] memory _owners, uint256 _required, uint256 _daylimit) payable {
    // Signature of the Wallet Library's init function
    bytes4 sig = bytes4(keccak256("initWallet(address[],uint256,uint256)"));
    address target = _walletLibrary;

    // Compute the size of the call data : arrays has 2
    // 32bytes for offset and length, plus 32bytes per element ;
    // plus 2 32bytes for each uint
    uint256 argarraysize = (2 + _owners.length);
    uint256 argsize = (2 + argarraysize) * 32;

    assembly {
      // Add the signature first to memory
      mstore(0x0, sig)
      // Add the call data, which is at the end of the
      // code
      codecopy(0x4,  sub(codesize(), argsize), argsize)
      // Delegate call to the library
      pop(delegatecall(sub(gas(), 10000), target, 0x0, add(argsize, 0x4), 0x0, 0x0))
    }
  }

  // METHODS

  // gets called when no other function matches
  fallback() external payable {
    // just being sent some cash?
    if (msg.value > 0)
      emit Deposit(msg.sender, msg.value);
    else if (msg.data.length > 0)
     // <yes> <report> ACCESS_CONTROL   (vulnerable line 223)
      _walletLibrary.delegatecall(msg.data); //it should have whitelisted specific methods that the user is allowed to call
  }

  // Gets an owner by 0-indexed position (using numOwners as the count)
  function getOwner(uint256 ownerIndex) external view returns (address) {
    return address(uint160(m_owners[ownerIndex + 1]));
  }

  // As return statement unavailable in fallback, explicit the method here

  function hasConfirmed(bytes32, address) external returns (bool) {
    (bool ok, ) = _walletLibrary.delegatecall(msg.data);
    return ok;
  }

  function isOwner(address) external returns (bool) {
    (bool ok, ) = _walletLibrary.delegatecall(msg.data);
    return ok;
  }

  // FIELDS
  address constant _walletLibrary = 0xCAfEcAfeCAfECaFeCaFecaFecaFECafECafeCaFe;

  // the number of owners that must confirm the same operation before it is run.
  uint256 public m_required;
  // pointer used to find a free slot in m_owners
  uint256 public m_numOwners;

  uint256 public m_dailyLimit;
  uint256 public m_spentToday;
  uint256 public m_lastDay;

  // list of owners
  uint256[256] m_owners;
}
