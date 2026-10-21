/*
 * PROVENANCE
 * -------------------------------------------------------------------
 * Dataset repo : smartbugs/smartbugs-curated
 * Dataset path : dataset/denial_of_service/list_dos.sol
 * Upstream @source: https://etherscan.io/address/0xf45717552f12ef7cb65e95476f217ea008167ae3#code
 * Original pragma: ^0.4.0
 * Original vulnerable line(s): 46,48
 * Fixed variant: ListDosFixed
 *
 * REMEDIATION (DoS): (1) creditor records are PRESERVED across a breakdown so a
 * single griefer cannot erase everyone's claims; (2) payouts are made by
 * pull-payment (crediting a withdrawable balance) so a failing recipient can
 * never block the flow.
 */
pragma solidity ^0.8.24;

contract ListDosFixed {

     uint32 public lastCreditorPayedOut;
     uint256 public lastTimeOfNewCredit;
     uint256 public profitFromCrash;
     address[] public creditorAddresses;
     uint256[] public creditorAmounts;
     address public corruptElite;
     mapping (address => uint256) buddies;
     uint256 constant TWELVE_HOURS = 43200;
     uint8 public round;

     // FIX: pull-payment balances instead of push `.send()`.
     mapping (address => uint256) public payouts;

     constructor() payable {
         profitFromCrash = msg.value;
         corruptElite = msg.sender;
         lastTimeOfNewCredit = block.timestamp;
     }

     function lendGovernmentMoney(address buddy) public payable returns (bool) {
         uint256 amount = msg.value;
         if (lastTimeOfNewCredit + TWELVE_HOURS < block.timestamp) {
             // FIX: credit balances (pull payments) - a failing recipient cannot block.
             payouts[msg.sender] += amount;
             payouts[creditorAddresses[creditorAddresses.length - 1]] += profitFromCrash;
             payouts[corruptElite] += address(this).balance;
             lastCreditorPayedOut = 0;
             lastTimeOfNewCredit = block.timestamp;
             profitFromCrash = 0;
             // FIX: creditor records are NOT wiped.
             round += 1;
             return false;
         }
         else {
             if (amount >= 10 ** 18) {
                 lastTimeOfNewCredit = block.timestamp;
                 creditorAddresses.push(msg.sender);
                 creditorAmounts.push(amount * 110 / 100);
                 payouts[corruptElite] += amount * 5/100;
                 if (profitFromCrash < 10000 * 10**18) {
                     profitFromCrash += amount * 5/100;
                 }
                 if(buddies[buddy] >= amount) {
                     payouts[buddy] += amount * 5/100;
                 }
                 buddies[msg.sender] += amount * 110 / 100;
                 if (creditorAmounts[lastCreditorPayedOut] <= address(this).balance - profitFromCrash) {
                     payouts[creditorAddresses[lastCreditorPayedOut]] += creditorAmounts[lastCreditorPayedOut];
                     buddies[creditorAddresses[lastCreditorPayedOut]] -= creditorAmounts[lastCreditorPayedOut];
                     lastCreditorPayedOut += 1;
                 }
                 return true;
             }
             else {
                 payouts[msg.sender] += amount;
                 return false;
             }
         }
     }

     // FIX: pull payments let each creditor withdraw without blocking others.
     function withdraw() public {
         uint256 a = payouts[msg.sender];
         payouts[msg.sender] = 0;
         (bool ok, ) = payable(msg.sender).call{value: a}("");
         require(ok, "withdraw failed");
     }

     fallback() external payable {
         lendGovernmentMoney(address(0));
     }

     function getCreditorAddresses() public view returns (address[] memory) {
         return creditorAddresses;
     }

     function getCreditorAmounts() public view returns (uint256[] memory) {
         return creditorAmounts;
     }
 }
