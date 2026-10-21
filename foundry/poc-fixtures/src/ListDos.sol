/*
 * PROVENANCE
 * -------------------------------------------------------------------
 * Dataset repo : smartbugs/smartbugs-curated
 * Dataset path : dataset/denial_of_service/list_dos.sol
 * Upstream @source: https://etherscan.io/address/0xf45717552f12ef7cb65e95476f217ea008167ae3#code
 * Original pragma: ^0.4.0
 * Original vulnerable line(s): 46,48  (DENIAL_OF_SERVICE)
 * Port pragma  : ^0.8.24
 *
 * Migration edits (mechanical 0.4 -> 0.8 only):
 *   - uint/uint8 -> uint256/uint8 kept; explicit visibility on all functions.
 *   - `function Government()` -> `constructor()`.
 *   - fallback `function()` -> `fallback() external payable`.
 *   - `msg.sender.send(x)` -> `payable(msg.sender).send(x)`; likewise for the
 *     creditor / elite / buddy sends (0.8 needs a payable type).
 *   - `this.balance` -> `address(this).balance`.
 *   - view added to the read-only helpers (totalDebt/totalPayedOut/getters).
 * The vulnerable ordering (state reset including the two array wipes) is
 * preserved verbatim.
 *
 * VULNERABILITY: any participant may trigger the 12-hour "breakdown" branch.
 * Inside it, `creditorAddresses` and `creditorAmounts` are both replaced with
 * fresh empty arrays, so every creditor's recorded claim is destroyed. A single
 * griefer therefore denies service to all creditors: their loans are erased and
 * can never be repaid.
 */
pragma solidity ^0.8.24;

contract ListDos {

     // Global Variables
     uint32 public lastCreditorPayedOut;
     uint256 public lastTimeOfNewCredit;
     uint256 public profitFromCrash;
     address[] public creditorAddresses;
     uint256[] public creditorAmounts;
     address public corruptElite;
     mapping (address => uint256) buddies;
     uint256 constant TWELVE_HOURS = 43200;
     uint8 public round;

     constructor() payable {
         // The corrupt elite establishes a new government
         // this is the commitment of the corrupt Elite - everything that can not be saved from a crash
         profitFromCrash = msg.value;
         corruptElite = msg.sender;
         lastTimeOfNewCredit = block.timestamp;
     }

     function lendGovernmentMoney(address buddy) public payable returns (bool) {
         uint256 amount = msg.value;
         // check if the system already broke down. If for 12h no new creditor gives new credit to the system it will brake down.
         // 12h are on average = 60*60*12/12.5 = 3456
         if (lastTimeOfNewCredit + TWELVE_HOURS < block.timestamp) {
             // Return money to sender
             payable(msg.sender).send(amount);
             // Sends all contract money to the last creditor
             payable(creditorAddresses[creditorAddresses.length - 1]).send(profitFromCrash);
             payable(corruptElite).send(address(this).balance);
             // Reset contract state
             lastCreditorPayedOut = 0;
             lastTimeOfNewCredit = block.timestamp;
             profitFromCrash = 0;
            // <yes> <report> DENIAL_OF_SERVICE
             creditorAddresses = new address[](0);
            // <yes> <report> DENIAL_OF_SERVICE
             creditorAmounts = new uint256[](0);
             round += 1;
             return false;
         }
         else {
             // the system needs to collect at least 1% of the profit from a crash to stay alive
             if (amount >= 10 ** 18) {
                 // the System has received fresh money, it will survive at leat 12h more
                 lastTimeOfNewCredit = block.timestamp;
                 // register the new creditor and his amount with 10% interest rate
                 creditorAddresses.push(msg.sender);
                 creditorAmounts.push(amount * 110 / 100);
                 // now the money is distributed
                 // first the corrupt elite grabs 5% - thieves!
                 payable(corruptElite).send(amount * 5/100);
                 // 5% are going into the economy (they will increase the value for the person seeing the crash comming)
                 if (profitFromCrash < 10000 * 10**18) {
                     profitFromCrash += amount * 5/100;
                 }
                 // if you have a buddy in the government (and he is in the creditor list) he can get 5% of your credits.
                 // Make a deal with him.
                 if(buddies[buddy] >= amount) {
                     payable(buddy).send(amount * 5/100);
                 }
                 buddies[msg.sender] += amount * 110 / 100;
                 // 90% of the money will be used to pay out old creditors
                 if (creditorAmounts[lastCreditorPayedOut] <= address(this).balance - profitFromCrash) {
                     payable(creditorAddresses[lastCreditorPayedOut]).send(creditorAmounts[lastCreditorPayedOut]);
                     buddies[creditorAddresses[lastCreditorPayedOut]] -= creditorAmounts[lastCreditorPayedOut];
                     lastCreditorPayedOut += 1;
                 }
                 return true;
             }
             else {
                 payable(msg.sender).send(amount);
                 return false;
             }
         }
     }

     // fallback function
     fallback() external payable {
         lendGovernmentMoney(address(0));
     }

     function totalDebt() public view returns (uint256 debt) {
         for(uint256 i=lastCreditorPayedOut; i<creditorAmounts.length; i++){
             debt += creditorAmounts[i];
         }
     }

     function totalPayedOut() public view returns (uint256 payout) {
         for(uint256 i=0; i<lastCreditorPayedOut; i++){
             payout += creditorAmounts[i];
         }
     }

     // better don't do it (unless you are the corrupt elite and you want to establish trust in the system)
     function investInTheSystem() public payable {
         profitFromCrash += msg.value;
     }

     // From time to time the corrupt elite inherits it's power to the next generation
     function inheritToNextGeneration(address nextGeneration) public {
         if (msg.sender == corruptElite) {
             corruptElite = nextGeneration;
         }
     }

     function getCreditorAddresses() public view returns (address[] memory) {
         return creditorAddresses;
     }

     function getCreditorAmounts() public view returns (uint256[] memory) {
         return creditorAmounts;
     }
 }
