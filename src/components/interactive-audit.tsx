import { useState } from "react";
import { Terminal, Play, Wand2, CheckCircle2, RefreshCcw, FileCode, Cpu } from "lucide-react";
import { runPocOnBackend, getBackendUrl } from "@/lib/audit/foundry-backend";
import { requestPocRepair } from "@/lib/audit/ai.functions";
import type { PocResult } from "@/lib/audit/types";

export function InteractiveAuditTab() {
  const [solidityCode, setSolidityCode] = useState<string>(
    `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

contract Vault {
    mapping(address => uint256) public balances;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount; // Vulnerability: State update after external call!
    }
}
`
  );

  const [testCode, setTestCode] = useState<string>(
    `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Vault.sol";

contract PoC is Test {
    Vault vault;
    
    function setUp() public {
        vault = new Vault();
    }
    
    function test_reentrancy() public {
        // Exploit logic here
        vault.deposit{value: 1 ether}();
        vault.withdraw(1 ether);
    }
}
`
  );

  const [targetAddress, setTargetAddress] = useState<string>("0x000000000000000000000000000000000000dead");
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [isRepairing, setIsRepairing] = useState<boolean>(false);
  const [pocResult, setPocResult] = useState<PocResult | null>(null);
  const [repairNotice, setRepairNotice] = useState<string | null>(null);

  const handleRunPoc = async () => {
    setIsRunning(true);
    setRepairNotice(null);
    try {
      const res = await runPocOnBackend(getBackendUrl(), {
        address: targetAddress,
        testCode: testCode,
      });
      setPocResult(res);
    } catch (err) {
      setPocResult({
        status: "backend_unreachable",
        logs: err instanceof Error ? err.message : String(err),
        durationMs: 0,
        runAt: new Date().toISOString(),
      });
    } finally {
      setIsRunning(false);
    }
  };

  const handleFixPoc = async () => {
    if (!pocResult || !pocResult.logs) return;
    setIsRepairing(true);
    setRepairNotice(null);
    try {
      const res = await requestPocRepair({
        data: {
          contractName: "InteractiveVault",
          originalCode: testCode,
          errorLogs: pocResult.logs,
          body: solidityCode,
        },
      });
      if (res && res.fixedCode) {
        setTestCode(res.fixedCode);
        setRepairNotice("PoC successfully repaired by LLM! You can now re-run the test.");
      }
    } catch (err) {
      setRepairNotice(`Repair failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsRepairing(false);
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 p-6 max-w-7xl mx-auto">
      {/* Left Column: Solidity Editor & Audit Checklist */}
      <div className="lg:col-span-6 flex flex-col gap-4">
        <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 shadow-sm flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-[#f4efe6] font-semibold">
              <FileCode className="w-4 h-4 text-[#e8a54b]" />
              <span>Interactive Solidity Contract</span>
            </div>
            <span className="text-xs font-mono text-[#a39886]">Solidity ^0.8.24</span>
          </div>
          <p className="text-xs text-[#a39886]">
            Modify the contract source code below to experiment with custom audit scenarios and vulnerabilities.
          </p>
          <textarea
            value={solidityCode}
            onChange={(e) => setSolidityCode(e.target.value)}
            rows={14}
            className="w-full font-mono text-xs bg-[#12110e] border border-[#3a3428] text-[#f4efe6] rounded-lg p-3 focus:outline-none focus:border-[#e8a54b]"
          />
        </div>

        <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 shadow-sm flex flex-col gap-2">
          <h4 className="text-sm font-semibold text-[#f4efe6] flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>Interactive Audit Guidance</span>
          </h4>
          <ul className="text-xs text-[#a39886] space-y-1.5 list-disc list-inside">
            <li>Check for reentrancy vectors in state mutations following external calls.</li>
            <li>Verify access controls on critical administrative functions.</li>
            <li>Inspect precision loss in arithmetic calculations (div-before-mul).</li>
          </ul>
        </div>
      </div>

      {/* Right Column: Foundry Test Harness & LLM Repair */}
      <div className="lg:col-span-6 flex flex-col gap-4">
        <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 shadow-sm flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-[#f4efe6] font-semibold">
              <Terminal className="w-4 h-4 text-[#e8a54b]" />
              <span>Foundry Test & PoC Harness</span>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={targetAddress}
                onChange={(e) => setTargetAddress(e.target.value)}
                placeholder="Target 0x..."
                className="bg-[#12110e] border border-[#3a3428] text-xs font-mono text-[#f4efe6] px-2 py-1 rounded w-36"
              />
              <button
                onClick={handleRunPoc}
                disabled={isRunning}
                className="px-3 py-1.5 bg-[#e8a54b] hover:bg-[#d6933c] text-[#12110e] font-bold text-xs rounded flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                {isRunning ? <RefreshCcw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                <span>Run PoC</span>
              </button>
            </div>
          </div>
          <p className="text-xs text-[#a39886]">
            Write or adjust your Foundry test below. If execution fails to compile or run, use the LLM Fix button to automatically repair the test code.
          </p>
          <textarea
            value={testCode}
            onChange={(e) => setTestCode(e.target.value)}
            rows={14}
            className="w-full font-mono text-xs bg-[#12110e] border border-[#3a3428] text-[#f4efe6] rounded-lg p-3 focus:outline-none focus:border-[#e8a54b]"
          />
        </div>

        {/* Execution Results & Fix Button */}
        <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 shadow-sm flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <h4 className="text-sm font-semibold text-[#f4efe6] flex items-center gap-2">
              <Cpu className="w-4 h-4 text-[#e8a54b]" />
              <span>Execution Output & LLM Repair</span>
            </h4>
            {pocResult && (pocResult.status === "error" || pocResult.status === "failed") && (
              <button
                onClick={handleFixPoc}
                disabled={isRepairing}
                className="px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs rounded flex items-center gap-1.5 shadow transition-colors disabled:opacity-50"
              >
                {isRepairing ? <RefreshCcw className="w-3.5 h-3.5 animate-spin" /> : <Wand2 className="w-3.5 h-3.5" />}
                <span>Fix PoC with LLM</span>
              </button>
            )}
          </div>

          {repairNotice && (
            <div className="p-2.5 rounded bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 text-xs">
              {repairNotice}
            </div>
          )}

          <div className="bg-[#12110e] border border-[#3a3428] rounded-lg p-3 font-mono text-xs text-[#a39886] min-h-[120px] max-h-60 overflow-y-auto whitespace-pre-wrap">
            {isRunning ? (
              <span className="text-[#e8a54b] animate-pulse">Running Foundry test on backend...</span>
            ) : pocResult ? (
              <div>
                <div className="flex items-center gap-2 mb-2 pb-2 border-b border-[#3a3428]">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      pocResult.status === "passed"
                        ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                        : pocResult.status === "failed"
                        ? "bg-amber-950 text-amber-400 border border-amber-800"
                        : "bg-rose-950 text-rose-400 border border-rose-800"
                    }`}
                  >
                    {pocResult.status}
                  </span>
                  <span className="text-[#a39886]">{pocResult.durationMs}ms</span>
                </div>
                <div className="text-[#f4efe6]">{pocResult.logs || "(No output logs)"}</div>
              </div>
            ) : (
              <span className="text-[#655d4e]">Run the PoC above to see compilation and execution logs here.</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
