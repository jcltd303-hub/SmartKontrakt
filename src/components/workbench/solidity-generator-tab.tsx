import { useState, useEffect } from "react";
import {
  ArrowRightLeft,
  BookOpen,
  Check,
  Code2,
  Copy,
  Download,
  FileCode,
  Flame,
  Loader2,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
} from "lucide-react";
import { downloadFile } from "@/lib/download-file";
import { convertFoundryToPlainSolidityFn } from "@/lib/audit/ai.functions";
import type { ConvertFoundryResult, ConvertMode } from "@/lib/audit/convert-foundry.server";
import type { WorkbenchController } from "./use-workbench-controller";

type SolidityGeneratorTabProps = Pick<
  WorkbenchController,
  | "activeTab"
  | "report"
  | "contractBody"
  | "setContractBody"
  | "singleAddress"
  | "singleAddressChain"
  | "aiReview"
>;

const SAMPLE_FOUNDRY_PRESETS = [
  {
    id: "reentrancy",
    label: "Reentrancy & Vault Draining",
    description: "Foundry test verifying reentrancy exploit on ether withdrawal",
    code: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IVault {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
    function balances(address user) external view returns (uint256);
}

contract ReentrancyTest is Test {
    IVault target;
    address attacker;

    function setUp() public {
        vm.createSelectFork(vm.envString("ETH_RPC_URL"));
        target = IVault(vm.envAddress("POC_TARGET"));
        attacker = makeAddr("attacker");
        vm.deal(attacker, 2 ether);
    }

    function test_reentrancy_exploit() public {
        vm.startPrank(attacker);
        target.deposit{value: 1 ether}();
        target.withdraw(1 ether);
        vm.stopPrank();

        // Validate target was drained
        assertEq(address(target).balance, 0, "Target balance should be drained");
    }

    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdraw(1 ether);
        }
    }
}`,
  },
  {
    id: "erc20_allowance",
    label: "ERC20 Approval & State Validation",
    description: "Foundry test verifying token allowance and transferFrom state changes",
    code: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
}

contract TokenTransferTest is Test {
    IERC20 token;
    address alice;
    address bob;

    function setUp() public {
        token = IERC20(vm.envAddress("TOKEN_ADDRESS"));
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        deal(address(token), alice, 1000e18);
    }

    function test_transferFrom_validation() public {
        // Alice approves Bob for 500 tokens
        vm.prank(alice);
        token.approve(bob, 500e18);
        assertEq(token.allowance(alice, bob), 500e18, "Allowance mismatch");

        // Bob executes transferFrom
        vm.prank(bob);
        token.transferFrom(alice, bob, 500e18);

        // State validation assertions
        assertEq(token.balanceOf(alice), 500e18, "Alice balance incorrect");
        assertEq(token.balanceOf(bob), 500e18, "Bob balance incorrect");
        assertEq(token.allowance(alice, bob), 0, "Allowance should be depleted");
    }
}`,
  },
  {
    id: "access_control",
    label: "Access Control & Role Validation",
    description: "Foundry test verifying unauthorized callers revert and admin calls succeed",
    code: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IManagedProtocol {
    function setFeeRate(uint256 newRate) external;
    function pause() external;
    function feeRate() external view returns (uint256);
    function owner() external view returns (address);
}

contract AccessControlTest is Test {
    IManagedProtocol protocol;
    address admin;
    address rando;

    function setUp() public {
        protocol = IManagedProtocol(vm.envAddress("PROTOCOL_TARGET"));
        admin = protocol.owner();
        rando = makeAddr("rando");
    }

    function test_unauthorized_revert_validation() public {
        // Random user cannot set fee
        vm.prank(rando);
        vm.expectRevert("Ownable: caller is not the owner");
        protocol.setFeeRate(500);

        // Admin successfully sets fee
        vm.prank(admin);
        protocol.setFeeRate(250);
        assertEq(protocol.feeRate(), 250, "Fee rate was not updated");
    }
}`,
  },
];

export function SolidityGeneratorTab({
  activeTab,
  report,
  contractBody,
  setContractBody,
  singleAddress,
  singleAddressChain,
  aiReview,
}: SolidityGeneratorTabProps) {
  const [foundryInput, setFoundryInput] = useState<string>("");
  const [contractName, setContractName] = useState<string>(report?.label || "TargetContract");
  const [targetAddressInput, setTargetAddressInput] = useState<string>(singleAddress || "");
  const [mode, setMode] = useState<ConvertMode>("interaction");
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [result, setResult] = useState<ConvertFoundryResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [showMatrix, setShowMatrix] = useState<boolean>(true);

  // Auto-prefill if AI review test code exists and input is empty
  useEffect(() => {
    if (aiReview?.foundryTestCode && !foundryInput) {
      setFoundryInput(aiReview.foundryTestCode);
    }
  }, [aiReview?.foundryTestCode, foundryInput]);

  // Keep target address in sync if singleAddress changes
  useEffect(() => {
    if (singleAddress && !targetAddressInput) {
      setTargetAddressInput(singleAddress);
    }
  }, [singleAddress, targetAddressInput]);

  useEffect(() => {
    if (report?.label && contractName === "TargetContract") {
      setContractName(report.label);
    }
  }, [report?.label, contractName]);

  if (activeTab !== "solidity-generator") return null;

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleDownload = () => {
    if (!result?.plainSolidityCode) return;
    const safeName = (contractName || "Target").replace(/[^a-zA-Z0-9_]/g, "");
    downloadFile(`${safeName}_InteractionValidation.sol`, result.plainSolidityCode);
  };

  const handleGenerate = async () => {
    const code = foundryInput.trim();
    if (!code) {
      setError("Please paste Foundry test code to generate plain Solidity.");
      return;
    }

    setIsGenerating(true);
    setError(null);

    try {
      const res = await convertFoundryToPlainSolidityFn({
        data: {
          foundryCode: code,
          contractName: contractName || "TargetContract",
          contractSource: contractBody ? contractBody.slice(0, 12000) : "",
          targetAddress: targetAddressInput.trim() || undefined,
          mode,
        },
      });
      setResult(res);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to generate plain Solidity code via LLM.",
      );
    } finally {
      setIsGenerating(false);
    }
  };

  const handleLoadPreset = (code: string) => {
    setFoundryInput(code);
    setError(null);
  };

  const handlePasteClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setFoundryInput(text);
        setError(null);
      }
    } catch {
      // clipboard access denied, ignore
    }
  };

  return (
    <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-5 flex flex-col gap-5 font-mono text-xs">
      {/* Top Banner / Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-4 border-b border-[#3a3428]">
        <div>
          <div className="flex items-center gap-2">
            <Code2 className="w-5 h-5 text-[#e8a54b]" />
            <h2 className="text-base font-bold text-[#f4efe6]">
              Foundry → Plain Solidity Generator
            </h2>
            <span className="px-2 py-0.5 rounded text-[10px] bg-[#e8a54b]/20 border border-[#e8a54b]/40 text-[#e8a54b] font-semibold">
              LLM Interaction & State Validation
            </span>
          </div>
          <p className="text-xs text-[#a39886] mt-1 max-w-3xl leading-relaxed">
            Paste Foundry test code (<code className="text-amber-200">forge-std/Test.sol</code>,{" "}
            <code className="text-amber-200">vm.*</code> cheatcodes, assertions) to automatically
            synthesize standalone Plain Solidity contracts that execute target interactions and
            assert state invariants natively without Foundry dependencies.
          </p>
        </div>

        <div className="flex items-center gap-2 self-start md:self-auto">
          <button
            onClick={() => setShowMatrix(!showMatrix)}
            className="px-3 py-1.5 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#a39886] hover:text-[#f4efe6] text-xs flex items-center gap-1.5 transition-colors"
          >
            <BookOpen className="w-3.5 h-3.5 text-[#e8a54b]" />
            <span>{showMatrix ? "Hide Cheatcode Matrix" : "Cheatcode Matrix"}</span>
          </button>
        </div>
      </div>

      {/* Preset Pickers */}
      <div className="bg-[#14120e] border border-[#2e2a20] rounded-lg p-3 flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-bold text-[#f4efe6] flex items-center gap-1.5 uppercase">
            <Flame className="w-3.5 h-3.5 text-[#e8a54b]" />
            Quick Presets & Sources
          </span>
          {aiReview?.foundryTestCode && (
            <button
              onClick={() => handleLoadPreset(aiReview.foundryTestCode)}
              className="text-[11px] text-[#e8a54b] hover:underline flex items-center gap-1"
            >
              <Sparkles className="w-3 h-3" />
              <span>Load Current AI Threat Suite</span>
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
          {SAMPLE_FOUNDRY_PRESETS.map((p) => (
            <button
              key={p.id}
              onClick={() => handleLoadPreset(p.code)}
              className="p-2.5 rounded bg-[#1c1a16] hover:bg-[#26231c] border border-[#3a3428] hover:border-[#e8a54b] text-left transition-all group flex flex-col gap-1 cursor-pointer"
            >
              <span className="font-semibold text-xs text-[#f4efe6] group-hover:text-[#e8a54b]">
                {p.label}
              </span>
              <span className="text-[10px] text-[#a39886] line-clamp-1">{p.description}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Config Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 bg-[#14120e] border border-[#2e2a20] rounded-lg p-3.5">
        <div>
          <label className="text-[11px] font-bold text-[#a39886] block mb-1">
            Target Contract Name
          </label>
          <input
            type="text"
            value={contractName}
            onChange={(e) => setContractName(e.target.value)}
            placeholder="e.g. Vault, StakingRewards"
            className="w-full bg-[#1c1a16] border border-[#3a3428] rounded px-2.5 py-1.5 text-xs text-[#f4efe6] font-mono focus:outline-none focus:border-[#e8a54b]"
          />
        </div>

        <div>
          <label className="text-[11px] font-bold text-[#a39886] block mb-1">
            Target Address (Optional)
            {singleAddressChain && (
              <span className="ml-1.5 font-normal text-[10px] text-amber-400/80">
                ({singleAddressChain})
              </span>
            )}
          </label>
          <input
            type="text"
            value={targetAddressInput}
            onChange={(e) => setTargetAddressInput(e.target.value)}
            placeholder="0x... (injected into constructor or default)"
            className="w-full bg-[#1c1a16] border border-[#3a3428] rounded px-2.5 py-1.5 text-xs text-[#f4efe6] font-mono focus:outline-none focus:border-[#e8a54b]"
          />
        </div>

        <div>
          <label className="text-[11px] font-bold text-[#a39886] block mb-1">
            Solidity Architecture Style
          </label>
          <select
            value={mode}
            onChange={(e) => setMode(e.target.value as ConvertMode)}
            className="w-full bg-[#1c1a16] border border-[#3a3428] rounded px-2.5 py-1.5 text-xs text-[#f4efe6] font-mono focus:outline-none focus:border-[#e8a54b]"
          >
            <option value="interaction">Interaction & State Validation (Balanced)</option>
            <option value="validation">Pure On-Chain Invariant Validator</option>
            <option value="exploit">Autonomous Attacker & Exploit Interactor</option>
          </select>
        </div>
      </div>

      {/* Cheatcode to Solidity Translation Matrix */}
      {showMatrix && (
        <div className="bg-[#12110e] border border-[#3a3428] rounded-lg p-3.5 flex flex-col gap-2">
          <div className="flex items-center gap-1.5 font-bold text-[#f4efe6]">
            <Sparkles className="w-3.5 h-3.5 text-[#e8a54b]" />
            <span>Cheatcode → Plain Solidity Transformation Rules</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2 text-[11px]">
            <div className="p-2 bg-[#1c1a16] border border-[#2e2a20] rounded">
              <span className="font-semibold text-amber-300">vm.prank(account)</span>
              <p className="text-[10px] text-stone-300 mt-1">
                Converts to direct calls from <code className="text-stone-100">msg.sender</code>,
                deploying interactor, or role-gated execution.
              </p>
            </div>
            <div className="p-2 bg-[#1c1a16] border border-[#2e2a20] rounded">
              <span className="font-semibold text-amber-300">vm.deal(user, eth)</span>
              <p className="text-[10px] text-stone-300 mt-1">
                Converts to <code className="text-stone-100">payable</code> entry point requiring{" "}
                <code className="text-stone-100">msg.value</code> or balance verification.
              </p>
            </div>
            <div className="p-2 bg-[#1c1a16] border border-[#2e2a20] rounded">
              <span className="font-semibold text-amber-300">vm.expectRevert(...)</span>
              <p className="text-[10px] text-stone-300 mt-1">
                Converts to native <code className="text-stone-100">try/catch</code> blocks or low-level{" "}
                <code className="text-stone-100">.call()</code> asserting revert.
              </p>
            </div>
            <div className="p-2 bg-[#1c1a16] border border-[#2e2a20] rounded">
              <span className="font-semibold text-amber-300">assertEq / assertTrue</span>
              <p className="text-[10px] text-stone-300 mt-1">
                Converts to native <code className="text-stone-100">require()</code> assertions and{" "}
                <code className="text-stone-100">event ValidationPassed</code>.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Main Dual-View Editor/Generator */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Left: Foundry Input Area */}
        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <label className="text-xs font-bold text-[#f4efe6] flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-[#e8a54b]" />
              <span>Foundry Test Code (Input)</span>
            </label>
            <div className="flex items-center gap-2">
              <button
                onClick={handlePasteClipboard}
                className="text-[11px] text-[#a39886] hover:text-[#f4efe6] transition-colors"
                title="Paste from clipboard"
              >
                Paste
              </button>
              <button
                onClick={() => setFoundryInput("")}
                className="text-[11px] text-stone-500 hover:text-red-400 transition-colors"
                title="Clear input"
              >
                Clear
              </button>
            </div>
          </div>

          <textarea
            value={foundryInput}
            onChange={(e) => setFoundryInput(e.target.value)}
            placeholder={`// Paste your Foundry test contract here:\nimport "forge-std/Test.sol";\n\ncontract PoC is Test {\n    function setUp() public { ... }\n    function test_contract_interaction() public { ... }\n}`}
            rows={18}
            className="w-full bg-[#12110e] border border-[#3a3428] rounded-lg p-3.5 text-xs text-[#f4efe6] font-mono focus:outline-none focus:border-[#e8a54b] transition-colors resize-y leading-relaxed"
          />

          <div className="flex items-center justify-between pt-1">
            <span className="text-[10px] text-[#746c60]">
              {foundryInput.length} characters •{" "}
              {foundryInput ? foundryInput.split("\n").length : 0} lines
            </span>

            <button
              onClick={handleGenerate}
              disabled={isGenerating || !foundryInput.trim()}
              className="px-4 py-2 rounded bg-[#e8a54b] hover:bg-[#f3b562] text-[#12110e] font-bold text-xs flex items-center gap-2 shadow transition-all disabled:opacity-50 cursor-pointer"
            >
              {isGenerating ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Generating Plain Solidity...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Generate Plain Solidity with LLM</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Right: Generated Plain Solidity Output */}
        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <label className="text-xs font-bold text-emerald-400 flex items-center gap-1.5">
              <FileCode className="w-3.5 h-3.5 text-emerald-400" />
              <span>Plain Solidity Interaction & Validation Contract (Output)</span>
            </label>

            {result?.plainSolidityCode && (
              <div className="flex items-center gap-1.5">
                {setContractBody && (
                  <button
                    onClick={() => setContractBody(result.plainSolidityCode)}
                    className="px-2 py-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#a39886] hover:text-[#f4efe6] text-[11px] flex items-center gap-1 transition-colors"
                    title="Load into Kiln Editor"
                  >
                    <ArrowRightLeft className="w-3 h-3 text-[#e8a54b]" />
                    <span>Load in Editor</span>
                  </button>
                )}
                <button
                  onClick={handleDownload}
                  className="px-2 py-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#a39886] hover:text-[#f4efe6] text-[11px] flex items-center gap-1 transition-colors"
                  title="Download .sol"
                >
                  <Download className="w-3 h-3 text-[#e8a54b]" />
                  <span>Download</span>
                </button>
                <button
                  onClick={() => handleCopy(result.plainSolidityCode, "output-sol")}
                  className="px-2.5 py-1 rounded bg-[#e8a54b] text-[#12110e] font-bold text-[11px] flex items-center gap-1 shadow hover:brightness-110 transition-all"
                >
                  {copiedKey === "output-sol" ? (
                    <>
                      <Check className="w-3 h-3" />
                      <span>Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>
            )}
          </div>

          {result?.plainSolidityCode ? (
            <div className="flex flex-col gap-2">
              <div className="flex items-center justify-between text-[11px] text-[#a39886] bg-[#14120e] p-2 rounded border border-[#2e2a20]">
                <div className="flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                  <span>
                    Generated via:{" "}
                    <strong className="text-[#f4efe6]">
                      {result.source === "openrouter" ? "OpenRouter Code LLM" : "Solidity AST Adapter"}
                    </strong>
                  </span>
                </div>
                <span className="text-[10px] text-[#746c60]">Duration: {result.durationMs}ms</span>
              </div>

              <div className="bg-[#12110e] border border-[#3a3428] rounded-lg p-3.5 text-amber-200 font-mono text-xs overflow-x-auto max-h-[460px] leading-relaxed">
                <pre className="whitespace-pre-wrap">{result.plainSolidityCode}</pre>
              </div>
            </div>
          ) : (
            <div className="border border-dashed border-[#3a3428] rounded-lg p-8 flex flex-col items-center justify-center text-center gap-3 min-h-[380px] bg-[#12110e]/40">
              <Code2 className="w-8 h-8 text-[#a39886]/40" />
              <div className="max-w-sm">
                <p className="font-bold text-[#f4efe6] text-xs">Awaiting Conversion</p>
                <p className="text-[11px] text-[#a39886] mt-1">
                  Paste your Foundry test on the left and click &quot;Generate Plain Solidity with LLM&quot;
                  to produce a deployable interaction and validation contract.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      {error && (
        <div className="p-3 bg-red-950/30 border border-red-800/60 rounded-lg text-xs text-red-300 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}
    </div>
  );
}
