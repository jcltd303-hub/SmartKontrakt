import { useState, useEffect } from "react";
import {
  ArrowRightLeft,
  Check,
  Copy,
  Download,
  FileCode,
  Loader2,
  Sparkles,
  Terminal,
  ShieldAlert,
  BookOpen,
} from "lucide-react";
import { downloadFile } from "@/lib/download-file";
import { convertFoundryToPlainSolidityFn } from "@/lib/audit/ai.functions";
import type { ConvertFoundryResult } from "@/lib/audit/convert-foundry.server";

interface FoundryToSolidityConverterProps {
  /** Initial Foundry test code, e.g. from aiReview.foundryTestCode */
  defaultFoundryCode?: string;
  contractName?: string;
  contractBody?: string;
  targetAddress?: string;
  /** Optional callback to load the converted Plain Solidity directly into the Workbench editor */
  onLoadIntoEditor?: (code: string) => void;
}

export function FoundryToSolidityConverter({
  defaultFoundryCode = "",
  contractName = "TargetContract",
  contractBody = "",
  targetAddress = "",
  onLoadIntoEditor,
}: FoundryToSolidityConverterProps) {
  const [foundryInput, setFoundryInput] = useState<string>(defaultFoundryCode);
  const [isConverting, setIsConverting] = useState<boolean>(false);
  const [conversionResult, setConversionResult] = useState<ConvertFoundryResult | null>(null);
  const [conversionError, setConversionError] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [showCheatcodeGuide, setShowCheatcodeGuide] = useState<boolean>(false);

  // Sync if defaultFoundryCode updates and input is empty
  useEffect(() => {
    if (defaultFoundryCode && !foundryInput) {
      setFoundryInput(defaultFoundryCode);
    }
  }, [defaultFoundryCode, foundryInput]);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleDownload = () => {
    if (!conversionResult?.plainSolidityCode) return;
    const safeName = (contractName || "Target").replace(/[^a-zA-Z0-9_]/g, "");
    downloadFile(`${safeName}Exploit.sol`, conversionResult.plainSolidityCode);
  };

  const handleConvert = async () => {
    const code = foundryInput.trim();
    if (!code) {
      setConversionError("Please provide Foundry test code to convert.");
      return;
    }

    setIsConverting(true);
    setConversionError(null);

    try {
      const res = await convertFoundryToPlainSolidityFn({
        data: {
          foundryCode: code,
          contractName: contractName || "TargetContract",
          contractSource: contractBody ? contractBody.slice(0, 10000) : "",
          targetAddress: targetAddress || undefined,
          mode: "interaction",
        },
      });
      setConversionResult(res);
    } catch (err) {
      setConversionError(
        err instanceof Error ? err.message : "Failed to convert Foundry test code",
      );
    } finally {
      setIsConverting(false);
    }
  };

  const handleResetToCurrentAiTest = () => {
    if (defaultFoundryCode) {
      setFoundryInput(defaultFoundryCode);
      setConversionError(null);
    }
  };

  return (
    <div className="bg-[#181612] border border-[#3a3428] rounded-xl p-5 flex flex-col gap-4 font-mono text-xs">
      {/* Header section */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#3a3428]">
        <div>
          <div className="flex items-center gap-2">
            <ArrowRightLeft className="w-4 h-4 text-[#e8a54b]" />
            <h3 className="text-sm font-bold text-[#f4efe6]">
              Foundry → Plain Solidity Exploit Converter (LLM)
            </h3>
            <span className="px-2 py-0.5 rounded text-[10px] bg-amber-950/60 border border-amber-800/60 text-[#e8a54b]">
              Standalone EVM
            </span>
          </div>
          <p className="text-[11px] text-[#a39886] mt-0.5">
            Converts Foundry test suites (<code className="text-amber-200">forge-std/Test.sol</code>,{" "}
            <code className="text-amber-200">vm.prank</code>, <code className="text-amber-200">vm.deal</code>)
            into standalone, deployable Solidity attacker contracts (Remix / Hardhat ready).
          </p>
        </div>

        <button
          onClick={() => setShowCheatcodeGuide(!showCheatcodeGuide)}
          className="text-xs text-[#a39886] hover:text-[#f4efe6] flex items-center gap-1.5 self-start sm:self-auto transition-colors"
        >
          <BookOpen className="w-3.5 h-3.5 text-[#e8a54b]" />
          <span>{showCheatcodeGuide ? "Hide Cheatcode Guide" : "Cheatcode Guide"}</span>
        </button>
      </div>

      {/* Cheatcode mapping guide panel */}
      {showCheatcodeGuide && (
        <div className="bg-[#12110e] border border-[#3a3428] rounded-lg p-3.5 text-[11px] text-[#a39886] flex flex-col gap-2 leading-relaxed">
          <div className="font-bold text-[#f4efe6] flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-[#e8a54b]" />
            Cheatcode to Plain Solidity Translation Matrix:
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mt-1">
            <div className="p-2 rounded bg-[#1c1a16] border border-[#2e2a20]">
              <span className="font-semibold text-amber-300">vm.prank(attacker)</span>
              <p className="text-[10px] text-stone-300 mt-0.5">
                → Executed directly from <code className="text-stone-100">msg.sender</code> / exploit contract.
              </p>
            </div>
            <div className="p-2 rounded bg-[#1c1a16] border border-[#2e2a20]">
              <span className="font-semibold text-amber-300">vm.deal(user, amount)</span>
              <p className="text-[10px] text-stone-300 mt-0.5">
                → Converted to <code className="text-stone-100">payable</code> constructor/attack with <code className="text-stone-100">msg.value</code>.
              </p>
            </div>
            <div className="p-2 rounded bg-[#1c1a16] border border-[#2e2a20]">
              <span className="font-semibold text-amber-300">vm.createSelectFork(...)</span>
              <p className="text-[10px] text-stone-300 mt-0.5">
                → Replaced with real target address parameter in constructor.
              </p>
            </div>
            <div className="p-2 rounded bg-[#1c1a16] border border-[#2e2a20]">
              <span className="font-semibold text-amber-300">vm.expectRevert(...)</span>
              <p className="text-[10px] text-stone-300 mt-0.5">
                → Translated to <code className="text-stone-100">try / catch</code> or low-level <code className="text-stone-100">.call()</code> checks.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Input section */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <label className="text-xs font-bold text-[#f4efe6] flex items-center gap-1.5">
            <Terminal className="w-3.5 h-3.5 text-[#e8a54b]" />
            <span>Foundry Test Code (Input)</span>
          </label>
          {defaultFoundryCode && (
            <button
              onClick={handleResetToCurrentAiTest}
              className="text-[11px] text-[#e8a54b] hover:underline"
            >
              Reset to Current AI Foundry Test
            </button>
          )}
        </div>

        <textarea
          value={foundryInput}
          onChange={(e) => setFoundryInput(e.target.value)}
          placeholder={`// Paste your Foundry test suite here (e.g. contract PoC is Test { ... })\nimport "forge-std/Test.sol";\n\ncontract PoC is Test {\n    function test_exploit() public { ... }\n}`}
          rows={8}
          className="w-full bg-[#12110e] border border-[#3a3428] rounded-lg p-3 text-xs text-[#f4efe6] font-mono focus:outline-none focus:border-[#e8a54b] transition-colors resize-y leading-relaxed"
        />

        <div className="flex items-center justify-between pt-1">
          <div className="text-[11px] text-[#a39886]">
            Target: <span className="text-[#f4efe6] font-semibold">{contractName}</span>
            {targetAddress && (
              <span className="ml-2 font-mono text-[10px] text-[#746c60]">({targetAddress})</span>
            )}
          </div>

          <button
            onClick={handleConvert}
            disabled={isConverting || !foundryInput.trim()}
            className="px-4 py-2 rounded bg-[#e8a54b] text-[#12110e] font-bold text-xs flex items-center gap-2 shadow hover:brightness-110 disabled:opacity-50 transition-all cursor-pointer"
          >
            {isConverting ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Converting via LLM...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-3.5 h-3.5" />
                <span>Convert to Plain Solidity</span>
              </>
            )}
          </button>
        </div>
      </div>

      {conversionError && (
        <div className="p-3 bg-red-950/30 border border-red-800/60 rounded-lg text-xs text-red-300 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
          <span>{conversionError}</span>
        </div>
      )}

      {/* Output section */}
      {conversionResult && (
        <div className="mt-2 pt-4 border-t border-[#3a3428] flex flex-col gap-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-1">
            <div className="flex items-center gap-2">
              <FileCode className="w-4 h-4 text-emerald-400" />
              <span className="text-xs font-bold text-emerald-400 uppercase tracking-wide">
                Plain Solidity Attacker Contract (Output)
              </span>
              <span className="text-[10px] px-2 py-0.5 rounded bg-[#26231c] text-[#a39886] border border-[#3a3428]">
                {conversionResult.source === "openrouter" ? "OpenRouter Code LLM" : "Fallback Solidity Adapter"}
              </span>
              <span className="text-[10px] text-[#746c60]">
                ({conversionResult.durationMs}ms)
              </span>
            </div>

            <div className="flex items-center gap-1.5 flex-wrap">
              {onLoadIntoEditor && (
                <button
                  onClick={() => onLoadIntoEditor(conversionResult.plainSolidityCode)}
                  className="px-2.5 py-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#a39886] hover:text-[#f4efe6] text-xs flex items-center gap-1 transition-colors"
                  title="Load into Workbench Editor to analyze or simulate"
                >
                  <ArrowRightLeft className="w-3 h-3 text-[#e8a54b]" />
                  <span>Load into Editor</span>
                </button>
              )}
              <button
                onClick={handleDownload}
                className="px-2.5 py-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#a39886] hover:text-[#f4efe6] text-xs flex items-center gap-1 transition-colors"
                title="Download Plain Solidity file"
              >
                <Download className="w-3 h-3 text-[#e8a54b]" />
                <span>Download .sol</span>
              </button>
              <button
                onClick={() => handleCopy(conversionResult.plainSolidityCode, "converted-sol")}
                className="px-3 py-1 rounded bg-[#e8a54b] text-[#12110e] font-bold text-xs flex items-center gap-1 shadow hover:brightness-110 transition-all"
              >
                {copiedKey === "converted-sol" ? (
                  <>
                    <Check className="w-3 h-3" />
                    <span>Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>Copy Solidity</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {conversionResult.notes && (
            <p className="text-[11px] text-[#746c60] italic">{conversionResult.notes}</p>
          )}

          <div className="bg-[#12110e] border border-[#3a3428] rounded-lg p-4 max-h-96 overflow-y-auto text-amber-200 leading-relaxed font-mono">
            <pre className="whitespace-pre-wrap">{conversionResult.plainSolidityCode}</pre>
          </div>
        </div>
      )}
    </div>
  );
}
