import { PocEvidenceBadge } from "@/components/poc-evidence-badge";
import { classifyPocEvidence } from "@/lib/audit/poc-evidence";
import { useState, useMemo } from "react";
import { Terminal, Play, Wand2, CheckCircle2, RefreshCcw, FileCode, Cpu, Globe, RotateCw, AlertTriangle, ShieldCheck, Download } from "lucide-react";
import { runPocOnBackend, runPocWithRpcRetries, getBackendUrl, isPocCompileError, isRpcOrForkFailure, type RpcRetryProgress } from "@/lib/audit/foundry-backend";
import { requestPocRepair } from "@/lib/audit/ai.functions";
import { SUPPORTED_CHAINS, getRpcsForChain, isValidEvmAddress } from "@/lib/audit/address-fetcher";
import { saveSmartPocResult } from "@/lib/audit/smart-poc-save";
import { getStoredSupabaseConfig } from "@/lib/supabase";
import type { PocResult } from "@/lib/audit/types";
import { interactiveBoxMismatch, type InteractiveSourceState } from "@/lib/audit/interactive-source";

export type InteractiveAuditTabProps = {
  /** Shared workbench selection: the address both tabs read/write. */
  address: string;
  chainId: string;
  onAddressChange: (value: string) => void;
  onChainChange: (value: string) => void;
  /** The source box state (lifted to the workbench controller). */
  source: InteractiveSourceState;
  onSourceChange: (code: string) => void;
  /** Fetch the selected address's source into the box. */
  onLoadSource: () => void;
};

export function InteractiveAuditTab({
  address,
  chainId,
  onAddressChange,
  onChainChange,
  source,
  onSourceChange,
  onLoadSource,
}: InteractiveAuditTabProps) {
  // The box content and the PoC target come from the shared workbench
  // selection; everything below consumes them exactly as the old local
  // state did (the source is the repair body, the target is forked).
  const solidityCode = source.code;
  const targetAddress = address;
  const selectedChainId = chainId;
  const mismatchNotice = interactiveBoxMismatch(source, address);

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

  const [customRpcUrl, setCustomRpcUrl] = useState<string>("");
  const [autoRetryAllRpcs, setAutoRetryAllRpcs] = useState<boolean>(true);
  const [saveNotice, setSaveNotice] = useState("");
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [isRepairing, setIsRepairing] = useState<boolean>(false);
  const [pocResult, setPocResult] = useState<PocResult | null>(null);
  const [repairNotice, setRepairNotice] = useState<string | null>(null);
  const [retryProgress, setRetryProgress] = useState<RpcRetryProgress | null>(null);

  // Active chain candidate RPC list
  const activeChainRpcs = useMemo(() => {
    return getRpcsForChain(selectedChainId);
  }, [selectedChainId]);

  const activeRpcUrl = useMemo(() => {
    if (customRpcUrl.trim()) return customRpcUrl.trim();
    return activeChainRpcs[0] || "https://ethereum.publicnode.com";
  }, [customRpcUrl, activeChainRpcs]);

  // Detected RPC or fork error in last result
  const hasRpcError = useMemo(() => {
    if (!pocResult) return false;
    return isRpcOrForkFailure(pocResult.logs ?? "", pocResult.error) || (pocResult.logs ?? "").includes("invalid rpc url");
  }, [pocResult]);

  const handleRunPoc = async (forceRetryAll = false) => {
    setIsRunning(true);
    setSaveNotice("");
    setRepairNotice(null);
    setRetryProgress(null);

    const shouldRetryAll = forceRetryAll || autoRetryAllRpcs;

    try {
      let res: PocResult;
      let executedCode = testCode;
      if (shouldRetryAll) {
        // Collect candidate RPCs for the chain and global fallbacks
        const rpcList = customRpcUrl.trim()
          ? [customRpcUrl.trim(), ...activeChainRpcs]
          : activeChainRpcs;

        res = await runPocWithRpcRetries(getBackendUrl(), {
          address: targetAddress,
          chainId: selectedChainId,
          testCode: testCode,
          preferredRpc: activeRpcUrl,
          rpcList: rpcList,
          onProgress: (prog) => {
            setRetryProgress(prog);
          },
        });

      } else {
        res = await runPocOnBackend(getBackendUrl(), {
          address: targetAddress,
          chainId: selectedChainId,
          testCode: testCode,
          rpcUrl: activeRpcUrl,
        });

      }
      if (res.status === "error" && isPocCompileError(res.logs)) {
        try {
          const repaired = await requestPocRepair({ data: { contractName: "Interactive contract", originalCode: executedCode, errorLogs: res.logs, body: solidityCode } });
          executedCode = repaired.fixedCode;
          setTestCode(executedCode);
          res = await runPocWithRpcRetries(getBackendUrl(), { address: targetAddress, testCode: executedCode,
            chainId: selectedChainId, preferredRpc: activeRpcUrl, retry: shouldRetryAll });
        } catch (repairError) { setRepairNotice(`Automatic repair failed: ${String(repairError)}`); }
      }
      setPocResult(res);
      try {
        const chainId = SUPPORTED_CHAINS.find(c => c.id === selectedChainId)?.chainId ?? 1;
        setSaveNotice(await saveSmartPocResult(res, executedCode, chainId, getStoredSupabaseConfig()));
      } catch (saveError) { setSaveNotice(`Save failed: ${String(saveError)}`); }
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
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={onLoadSource}
              disabled={source.status === "loading" || !isValidEvmAddress(targetAddress.trim())}
              title="Fetch the target address's source (Sourcify / explorer) into this box"
              className="px-2.5 py-1.5 bg-[#2a251c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] font-bold text-xs rounded flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              {source.status === "loading" ? (
                <RefreshCcw className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Download className="w-3.5 h-3.5" />
              )}
              <span>{source.status === "loading" ? "Loading source…" : "Load source by address"}</span>
            </button>
            {source.codeForAddress && (
              <span className="text-[10px] font-mono px-2 py-1 rounded bg-[#12110e] border border-[#3a3428] text-[#a39886]">
                Source loaded for {source.codeForAddress.slice(0, 10)}…{source.codeForAddress.slice(-6)}
                {source.edited ? " (edited)" : ""}
              </span>
            )}
          </div>
          {source.status === "error" && source.error && (
            <p className="text-xs text-rose-300 bg-rose-950/40 border border-rose-800/60 rounded p-2.5">
              Source load failed: {source.error}
            </p>
          )}
          {source.notice && (
            <p className="text-xs text-amber-300 bg-amber-950/40 border border-amber-800/60 rounded p-2.5">
              {source.notice}
            </p>
          )}
          {mismatchNotice && source.status !== "error" && (
            <p className="text-xs text-amber-300 bg-amber-950/40 border border-amber-800/60 rounded p-2.5">
              {mismatchNotice}
            </p>
          )}
          <textarea
            value={solidityCode}
            onChange={(e) => onSourceChange(e.target.value)}
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
            <li>Audit SWC-112 delegatecalls: prevent callee control and storage collisions.</li>
          </ul>
        </div>
      </div>

      {/* Right Column: Foundry Test Harness & LLM Repair */}
      <div className="lg:col-span-6 flex flex-col gap-4">
        {/* Network & RPC Selection Toolbar */}
        <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 shadow-sm flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-[#f4efe6] font-semibold text-xs">
              <Globe className="w-4 h-4 text-[#e8a54b]" />
              <span>Network & RPC Configuration</span>
            </div>
            <span className="text-[10px] font-mono text-[#a39886]">{activeChainRpcs.length} RPCs available</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <div>
              <label className="text-[10px] uppercase font-mono text-[#a39886] block mb-1">Target Chain</label>
              <select
                value={selectedChainId}
                onChange={(e) => {
                  onChainChange(e.target.value);
                  setCustomRpcUrl("");
                }}
                className="w-full bg-[#12110e] border border-[#3a3428] text-xs font-mono text-[#f4efe6] px-2 py-1.5 rounded focus:outline-none focus:border-[#e8a54b]"
              >
                {SUPPORTED_CHAINS.map((chain) => (
                  <option key={chain.id} value={chain.id}>
                    {chain.name} ({chain.chainId})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-[10px] uppercase font-mono text-[#a39886] block mb-1">Active / Custom RPC</label>
              <input
                type="text"
                value={customRpcUrl}
                onChange={(e) => setCustomRpcUrl(e.target.value)}
                placeholder={activeChainRpcs[0] || "https://..."}
                className="w-full bg-[#12110e] border border-[#3a3428] text-xs font-mono text-[#f4efe6] px-2 py-1.5 rounded focus:outline-none focus:border-[#e8a54b]"
              />
            </div>
          </div>

          <div className="flex items-center justify-between pt-1 border-t border-[#3a3428]/50">
            <label className="flex items-center gap-2 text-xs font-mono text-[#f4efe6] cursor-pointer">
              <input
                type="checkbox"
                checked={autoRetryAllRpcs}
                onChange={(e) => setAutoRetryAllRpcs(e.target.checked)}
                className="rounded border-[#3a3428] text-[#e8a54b] focus:ring-0 bg-[#12110e]"
              />
              <span>Retry using all RPCs in list when necessary</span>
            </label>
            <button
              onClick={() => handleRunPoc(true)}
              disabled={isRunning}
              title="Force execution across all candidate RPCs"
              className="text-[11px] font-mono text-[#e8a54b] hover:text-[#f0b25e] flex items-center gap-1 disabled:opacity-50"
            >
              <RotateCw className="w-3 h-3" />
              <span>Retry All RPCs</span>
            </button>
          </div>
        </div>

        {/* Foundry Test & PoC Harness */}
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
                onChange={(e) => onAddressChange(e.target.value)}
                placeholder="Target 0x..."
                className="bg-[#12110e] border border-[#3a3428] text-xs font-mono text-[#f4efe6] px-2 py-1 rounded w-36"
              />
              <button
                onClick={() => handleRunPoc(false)}
                disabled={isRunning}
                className="px-3 py-1.5 bg-[#e8a54b] hover:bg-[#d6933c] text-[#12110e] font-bold text-xs rounded flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                {isRunning ? <RefreshCcw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                <span>Run PoC</span>
              </button>
            </div>
          </div>
          <p className="text-xs text-[#a39886]">
            Write or adjust your Foundry test below. If execution encounters an RPC or compilation error, use the RPC retry or LLM Fix button.
          </p>
          <PocEvidenceBadge evidence={classifyPocEvidence({ code: testCode, result: pocResult,
            target: targetAddress, chainId: selectedChainId })} />
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
            <div className="flex items-center gap-2">
              {hasRpcError && (
                <button
                  onClick={() => handleRunPoc(true)}
                  disabled={isRunning}
                  className="px-2.5 py-1.5 bg-amber-600 hover:bg-amber-500 text-white font-bold text-xs rounded flex items-center gap-1.5 shadow transition-colors disabled:opacity-50"
                >
                  <RotateCw className="w-3.5 h-3.5" />
                  <span>Retry All RPCs</span>
                </button>
              )}
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
          </div>

          {/* RPC Rotation Status Notice */}
          {retryProgress && (
            <div className="p-2.5 rounded bg-blue-950/40 border border-blue-800/60 text-blue-300 text-xs flex items-center gap-2">
              <RefreshCcw className="w-3.5 h-3.5 animate-spin text-blue-400 shrink-0" />
              <span>
                Attempt {retryProgress.attempt}/{retryProgress.total}: testing with RPC{" "}
                <span className="font-mono font-bold text-white">{retryProgress.rpcUrl}</span>
                {retryProgress.error ? ` — ${retryProgress.error}` : "..."}
              </span>
            </div>
          )}

          {hasRpcError && !isRunning && (
            <div className="p-2.5 rounded bg-amber-950/40 border border-amber-800/60 text-amber-300 text-xs flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                <span>
                  RPC or fork setup issue detected (<span className="font-mono text-white">vm.createSelectFork / invalid rpc url</span>).
                </span>
              </div>
              <button
                onClick={() => handleRunPoc(true)}
                className="px-2 py-1 bg-amber-500 hover:bg-amber-400 text-black font-bold text-[11px] rounded whitespace-nowrap"
              >
                Retry All {activeChainRpcs.length} RPCs
              </button>
            </div>
          )}

          {repairNotice && (
            <div className="p-2.5 rounded bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 text-xs flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{repairNotice}</span>
            </div>
          )}

          <div className="bg-[#12110e] border border-[#3a3428] rounded-lg p-3 font-mono text-xs text-[#a39886] min-h-[120px] max-h-60 overflow-y-auto whitespace-pre-wrap">
            {isRunning ? (
              <span className="text-[#e8a54b] animate-pulse">
                {retryProgress
                  ? `[Attempt ${retryProgress.attempt}/${retryProgress.total}] Running test against ${retryProgress.rpcUrl}...`
                  : "Running Foundry test on backend..."}
              </span>
            ) : pocResult ? (
              <div>
                <div className="flex items-center gap-2 mb-2 pb-2 border-b border-[#3a3428]">
                  <PocEvidenceBadge evidence={classifyPocEvidence({ code: testCode, result: pocResult,
                    target: targetAddress, chainId: selectedChainId })} />
                  <span className="text-[#a39886]">{pocResult.durationMs}ms</span>
                </div>
                <div className="text-[#f4efe6]">{saveNotice ? `Persistence: ${saveNotice}\n` : ""}{pocResult.logs || "(No output logs)"}</div>
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

