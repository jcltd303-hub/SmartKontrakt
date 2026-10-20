import { SUPPORTED_CHAINS } from "@/lib/audit/address-fetcher";
import { analyzeInput } from "@/lib/audit/engine";
import { SAMPLES } from "@/lib/audit/samples";
import {
  ArrowRight,
  Check,
  Copy,
  FileCode,
  Globe,
  Layers,
  Loader2,
  Search,
  Terminal,
  Trash2,
} from "lucide-react";
import type { WorkbenchController } from "./use-workbench-controller";

type ContractEditorProps = Pick<
  WorkbenchController,
  | "singleAddress"
  | "setSingleAddress"
  | "setAddressFetchError"
  | "singleAddressChain"
  | "setSingleAddressChain"
  | "handleFetchSingleAddress"
  | "isFetchingAddress"
  | "addressFetchError"
  | "proxyInfo"
  | "handleSelectSample"
  | "selectedSampleId"
  | "setSelectedSampleId"
  | "setContractBody"
  | "setContractLabel"
  | "contractLabel"
  | "isBytecode"
  | "contractBody"
  | "setReport"
  | "copyToClipboard"
  | "copiedKey"
>;

export function ContractEditor({
  singleAddress,
  setSingleAddress,
  setAddressFetchError,
  singleAddressChain,
  setSingleAddressChain,
  handleFetchSingleAddress,
  isFetchingAddress,
  addressFetchError,
  proxyInfo,
  handleSelectSample,
  selectedSampleId,
  setSelectedSampleId,
  setContractBody,
  setContractLabel,
  contractLabel,
  isBytecode,
  contractBody,
  setReport,
  copyToClipboard,
  copiedKey,
}: ContractEditorProps) {
  return (
    <section className="lg:col-span-5 flex min-w-0 flex-col gap-4">
      {/* Single Address Fetcher Card */}
      <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-3.5 shadow-sm flex flex-col gap-2.5">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-[#a39886] uppercase tracking-wider flex items-center gap-1.5 font-mono">
            <Globe className="w-3.5 h-3.5 text-[#e8a54b]" />
            Fetch Contract by Address
          </span>
          <span className="text-[10px] text-[#746c60] font-mono">RPC + Sourcify</span>
        </div>
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
          <input
            type="text"
            placeholder="0x... EVM address"
            value={singleAddress}
            onChange={(e) => {
              setSingleAddress(e.target.value);
              setAddressFetchError(null);
            }}
            className="flex-1 bg-[#12110e] border border-[#3a3428] rounded px-3 py-1.5 text-xs font-mono text-[#f4efe6] focus:outline-none focus:border-[#e8a54b]"
          />
          <select
            value={singleAddressChain}
            onChange={(e) => setSingleAddressChain(e.target.value)}
            className="bg-[#26231c] border border-[#3a3428] rounded px-2.5 py-1.5 text-xs font-mono text-[#e8a54b] focus:outline-none cursor-pointer"
          >
            {SUPPORTED_CHAINS.map((c) => (
              <option key={c.id} value={c.id} className="bg-[#1c1a16] text-[#f4efe6]">
                {c.name}
              </option>
            ))}
          </select>
          <button
            onClick={handleFetchSingleAddress}
            disabled={isFetchingAddress || !singleAddress.trim()}
            className="px-3.5 py-1.5 rounded bg-[#e8a54b] hover:brightness-110 text-[#12110e] text-xs font-bold font-mono flex items-center justify-center gap-1.5 disabled:opacity-50 transition-all shrink-0"
          >
            {isFetchingAddress ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Search className="w-3.5 h-3.5" />
            )}
            <span>Fetch</span>
          </button>
        </div>
        {addressFetchError && (
          <div className="text-[11px] text-red-400 font-mono bg-red-950/40 p-2 rounded border border-red-900/60 leading-relaxed">
            {addressFetchError}
          </div>
        )}
      </div>

      {/* Upgradeable Proxy Banner if detected */}
      {proxyInfo?.isProxy && proxyInfo.implementationAddress && (
        <div className="p-3.5 bg-purple-950/30 border border-purple-800/60 rounded-xl flex flex-col gap-2 font-mono text-xs shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-purple-300 font-bold flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-purple-400" />
              {proxyInfo.proxyType} Upgradeable Proxy Detected
            </span>
            <span className="text-[10px] text-purple-400/80">EIP-1967 Storage Slot</span>
          </div>
          <div className="text-[11px] text-[#f4efe6] break-all">
            Implementation:{" "}
            <span className="text-purple-200 font-bold">{proxyInfo.implementationAddress}</span>
          </div>
          {proxyInfo.adminAddress && (
            <div className="text-[10px] text-[#a39886] truncate">
              Proxy Admin Controller: {proxyInfo.adminAddress}
            </div>
          )}
          <button
            onClick={() => {
              setSingleAddress(proxyInfo.implementationAddress!);
              handleFetchSingleAddress();
            }}
            className="mt-1 px-3 py-1.5 rounded bg-purple-900/70 hover:bg-purple-800 text-purple-200 text-xs font-bold flex items-center justify-center gap-1.5 transition-all shadow"
          >
            <ArrowRight className="w-3.5 h-3.5" />
            <span>Audit Implementation Target Contract</span>
          </button>
        </div>
      )}
      {/* Sample Selectors Ribbon */}
      <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-3.5 shadow-sm">
        <div className="flex items-center justify-between mb-2.5">
          <span className="text-xs font-semibold text-[#a39886] uppercase tracking-wider flex items-center gap-1.5">
            <FileCode className="w-3.5 h-3.5 text-[#e8a54b]" />
            Sample Test Vectors
          </span>
          <span className="text-[11px] text-[#746c60]">Click to load</span>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {SAMPLES.map((s) => (
            <button
              key={s.id}
              onClick={() => handleSelectSample(s)}
              className={`text-xs px-2.5 py-1.5 rounded-md font-mono border transition-all ${
                selectedSampleId === s.id
                  ? "bg-[#3a2c14] border-[#e8a54b] text-[#e8a54b] font-medium shadow-sm"
                  : "bg-[#26231c] border-[#3a3428] text-[#a39886] hover:text-[#f4efe6] hover:bg-[#322d24]"
              }`}
              title={s.blurb}
            >
              {s.label}
            </button>
          ))}
          <button
            onClick={() => {
              setSelectedSampleId("blank");
              setContractBody("");
              setContractLabel("Custom Contract");
            }}
            className={`text-xs px-2.5 py-1.5 rounded-md font-mono border transition-all ${
              selectedSampleId === "blank"
                ? "bg-[#3a2c14] border-[#e8a54b] text-[#e8a54b]"
                : "bg-[#26231c] border-[#3a3428] text-[#746c60] hover:text-[#f4efe6]"
            }`}
          >
            + Blank
          </button>
        </div>
      </div>

      {/* Editor Container */}
      <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl flex flex-col flex-1 shadow-sm overflow-hidden min-h-[500px]">
        {/* Editor Meta Bar */}
        <div className="px-4 py-2.5 bg-[#26231c] border-b border-[#3a3428] flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-2 min-w-0">
            <input
              type="text"
              value={contractLabel}
              onChange={(e) => setContractLabel(e.target.value)}
              className="bg-transparent border-none text-xs font-mono font-medium text-[#f4efe6] focus:outline-none focus:ring-1 focus:ring-[#e8a54b] rounded px-1.5 py-0.5 w-44 truncate"
              placeholder="Contract name..."
            />
            <span
              className={`shrink-0 whitespace-nowrap text-[10px] font-mono px-2 py-0.5 rounded border ${
                isBytecode
                  ? "bg-purple-950/40 text-purple-300 border-purple-800/60"
                  : "bg-emerald-950/40 text-emerald-300 border-emerald-800/60"
              }`}
            >
              {isBytecode ? "EVM Runtime Bytecode" : "Solidity Source"}
            </span>
          </div>

          <div className="flex items-center gap-2 text-xs text-[#a39886] font-mono">
            <span>{contractBody.length.toLocaleString()} chars</span>
            <span>•</span>
            <span>{contractBody.split("\n").length} lines</span>
          </div>
        </div>

        {/* Code Textarea with subtle styling */}
        <div className="relative flex-1 flex flex-col">
          <textarea
            value={contractBody}
            onChange={(e) => {
              setSelectedSampleId("custom");
              setContractBody(e.target.value);
            }}
            placeholder="// Paste Solidity contract or runtime bytecode (0x...)..."
            spellCheck={false}
            className="w-full flex-1 p-4 bg-[#12110e]/70 text-[#f4efe6] font-mono text-xs sm:text-[13px] leading-relaxed resize-none focus:outline-none border-none selection:bg-[#e8a54b]/30"
            style={{ tabSize: 4 }}
          />

          {/* Editor bottom bar */}
          <div className="p-3 bg-[#1c1a16] border-t border-[#3a3428] flex items-center justify-between gap-2">
            <span className="text-[11px] text-[#746c60] font-mono flex items-center gap-1">
              <Terminal className="w-3.5 h-3.5 text-[#e8a54b]" />
              <span>Press Run Audit to analyze AST & opcodes</span>
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => {
                  setContractBody("");
                  setReport(analyzeInput("", "Untitled contract"));
                }}
                className="p-1.5 text-[#746c60] hover:text-[#e25b45] transition-colors"
                title="Clear editor"
              >
                <Trash2 className="w-4 h-4" />
              </button>
              <button
                onClick={() => copyToClipboard(contractBody, "input")}
                className="p-1.5 text-[#a39886] hover:text-[#f4efe6] transition-colors flex items-center gap-1 text-xs font-mono"
                title="Copy code"
              >
                {copiedKey === "input" ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
