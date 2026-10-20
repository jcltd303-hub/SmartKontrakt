import type { Dispatch, SetStateAction, RefObject } from "react";
import { parseAddressList, type BatchItem } from "@/lib/audit/address-fetcher";
import { Upload, FileText, Zap } from "lucide-react";

type Setter<T> = Dispatch<SetStateAction<T>>;
interface PipelineAddressInputProps {
  fileInputRef: RefObject<HTMLInputElement | null>;
  setFileMeta: Setter<{ name: string; count: number; sizeKb: number } | null>;
  setInputText: Setter<string>;
  fileMeta: { name: string; count: number; sizeKb: number } | null;
  inputText: string;
  sampleInput: string;
  selectedChainId: string;
  setQueue: (next: BatchItem[] | ((previous: BatchItem[]) => BatchItem[])) => boolean;
  setCurrentPage: Setter<number>;
  parsedCount: number;
  handleLoadNewBatch: () => void;
}

export function PipelineAddressInput({
  fileInputRef,
  setFileMeta,
  setInputText,
  fileMeta,
  inputText,
  sampleInput,
  selectedChainId,
  setQueue,
  setCurrentPage,
  parsedCount,
  handleLoadNewBatch
}: PipelineAddressInputProps) {
  return (
    <>
        {/* Left: Multiline Text Ingestion */}
        <div className="lg:col-span-5 bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-[#e8a54b]" />
              <h3 className="text-xs font-mono font-bold text-[#f4efe6] uppercase">
                Input Addresses (CSV or 1 per line)
              </h3>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <button
                onClick={() => fileInputRef.current?.click()}
                className="px-2.5 py-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[11px] font-mono text-[#f4efe6] flex items-center gap-1 transition-colors"
                title="Upload .csv or .txt (parses 1st column)"
              >
                <Upload className="w-3 h-3 text-[#e8a54b]" />
                <span>Upload .csv / .txt</span>
              </button>
              <button
                onClick={() => {
                  setFileMeta(null);
                  setInputText(sampleInput);
                }}
                className="px-2 py-1 text-[11px] font-mono text-[#a39886] hover:text-[#f4efe6]"
              >
                Reset Sample
              </button>
            </div>
          </div>

          {fileMeta && (
            <div className="flex items-center justify-between bg-[#26231c] border border-[#e8a54b]/40 rounded-lg p-2.5 text-xs font-mono text-[#e8a54b]">
              <div className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-[#e8a54b] shrink-0" />
                <span className="truncate">
                  <strong>{fileMeta.name}</strong> ({fileMeta.count.toLocaleString()} contracts, {fileMeta.sizeKb} KB) loaded in streaming memory mode
                </span>
              </div>
              <button
                onClick={() => {
                  setFileMeta(null);
                  setInputText(sampleInput);
                  setQueue(parseAddressList(sampleInput, selectedChainId));
                  setCurrentPage(1);
                }}
                className="text-[#a39886] hover:text-[#f4efe6] underline text-[11px] ml-2 shrink-0"
              >
                Clear File
              </button>
            </div>
          )}

          <textarea
            value={inputText}
            onChange={(e) => {
              setInputText(e.target.value);
              if (fileMeta) setFileMeta(null);
            }}
            placeholder={`ContractAddress,Name,Chain\n0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984,Uniswap Token,ethereum\n0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D,Router02,ethereum`}
            spellCheck={false}
            className="w-full h-56 bg-[#12110e] border border-[#3a3428] rounded-lg p-3 font-mono text-xs text-[#f4efe6] focus:outline-none focus:border-[#e8a54b] leading-relaxed resize-none"
          />

          <div className="flex items-center justify-between text-xs font-mono text-[#a39886]">
            <span>
              Parsed {parsedCount.toLocaleString()} valid addresses
            </span>
            <button
              onClick={handleLoadNewBatch}
              className="px-3 py-1 rounded bg-[#e8a54b] text-[#12110e] font-bold text-xs hover:brightness-110 transition-all"
            >
              Apply to Queue
            </button>
          </div>
        </div>

    </>
  );
}
