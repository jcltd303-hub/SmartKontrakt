import { ArrowRight, BookOpen, Loader2, X } from "lucide-react";
import type { WorkbenchController } from "./use-workbench-controller";

type FindingKnowledgeModalProps = Pick<
  WorkbenchController,
  | "ragModalFinding"
  | "setRagModalFinding"
  | "isLoadingRagModal"
  | "ragModalResults"
  | "setWorkbenchMode"
>;

export function FindingKnowledgeModal({
  ragModalFinding,
  setRagModalFinding,
  isLoadingRagModal,
  ragModalResults,
  setWorkbenchMode,
}: FindingKnowledgeModalProps) {
  return (
    <>
      {ragModalFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn font-mono text-xs">
          <div className="bg-[#1c1a16] border border-[#3a3428] rounded-2xl max-w-2xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="p-4 border-b border-[#3a3428] flex items-center justify-between bg-[#26231c]/60">
              <div className="flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-[#e8a54b]" />
                <div>
                  <h3 className="font-bold text-sm text-[#f4efe6]">
                    RAG Knowledgebase Intelligence
                  </h3>
                  <p className="text-[11px] text-[#a39886] truncate max-w-md">
                    Historical patterns & fixes for: {ragModalFinding.title}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setRagModalFinding(null)}
                className="p-1 rounded text-[#a39886] hover:text-[#f4efe6]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-4 overflow-y-auto flex flex-col gap-3 flex-1">
              {isLoadingRagModal ? (
                <div className="py-12 text-center text-[#a39886] flex flex-col items-center gap-2">
                  <Loader2 className="w-6 h-6 animate-spin text-[#e8a54b]" />
                  <span>Querying local RAG knowledge vectors...</span>
                </div>
              ) : ragModalResults.length === 0 ? (
                <div className="py-8 text-center text-[#746c60] flex flex-col items-center gap-2">
                  <BookOpen className="w-8 h-8 text-[#746c60]" />
                  <span>No direct knowledgebase matches found for this detector yet.</span>
                </div>
              ) : (
                ragModalResults.map((chunk) => (
                  <div
                    key={chunk.id}
                    className="p-3 bg-[#12110e] rounded-xl border border-[#3a3428] flex flex-col gap-2"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-1.5">
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-[#e8a54b]/20 text-[#e8a54b] border border-[#e8a54b]/40">
                          {chunk.relevanceScore}% MATCH
                        </span>
                        <span className="font-bold text-[#f4efe6] text-xs">{chunk.title}</span>
                      </div>
                      <span className="text-[10px] text-[#746c60]">{chunk.category}</span>
                    </div>
                    <p className="text-[#a39886] text-[11px] leading-relaxed line-clamp-3">
                      {chunk.content}
                    </p>
                    {chunk.metadata?.remediationSolidity && (
                      <div className="mt-1 p-2.5 bg-[#1c1a16] rounded border border-emerald-950 text-emerald-300 text-[11px] overflow-x-auto">
                        <pre>{chunk.metadata.remediationSolidity}</pre>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>

            <div className="p-3 border-t border-[#3a3428] flex items-center justify-between bg-[#26231c]/40">
              <button
                onClick={() => {
                  setRagModalFinding(null);
                  setWorkbenchMode("rag");
                }}
                className="text-xs text-[#e8a54b] hover:underline flex items-center gap-1"
              >
                <span>Open in Full RAG Knowledgebase</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => setRagModalFinding(null)}
                className="px-3 py-1.5 rounded bg-[#26231c] text-[#f4efe6] text-xs hover:bg-[#3a3428]"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
