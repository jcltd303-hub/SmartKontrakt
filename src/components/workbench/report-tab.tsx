import { Check, Copy, Download } from "lucide-react";
import type { WorkbenchController } from "./use-workbench-controller";

type ReportTabProps = Pick<
  WorkbenchController,
  | "activeTab"
  | "copyToClipboard"
  | "generateMarkdownReport"
  | "handleDownloadMarkdownReport"
  | "copiedKey"
>;

export function ReportTab({
  activeTab,
  copyToClipboard,
  generateMarkdownReport,
  handleDownloadMarkdownReport,
  copiedKey,
}: ReportTabProps) {
  return (
    <>
      {activeTab === "report" && (
        <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-5 flex flex-col gap-4 font-mono text-xs">
          <div className="flex items-center justify-between pb-3 border-b border-[#3a3428]">
            <div>
              <h3 className="text-sm font-bold text-[#f4efe6]">Complete Audit Report (Markdown)</h3>
              <p className="text-[11px] text-[#a39886]">
                Formal security finding documentation & summary
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={handleDownloadMarkdownReport}
                className="px-3 py-1.5 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] font-bold text-xs flex items-center gap-1.5 shadow transition-colors"
                title="Download Markdown Report (.md)"
              >
                <Download className="w-3.5 h-3.5 text-[#e8a54b]" />
                <span>Download .md</span>
              </button>
              <button
                onClick={() => copyToClipboard(generateMarkdownReport(), "md-full")}
                className="px-3 py-1.5 rounded bg-[#e8a54b] text-[#12110e] font-bold text-xs flex items-center gap-1.5 shadow hover:bg-[#f3b562] transition-colors"
              >
                {copiedKey === "md-full" ? (
                  <Check className="w-3.5 h-3.5" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
                <span>Copy Report</span>
              </button>
            </div>
          </div>

          <div className="bg-[#12110e] p-4 rounded-lg border border-[#3a3428] max-h-[500px] overflow-y-auto leading-relaxed text-[#f4efe6]">
            <pre className="whitespace-pre-wrap">{generateMarkdownReport()}</pre>
          </div>
        </div>
      )}
    </>
  );
}
