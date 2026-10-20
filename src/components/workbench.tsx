import { AuditCertificate } from "@/components/audit-certificate";
import { BatchPipeline } from "@/components/batch-pipeline";
import { InteractiveAuditTab } from "@/components/interactive-audit";
import { LocalDbRecords } from "@/components/local-db-records";
import { RagKnowledgebase } from "@/components/rag-knowledgebase";
import { RecentPocAudits } from "@/components/recent-poc-audits";
import { SupabaseDbModal } from "@/components/supabase-db-modal";
import type { ScanSummary } from "@/lib/audit/persist.server";
import { resolveContractDisplayName } from "@/lib/audit/simulator";
import {
  Activity,
  Bug,
  Check,
  Clock,
  Copy,
  FileText,
  GitBranch,
  Info,
  Layers,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Wand2,
} from "lucide-react";
import { AiTab } from "./workbench/ai-tab";
import { BytecodeTab } from "./workbench/bytecode-tab";
import { ContractEditor } from "./workbench/contract-editor";
import { FindingKnowledgeModal } from "./workbench/finding-knowledge-modal";
import { FindingsTab } from "./workbench/findings-tab";
import { WorkbenchHeader } from "./workbench/header";
import { HistoryTab } from "./workbench/history-tab";
import { ProbeTab } from "./workbench/probe-tab";
import { ReportTab } from "./workbench/report-tab";
import { SurfaceTab } from "./workbench/surface-tab";
import { useWorkbenchController } from "./workbench/use-workbench-controller";
import { WalkthroughTab } from "./workbench/walkthrough-tab";

interface WorkbenchProps {
  initialScans?: ScanSummary[];
}
export function Workbench({ initialScans = [] }: WorkbenchProps) {
  const {
    fileInputRef,
    handleFileUpload,
    setWorkbenchMode,
    workbenchMode,
    setIsSupabaseDbModalOpen,
    dbInfo,
    handleSaveToLocalDb,
    isSavingDb,
    setShowCertificate,
    handleRunAnalysis,
    dbSavedNotice,
    setDbSavedNotice,
    handleInspectPipelineItem,
    handleLoadStoredScan,
    setContractBody,
    setContractLabel,
    handleLoadStoredScanById,
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
    contractLabel,
    isBytecode,
    contractBody,
    setReport,
    copyToClipboard,
    copiedKey,
    report,
    risk,
    probes,
    setActiveTab,
    activeTab,
    aiReview,
    handleTriggerAiReview,
    handleRunManualProbe,
    scanHistory,
    generateMarkdownReport,
    setSeverityFilter,
    severityFilter,
    findingSearch,
    setFindingSearch,
    filteredFindings,
    expandedFindings,
    findingPocRuns,
    setExpandedFindings,
    handleRunFindingPoc,
    findingPocRunning,
    handleRetryFindingPocSave,
    findingTriage,
    setFindingTriage,
    handleOpenRagForFinding,
    disasmLines,
    setBytecodeSubView,
    bytecodeSubView,
    disasmFilter,
    setDisasmFilter,
    cfgDisassembly,
    isLoadingAi,
    pocRunning,
    pocResult,
    pocSaved,
    handleRunDeepAgent,
    deepAgentRunning,
    deepAgentStatus,
    deepAgentError,
    deepAgentRounds,
    isProbing,
    getRiskColor,
    handleDeleteScan,
    showCertificate,
    ragModalFinding,
    setRagModalFinding,
    isLoadingRagModal,
    ragModalResults,
    isSupabaseDbModalOpen,
  } = useWorkbenchController(initialScans);
  return (
    <div className="min-h-screen bg-[#12110e] text-[#f4efe6] flex flex-col font-sans selection:bg-[#e8a54b]/30 selection:text-[#f4efe6]">
      {/* Hidden file input for Solidity/bytecode upload */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".sol,.hex,.bin,.txt"
        onChange={handleFileUpload}
        className="hidden"
      />

      {/* Top Banner Navigation */}
      <WorkbenchHeader
        setWorkbenchMode={setWorkbenchMode}
        workbenchMode={workbenchMode}
        setIsSupabaseDbModalOpen={setIsSupabaseDbModalOpen}
        dbInfo={dbInfo}
        handleSaveToLocalDb={handleSaveToLocalDb}
        isSavingDb={isSavingDb}
        fileInputRef={fileInputRef}
        setShowCertificate={setShowCertificate}
        handleRunAnalysis={handleRunAnalysis}
        dbSavedNotice={dbSavedNotice}
        setDbSavedNotice={setDbSavedNotice}
      />

      {/* Main Layout Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6">
        <div hidden={workbenchMode !== "pipeline"}>
          <BatchPipeline onInspectItem={handleInspectPipelineItem} />
        </div>
        {workbenchMode === "pipeline" ? null : workbenchMode === "records" ? (
          <LocalDbRecords
            onLoadInWorkbench={handleLoadStoredScan}
            onNavigateToRag={() => setWorkbenchMode("rag")}
            onNavigateToPocAudits={() => setWorkbenchMode("poc-audits")}
          />
        ) : workbenchMode === "rag" ? (
          <RagKnowledgebase
            onLoadContractInWorkbench={(body, label) => {
              setContractBody(body);
              setContractLabel(label);
              setWorkbenchMode("audit");
              handleRunAnalysis(body, label);
            }}
          />
        ) : workbenchMode === "interactive" ? (
          <InteractiveAuditTab />
        ) : workbenchMode === "poc-audits" ? (
          <RecentPocAudits onLoadScanInWorkbench={handleLoadStoredScanById} />
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* ================= Left Column: Contract Editor & Input ================= */}
            <ContractEditor
              singleAddress={singleAddress}
              setSingleAddress={setSingleAddress}
              setAddressFetchError={setAddressFetchError}
              singleAddressChain={singleAddressChain}
              setSingleAddressChain={setSingleAddressChain}
              handleFetchSingleAddress={handleFetchSingleAddress}
              isFetchingAddress={isFetchingAddress}
              addressFetchError={addressFetchError}
              proxyInfo={proxyInfo}
              handleSelectSample={handleSelectSample}
              selectedSampleId={selectedSampleId}
              setSelectedSampleId={setSelectedSampleId}
              setContractBody={setContractBody}
              setContractLabel={setContractLabel}
              contractLabel={contractLabel}
              isBytecode={isBytecode}
              contractBody={contractBody}
              setReport={setReport}
              copyToClipboard={copyToClipboard}
              copiedKey={copiedKey}
            />

            {/* ================= Right Column: Security Analysis & Findings ================= */}
            <section className="lg:col-span-7 flex min-w-0 flex-col gap-4">
              {/* Executive Header / Scorecard */}
              {report && (
                <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 sm:p-5 shadow-sm">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#3a3428]">
                    {/* Score & Rating */}
                    <div className="flex items-center gap-4">
                      <div className="relative w-16 h-16 rounded-xl bg-[#26231c] border border-[#3a3428] flex flex-col items-center justify-center shadow-inner">
                        <span className="text-[10px] font-mono text-[#a39886] uppercase">RISK</span>
                        <span className={`text-2xl font-bold font-mono ${risk.text}`}>
                          {report.riskScore}
                        </span>
                        <div className="absolute -bottom-1 -right-1">
                          {report.riskScore >= 50 ? (
                            <ShieldAlert className="w-5 h-5 text-red-400 drop-shadow" />
                          ) : (
                            <ShieldCheck className="w-5 h-5 text-emerald-400 drop-shadow" />
                          )}
                        </div>
                      </div>

                      <div>
                        <div className="flex items-center gap-2">
                          {/* Item 1: the header shows the unified display name —
                          on-chain name() probe first, then the analyzed
                          contract — and updates when probes land. */}
                          <h2 className="text-base font-bold text-[#f4efe6]">
                            {resolveContractDisplayName(probes, report)}
                          </h2>
                          <span
                            className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${risk.text} bg-[#26231c] border border-[#3a3428]`}
                          >
                            {risk.label}
                          </span>
                        </div>
                        <p className="text-xs text-[#a39886] mt-0.5 max-w-md line-clamp-1">
                          {report.inventory.kindNote || "Analysis completed"}
                        </p>
                      </div>
                    </div>

                    {/* Severity Counters Bar */}
                    <div className="flex items-center gap-1.5 bg-[#26231c] p-1.5 rounded-lg border border-[#3a3428]">
                      <div className="px-2 py-1 text-center font-mono">
                        <div className="text-[10px] text-[#a39886] uppercase">Crit</div>
                        <div className="text-xs font-bold text-red-400">
                          {report.findings.filter((f) => f.severity === "critical").length}
                        </div>
                      </div>
                      <div className="w-px h-6 bg-[#3a3428]" />
                      <div className="px-2 py-1 text-center font-mono">
                        <div className="text-[10px] text-[#a39886] uppercase">High</div>
                        <div className="text-xs font-bold text-amber-400">
                          {report.findings.filter((f) => f.severity === "high").length}
                        </div>
                      </div>
                      <div className="w-px h-6 bg-[#3a3428]" />
                      <div className="px-2 py-1 text-center font-mono">
                        <div className="text-[10px] text-[#a39886] uppercase">Med</div>
                        <div className="text-xs font-bold text-yellow-400">
                          {report.findings.filter((f) => f.severity === "medium").length}
                        </div>
                      </div>
                      <div className="w-px h-6 bg-[#3a3428]" />
                      <div className="px-2 py-1 text-center font-mono">
                        <div className="text-[10px] text-[#a39886] uppercase">Low</div>
                        <div className="text-xs font-bold text-blue-400">
                          {report.findings.filter((f) => f.severity === "low").length}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Summary Text */}
                  <div className="pt-3 flex items-start gap-2 text-xs text-[#f4efe6]/90 leading-relaxed font-sans">
                    <Info className="w-4 h-4 text-[#e8a54b] shrink-0 mt-0.5" />
                    <span>{report.summary}</span>
                  </div>
                </div>
              )}

              {/* Tab Navigation */}
              <div className="flex items-center justify-between border-b border-[#3a3428] pb-1 overflow-x-auto gap-2">
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => setActiveTab("findings")}
                    className={`px-3 py-2 text-xs font-mono font-medium rounded-t-lg transition-colors flex items-center gap-1.5 ${
                      activeTab === "findings"
                        ? "bg-[#1c1a16] text-[#e8a54b] border-t-2 border-[#e8a54b] font-semibold"
                        : "text-[#a39886] hover:text-[#f4efe6]"
                    }`}
                  >
                    <Bug className="w-3.5 h-3.5" />
                    <span>Findings ({report?.findings.length ?? 0})</span>
                  </button>

                  <button
                    onClick={() => setActiveTab("surface")}
                    className={`px-3 py-2 text-xs font-mono font-medium rounded-t-lg transition-colors flex items-center gap-1.5 ${
                      activeTab === "surface"
                        ? "bg-[#1c1a16] text-[#e8a54b] border-t-2 border-[#e8a54b] font-semibold"
                        : "text-[#a39886] hover:text-[#f4efe6]"
                    }`}
                  >
                    <Layers className="w-3.5 h-3.5" />
                    <span>Surface ABI ({report?.inventory.functions.length ?? 0})</span>
                  </button>

                  <button
                    onClick={() => setActiveTab("bytecode")}
                    className={`px-3 py-2 text-xs font-mono font-medium rounded-t-lg transition-colors flex items-center gap-1.5 ${
                      activeTab === "bytecode"
                        ? "bg-[#1c1a16] text-[#e8a54b] border-t-2 border-[#e8a54b] font-semibold"
                        : "text-[#a39886] hover:text-[#f4efe6]"
                    }`}
                  >
                    <GitBranch className="w-3.5 h-3.5" />
                    <span>Bytecode & CFG</span>
                  </button>

                  <button
                    onClick={() => {
                      setActiveTab("ai");
                      if (!aiReview) handleTriggerAiReview();
                    }}
                    className={`px-3 py-2 text-xs font-mono font-medium rounded-t-lg transition-colors flex items-center gap-1.5 ${
                      activeTab === "ai"
                        ? "bg-[#1c1a16] text-[#e8a54b] border-t-2 border-[#e8a54b] font-semibold"
                        : "text-[#a39886] hover:text-[#f4efe6]"
                    }`}
                  >
                    <Sparkles className="w-3.5 h-3.5 text-[#e8a54b]" />
                    <span>AI Threat & Foundry</span>
                  </button>

                  <button
                    onClick={() => {
                      setActiveTab("probe");
                      if (probes.length === 0 && singleAddress) handleRunManualProbe();
                    }}
                    className={`px-3 py-2 text-xs font-mono font-medium rounded-t-lg transition-colors flex items-center gap-1.5 ${
                      activeTab === "probe"
                        ? "bg-[#1c1a16] text-[#e8a54b] border-t-2 border-[#e8a54b] font-semibold"
                        : "text-[#a39886] hover:text-[#f4efe6]"
                    }`}
                  >
                    <Activity className="w-3.5 h-3.5" />
                    <span>State Probe ({probes.filter((p) => p.success).length})</span>
                  </button>

                  <button
                    onClick={() => setActiveTab("report")}
                    className={`px-3 py-2 text-xs font-mono font-medium rounded-t-lg transition-colors flex items-center gap-1.5 ${
                      activeTab === "report"
                        ? "bg-[#1c1a16] text-[#e8a54b] border-t-2 border-[#e8a54b] font-semibold"
                        : "text-[#a39886] hover:text-[#f4efe6]"
                    }`}
                  >
                    <FileText className="w-3.5 h-3.5" />
                    <span>Full Report</span>
                  </button>

                  <button
                    onClick={() => setActiveTab("history")}
                    className={`px-3 py-2 text-xs font-mono font-medium rounded-t-lg transition-colors flex items-center gap-1.5 ${
                      activeTab === "history"
                        ? "bg-[#1c1a16] text-[#e8a54b] border-t-2 border-[#e8a54b] font-semibold"
                        : "text-[#a39886] hover:text-[#f4efe6]"
                    }`}
                  >
                    <Clock className="w-3.5 h-3.5" />
                    <span>Scans ({scanHistory.length})</span>
                  </button>

                  <button
                    onClick={() => setActiveTab("walkthrough")}
                    className={`px-3 py-2 text-xs font-mono font-medium rounded-t-lg transition-colors flex items-center gap-1.5 ${
                      activeTab === "walkthrough"
                        ? "bg-[#1c1a16] text-[#e8a54b] border-t-2 border-[#e8a54b] font-semibold"
                        : "text-[#a39886] hover:text-[#f4efe6]"
                    }`}
                  >
                    <Wand2 className="w-3.5 h-3.5 text-[#e8a54b]" />
                    <span>Exploit & Mitigation</span>
                  </button>
                </div>

                {/* Quick Export Button */}
                {report && (
                  <button
                    onClick={() => copyToClipboard(generateMarkdownReport(), "md-report")}
                    className="text-xs px-2.5 py-1 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#a39886] hover:text-[#f4efe6] font-mono flex items-center gap-1 transition-colors"
                    title="Copy Full Markdown Report"
                  >
                    {copiedKey === "md-report" ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-400" />
                        <span>Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3 text-[#e8a54b]" />
                        <span>Copy MD</span>
                      </>
                    )}
                  </button>
                )}
              </div>

              {/* ================= Tab 1: Findings ================= */}
              <FindingsTab
                activeTab={activeTab}
                report={report}
                setSeverityFilter={setSeverityFilter}
                severityFilter={severityFilter}
                findingSearch={findingSearch}
                setFindingSearch={setFindingSearch}
                filteredFindings={filteredFindings}
                expandedFindings={expandedFindings}
                findingPocRuns={findingPocRuns}
                setExpandedFindings={setExpandedFindings}
                handleRunFindingPoc={handleRunFindingPoc}
                findingPocRunning={findingPocRunning}
                singleAddress={singleAddress}
                singleAddressChain={singleAddressChain}
                copyToClipboard={copyToClipboard}
                copiedKey={copiedKey}
                handleRetryFindingPocSave={handleRetryFindingPocSave}
                findingTriage={findingTriage}
                setFindingTriage={setFindingTriage}
                handleOpenRagForFinding={handleOpenRagForFinding}
              />

              {/* ================= Tab 2: Surface ABI ================= */}
              <SurfaceTab activeTab={activeTab} report={report} />

              {/* ================= Tab 3: Bytecode & Disassembly ================= */}
              <BytecodeTab
                activeTab={activeTab}
                report={report}
                contractBody={contractBody}
                disasmLines={disasmLines}
                setBytecodeSubView={setBytecodeSubView}
                bytecodeSubView={bytecodeSubView}
                disasmFilter={disasmFilter}
                setDisasmFilter={setDisasmFilter}
                cfgDisassembly={cfgDisassembly}
              />

              {/* ================= Tab: AI Threat Modeling & Foundry Exploit ================= */}
              <AiTab
                activeTab={activeTab}
                handleTriggerAiReview={handleTriggerAiReview}
                isLoadingAi={isLoadingAi}
                aiReview={aiReview}
                copyToClipboard={copyToClipboard}
                copiedKey={copiedKey}
                singleAddress={singleAddress}
                singleAddressChain={singleAddressChain}
                report={report}
                pocRunning={pocRunning}
                pocResult={pocResult}
                pocSaved={pocSaved}
                handleRunDeepAgent={handleRunDeepAgent}
                deepAgentRunning={deepAgentRunning}
                deepAgentStatus={deepAgentStatus}
                deepAgentError={deepAgentError}
                deepAgentRounds={deepAgentRounds}
              />

              {/* ================= Tab: On-Chain State Probes ================= */}
              <ProbeTab
                activeTab={activeTab}
                handleRunManualProbe={handleRunManualProbe}
                isProbing={isProbing}
                probes={probes}
              />

              {/* ================= Tab 4: Full Report ================= */}
              <ReportTab
                activeTab={activeTab}
                copyToClipboard={copyToClipboard}
                generateMarkdownReport={generateMarkdownReport}
                copiedKey={copiedKey}
              />

              {/* ================= Tab 5: Scan History ================= */}
              <HistoryTab
                activeTab={activeTab}
                scanHistory={scanHistory}
                getRiskColor={getRiskColor}
                handleSelectSample={handleSelectSample}
                setContractLabel={setContractLabel}
                handleRunAnalysis={handleRunAnalysis}
                contractBody={contractBody}
                setActiveTab={setActiveTab}
                handleDeleteScan={handleDeleteScan}
              />

              <WalkthroughTab activeTab={activeTab} report={report} contractBody={contractBody} />
            </section>
          </div>
        )}
      </main>

      {/* Official Audit Certificate Printable Modal */}
      {showCertificate && (
        <AuditCertificate
          report={report}
          contractBody={contractBody}
          onClose={() => setShowCertificate(false)}
        />
      )}

      {/* Quick RAG Finding Intelligence Modal */}
      <FindingKnowledgeModal
        ragModalFinding={ragModalFinding}
        setRagModalFinding={setRagModalFinding}
        isLoadingRagModal={isLoadingRagModal}
        ragModalResults={ragModalResults}
        setWorkbenchMode={setWorkbenchMode}
      />

      <SupabaseDbModal
        isOpen={isSupabaseDbModalOpen}
        onClose={() => setIsSupabaseDbModalOpen(false)}
      />
    </div>
  );
}
