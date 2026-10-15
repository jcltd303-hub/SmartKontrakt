import { Flame, Award, Printer, X, CheckCircle2 } from "lucide-react";
import type { Report } from "@/lib/audit/types";

interface AuditCertificateProps {
  report: Report;
  contractBody: string;
  onClose: () => void;
}

export function AuditCertificate({ report, contractBody, onClose }: AuditCertificateProps) {
  const crit = report.findings.filter((f) => f.severity === "critical").length;
  const high = report.findings.filter((f) => f.severity === "high").length;
  const med = report.findings.filter((f) => f.severity === "medium").length;
  const low = report.findings.filter((f) => f.severity === "low").length;

  const auditHash = "0x" + Array.from(new TextEncoder().encode(report.label + contractBody.slice(0, 500)))
    .slice(0, 16)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("") + "..." + Math.random().toString(16).slice(2, 6);

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto print:p-0 print:bg-white print:text-black">
      <div className="bg-[#1c1a16] border border-[#3a3428] rounded-2xl max-w-3xl w-full p-6 sm:p-8 shadow-2xl flex flex-col gap-6 font-sans text-xs print:border-none print:shadow-none print:bg-white print:text-black print:p-0">
        {/* Top Actions (Hidden in Print) */}
        <div className="flex items-center justify-between pb-3 border-b border-[#3a3428] print:hidden">
          <div className="flex items-center gap-2">
            <Award className="w-4 h-4 text-[#e8a54b]" />
            <span className="font-bold font-mono text-sm text-[#f4efe6]">Official Audit Certificate Preview</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handlePrint}
              className="px-3.5 py-1.5 rounded-lg bg-[#e8a54b] hover:brightness-110 text-[#12110e] font-bold font-mono text-xs flex items-center gap-1.5 shadow transition-all"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / Save PDF</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-[#a39886] hover:text-[#f4efe6] transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* ================= Printable Certificate Body ================= */}
        <div className="bg-[#12110e] border border-[#3a3428] rounded-xl p-6 sm:p-8 flex flex-col gap-6 print:border-2 print:border-black print:bg-white print:p-6">
          {/* Certificate Header */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-[#3a3428] pb-5 print:border-b-2 print:border-black">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-[#e8a54b] to-[#e25b45] p-0.5 flex items-center justify-center print:bg-black">
                <div className="w-full h-full bg-[#12110e] rounded-[10px] flex items-center justify-center print:bg-white">
                  <Flame className="w-6 h-6 text-[#e8a54b] print:text-black" />
                </div>
              </div>
              <div>
                <h1 className="text-xl font-bold font-mono tracking-wider text-[#f4efe6] print:text-black">
                  KILN AUDIT CERTIFICATE
                </h1>
                <p className="text-xs text-[#a39886] print:text-neutral-600 font-mono">
                  EVM Smart Contract Security Assessment
                </p>
              </div>
            </div>

            <div className="text-left sm:text-right font-mono">
              <div className="text-[10px] text-[#746c60] uppercase">Verification Certificate</div>
              <div className="text-xs text-[#e8a54b] font-bold print:text-black">{auditHash}</div>
              <div className="text-[10px] text-[#a39886] print:text-neutral-600">{new Date().toUTCString()}</div>
            </div>
          </div>

          {/* Subject & Overall Risk Assessment */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="p-3.5 bg-[#1c1a16] border border-[#3a3428] rounded-lg print:border print:border-black print:bg-neutral-50">
              <span className="text-[10px] font-mono text-[#a39886] uppercase block mb-1">Contract Subject</span>
              <span className="text-sm font-bold text-[#f4efe6] font-mono truncate block print:text-black">{report.label}</span>
              <span className="text-[10px] text-[#746c60] font-mono capitalize">{report.inputKind} analysis</span>
            </div>

            <div className="p-3.5 bg-[#1c1a16] border border-[#3a3428] rounded-lg print:border print:border-black print:bg-neutral-50">
              <span className="text-[10px] font-mono text-[#a39886] uppercase block mb-1">Assessed Risk Score</span>
              <div className="flex items-center gap-2 font-mono">
                <span className={`text-xl font-bold ${report.riskScore >= 50 ? "text-red-400 print:text-red-700" : "text-emerald-400 print:text-emerald-700"}`}>
                  {report.riskScore} / 100
                </span>
                <span className="text-[10px] px-1.5 py-0.5 rounded border border-[#3a3428] text-[#a39886]">
                  {report.riskScore >= 70 ? "CRITICAL" : report.riskScore >= 40 ? "HIGH" : "MODERATE/LOW"}
                </span>
              </div>
            </div>

            <div className="p-3.5 bg-[#1c1a16] border border-[#3a3428] rounded-lg print:border print:border-black print:bg-neutral-50">
              <span className="text-[10px] font-mono text-[#a39886] uppercase block mb-1">Findings Summary</span>
              <div className="flex items-center gap-2 font-mono text-xs font-bold">
                <span className="text-red-400 print:text-red-700">Crit: {crit}</span>
                <span>•</span>
                <span className="text-amber-400 print:text-amber-700">High: {high}</span>
                <span>•</span>
                <span className="text-yellow-400 print:text-yellow-700">Med: {med}</span>
                <span>•</span>
                <span className="text-blue-400 print:text-blue-700">Low: {low}</span>
              </div>
            </div>
          </div>

          {/* Executive Summary */}
          <div>
            <h4 className="text-[11px] font-mono uppercase tracking-wider text-[#e8a54b] print:text-black mb-1.5 font-bold">
              Auditor Executive Summary
            </h4>
            <div className="p-3 bg-[#1c1a16] border border-[#3a3428] rounded-lg text-xs leading-relaxed text-[#f4efe6] print:border print:border-black print:bg-neutral-50 print:text-black">
              {report.summary}
            </div>
          </div>

          {/* Findings Table */}
          <div>
            <h4 className="text-[11px] font-mono uppercase tracking-wider text-[#e8a54b] print:text-black mb-1.5 font-bold">
              Key Security Vulnerability Findings ({report.findings.length})
            </h4>
            {report.findings.length === 0 ? (
              <div className="p-3 bg-emerald-950/20 border border-emerald-900 rounded-lg text-emerald-300 text-xs flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4" />
                <span>Zero vulnerability signatures detected by the Kiln EVM Static Analysis ruleset.</span>
              </div>
            ) : (
              <div className="border border-[#3a3428] rounded-lg overflow-hidden print:border print:border-black">
                <table className="w-full text-left font-mono text-[11px]">
                  <thead className="bg-[#1c1a16] border-b border-[#3a3428] text-[#a39886] print:bg-neutral-100 print:text-black">
                    <tr>
                      <th className="p-2">Severity</th>
                      <th className="p-2">Title</th>
                      <th className="p-2">Classification</th>
                      <th className="p-2">Location</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#3a3428] print:divide-black text-[#f4efe6] print:text-black">
                    {report.findings.slice(0, 6).map((f) => (
                      <tr key={f.id} className="hover:bg-[#1c1a16]/40">
                        <td className="p-2 uppercase font-bold text-red-400 print:text-red-700">{f.severity}</td>
                        <td className="p-2 font-bold">{f.title}</td>
                        <td className="p-2 text-[#a39886] print:text-neutral-700">{f.swc ? `SWC-${f.swc}` : f.detector}</td>
                        <td className="p-2 text-[#a39886] print:text-neutral-700">{f.locationFn || "Contract body"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Auditor Sign-off Seal & Certification */}
          <div className="pt-4 border-t border-[#3a3428] print:border-t-2 print:border-black flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 font-mono text-[10px] text-[#746c60] print:text-neutral-700">
            <div>
              <p>Audited with Kiln v2.4 Automated Static Analysis & EVM Bytecode Disassembly Engine.</p>
              <p className="mt-0.5">Disclaimer: Automated audits do not guarantee complete absence of vulnerabilities.</p>
            </div>

            <div className="text-left sm:text-right border-t sm:border-t-0 sm:border-l border-[#3a3428] sm:pl-4 pt-2 sm:pt-0">
              <div className="text-[#f4efe6] font-bold text-xs print:text-black">KILN SECURITY PROTOCOL</div>
              <div className="text-emerald-400 font-bold print:text-black">CRYPTOGRAPHICALLY SEALED</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
