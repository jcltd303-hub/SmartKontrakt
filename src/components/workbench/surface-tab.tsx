import { Binary, Code2, Layers } from "lucide-react";
import type { WorkbenchController } from "./use-workbench-controller";

type SurfaceTabProps = Pick<WorkbenchController, "activeTab" | "report">;

export function SurfaceTab({ activeTab, report }: SurfaceTabProps) {
  return (
    <>
      {activeTab === "surface" && (
        <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 flex flex-col gap-5">
          {/* Functions Surface */}
          <div>
            <h3 className="text-xs font-mono font-bold text-[#e8a54b] uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
              <Code2 className="w-3.5 h-3.5" />
              Discovered Functions ({report?.inventory.functions.length ?? 0})
            </h3>
            {report?.inventory.functions.length === 0 ? (
              <p className="text-xs text-[#746c60]">
                No function declarations parsed in this source.
              </p>
            ) : (
              <div className="border border-[#3a3428] rounded-lg overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-[#26231c] text-[#a39886] border-b border-[#3a3428]">
                    <tr>
                      <th className="p-2.5">Function Name</th>
                      <th className="p-2.5">Visibility</th>
                      <th className="p-2.5">Mutability</th>
                      <th className="p-2.5">Modifiers</th>
                      <th className="p-2.5">Parameters</th>
                      <th className="p-2.5">Line</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#3a3428]">
                    {report?.inventory.functions.map((fn, idx) => (
                      <tr key={idx} className="hover:bg-[#26231c]/50">
                        <td className="p-2.5 font-bold text-[#f4efe6]">{fn.name}</td>
                        <td className="p-2.5">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] ${
                              fn.visibility === "external" || fn.visibility === "public"
                                ? "bg-amber-950/60 text-amber-300 border border-amber-800"
                                : "bg-[#26231c] text-[#a39886]"
                            }`}
                          >
                            {fn.visibility}
                          </span>
                        </td>
                        <td className="p-2.5 text-[#a39886]">{fn.mutability}</td>
                        <td className="p-2.5">
                          {fn.modifiers.length > 0 ? (
                            <span className="text-emerald-400">{fn.modifiers.join(", ")}</span>
                          ) : (
                            <span className="text-[#746c60]">—</span>
                          )}
                        </td>
                        <td className="p-2.5 text-[#a39886] max-w-[200px] truncate">
                          {fn.params || "—"}
                        </td>
                        <td className="p-2.5 text-[#746c60]">{fn.line ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* State Variables */}
          <div>
            <h3 className="text-xs font-mono font-bold text-[#e8a54b] uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5" />
              State Variables ({report?.inventory.stateVars.length ?? 0})
            </h3>
            {report?.inventory.stateVars.length === 0 ? (
              <p className="text-xs text-[#746c60]">No state variables parsed.</p>
            ) : (
              <div className="border border-[#3a3428] rounded-lg overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-[#26231c] text-[#a39886] border-b border-[#3a3428]">
                    <tr>
                      <th className="p-2.5">Variable Name</th>
                      <th className="p-2.5">Type</th>
                      <th className="p-2.5">Visibility</th>
                      <th className="p-2.5">Constant/Immutable</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#3a3428]">
                    {report?.inventory.stateVars.map((v, idx) => (
                      <tr key={idx} className="hover:bg-[#26231c]/50">
                        <td className="p-2.5 font-bold text-[#f4efe6]">{v.name}</td>
                        <td className="p-2.5 text-blue-300">{v.typeName}</td>
                        <td className="p-2.5 text-[#a39886]">{v.visibility}</td>
                        <td className="p-2.5">
                          {v.constOrImmutable ? (
                            <span className="text-emerald-400">Yes</span>
                          ) : (
                            <span className="text-[#746c60]">No</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Function Selectors */}
          <div>
            <h3 className="text-xs font-mono font-bold text-[#e8a54b] uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
              <Binary className="w-3.5 h-3.5" />
              4-Byte Function Selectors ({report?.inventory.selectors.length ?? 0})
            </h3>
            {report?.inventory.selectors.length === 0 ? (
              <p className="text-xs text-[#746c60]">No 4-byte selectors resolved.</p>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {report?.inventory.selectors.map((sel, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 bg-[#26231c] border border-[#3a3428] rounded-lg font-mono text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-[#e8a54b] font-bold">{sel.selector}</span>
                      <span
                        className="text-[#a39886] truncate max-w-[200px]"
                        title={sel.signature ?? ""}
                      >
                        {sel.signature ?? "unknown()"}
                      </span>
                    </div>
                    {sel.signatures && sel.signatures.length > 1 && (
                      <details className="mt-1">
                        <summary className="cursor-pointer text-[11px] text-[#e8a54b]">
                          +{sel.signatures.length - 1} more{" "}
                          {sel.signatures.length - 1 === 1 ? "signature" : "signatures"}
                        </summary>
                        <div className="mt-1 flex flex-col gap-0.5 text-[11px] text-[#a39886]">
                          {sel.signatures.slice(1).map((s) => (
                            <span key={s} title={s}>
                              {s}
                            </span>
                          ))}
                        </div>
                      </details>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Event Signatures (4byte) — only resolved topics shown;
                  analyzeBytecode also records unresolved PUSH32 candidates,
                  which enrichment fills when the table knows them. */}
          <div>
            <h3 className="text-xs font-mono font-bold text-[#e8a54b] uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
              <Binary className="w-3.5 h-3.5" />
              32-Byte Event Signatures (
              {(report?.inventory.topics ?? []).filter((t) => t.signature).length})
            </h3>
            {(report?.inventory.topics ?? []).filter((t) => t.signature).length === 0 ? (
              <p className="text-xs text-[#746c60]">No event topics resolved.</p>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {(report?.inventory.topics ?? [])
                  .filter((t) => t.signature)
                  .map((t, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 bg-[#26231c] border border-[#3a3428] rounded-lg flex items-center justify-between font-mono text-xs"
                    >
                      <span
                        className="text-[#e8a54b] font-bold truncate max-w-[180px]"
                        title={t.topic}
                      >
                        {t.topic}
                      </span>
                      <span
                        className="text-[#a39886] truncate max-w-[200px]"
                        title={t.signature ?? ""}
                      >
                        {t.signature ?? "unknown()"}
                      </span>
                    </div>
                  ))}
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
