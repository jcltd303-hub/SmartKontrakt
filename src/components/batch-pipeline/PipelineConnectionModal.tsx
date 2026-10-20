import type { Dispatch, SetStateAction } from "react";
import type { SupabaseConfig } from "@/lib/supabase";
import { Database, Loader2, RefreshCw } from "lucide-react";

type Setter<T> = Dispatch<SetStateAction<T>>;
interface PipelineConnectionModalProps {
  isSupabaseModalOpen: boolean;
  setIsSupabaseModalOpen: Setter<boolean>;
  setIsDbWiringModalOpen: Setter<boolean>;
  supabaseCfg: SupabaseConfig;
  setSupabaseCfg: Setter<SupabaseConfig>;
  supabaseStatusMsg: { ok: boolean; msg: string } | null;
  isTestingSupabase: boolean;
  handleTestSupabase: () => Promise<void>;
  handleSaveSupabaseConfig: () => void;
}

export function PipelineConnectionModal({
  isSupabaseModalOpen,
  setIsSupabaseModalOpen,
  setIsDbWiringModalOpen,
  supabaseCfg,
  setSupabaseCfg,
  supabaseStatusMsg,
  isTestingSupabase,
  handleTestSupabase,
  handleSaveSupabaseConfig
}: PipelineConnectionModalProps) {
  return (
    <>
      {isSupabaseModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl max-w-lg w-full p-5 shadow-2xl flex flex-col gap-4 text-xs font-mono">
            <div className="flex items-center justify-between pb-2 border-b border-[#3a3428]">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-[#e8a54b]" />
                <h3 className="font-bold text-sm text-[#f4efe6]">Supabase Pipeline Persistence</h3>
              </div>
              <button
                onClick={() => setIsSupabaseModalOpen(false)}
                className="text-[#a39886] hover:text-[#f4efe6]"
              >
                ✕
              </button>
            </div>

            <p className="text-[#a39886] text-[11px] leading-relaxed font-sans">
              Connect your Supabase project to automatically persist batch audits in real-time, resume queues across devices, and archive findings. (Works out-of-the-box on Vercel deployment with no native drivers required).
            </p>

            <div className="flex flex-col gap-3">
              <div>
                <label className="text-[#a39886] text-[10px] uppercase block mb-1">Supabase Project URL</label>
                <input
                  type="text"
                  placeholder="https://xyzproject.supabase.co"
                  value={supabaseCfg.url}
                  onChange={(e) => setSupabaseCfg({ ...supabaseCfg, url: e.target.value })}
                  className="w-full bg-[#12110e] border border-[#3a3428] rounded px-3 py-1.5 text-[#f4efe6] focus:outline-none focus:border-[#e8a54b]"
                />
              </div>

              <div>
                <label className="text-[#a39886] text-[10px] uppercase block mb-1">Supabase Publishable / Anon Key</label>
                <input
                  type="password"
                  placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6..."
                  value={supabaseCfg.anonKey}
                  onChange={(e) => setSupabaseCfg({ ...supabaseCfg, anonKey: e.target.value })}
                  className="w-full bg-[#12110e] border border-[#3a3428] rounded px-3 py-1.5 text-[#f4efe6] focus:outline-none focus:border-[#e8a54b]"
                />
              </div>

              <div>
                <label className="text-[#a39886] text-[10px] uppercase block mb-1">Table Name</label>
                <input
                  type="text"
                  placeholder="kiln_batch_audits"
                  value={supabaseCfg.tableName}
                  onChange={(e) => setSupabaseCfg({ ...supabaseCfg, tableName: e.target.value })}
                  className="w-full bg-[#12110e] border border-[#3a3428] rounded px-3 py-1.5 text-[#f4efe6] focus:outline-none focus:border-[#e8a54b]"
                />
              </div>

              <div className="flex items-center gap-2 pt-1">
                <input
                  type="checkbox"
                  id="enableSupabase"
                  checked={supabaseCfg.enabled}
                  onChange={(e) => setSupabaseCfg({ ...supabaseCfg, enabled: e.target.checked })}
                  className="rounded border-[#3a3428] accent-[#e8a54b]"
                />
                <label htmlFor="enableSupabase" className="text-[#f4efe6] text-xs cursor-pointer">
                  Enable active Supabase sync for batch pipeline
                </label>
              </div>

              {supabaseStatusMsg && (
                <div
                  className={`p-2.5 rounded border text-[11px] ${
                    supabaseStatusMsg.ok
                      ? "bg-emerald-950/40 text-emerald-300 border-emerald-800"
                      : "bg-red-950/40 text-red-300 border-red-800"
                  }`}
                >
                  {supabaseStatusMsg.msg}
                </div>
              )}
              <div className="p-3 rounded-lg bg-[#12110e] border border-[#3a3428] flex items-center justify-between">
                <div>
                  <span className="text-[10px] text-[#e8a54b] font-bold block">Direct PostgreSQL DB Wiring</span>
                  <span className="text-[10px] text-[#a39886]">Connect direct Supabase Postgres for project SmartKontrakt</span>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setIsSupabaseModalOpen(false);
                    setIsDbWiringModalOpen(true);
                  }}
                  className="px-2.5 py-1 rounded bg-[#3a2c14] hover:bg-[#4a391c] border border-[#e8a54b]/40 text-[#e8a54b] text-[10px] font-bold transition-colors"
                >
                  Configure DB &rarr;
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-[#3a3428]">
              <button
                type="button"
                onClick={handleTestSupabase}
                disabled={isTestingSupabase || !supabaseCfg.url}
                className="px-3 py-1.5 rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] flex items-center gap-1.5 disabled:opacity-50"
              >
                {isTestingSupabase ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5 text-[#e8a54b]" />}
                <span>Test Connection</span>
              </button>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setIsSupabaseModalOpen(false)}
                  className="px-3 py-1.5 rounded text-[#a39886] hover:text-[#f4efe6]"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleSaveSupabaseConfig}
                  className="px-4 py-1.5 rounded bg-[#e8a54b] text-[#12110e] font-bold"
                >
                  Save Config
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

    </>
  );
}
