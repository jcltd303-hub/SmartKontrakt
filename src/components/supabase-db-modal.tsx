import { useState, useEffect } from "react";
import {
  getDatabaseStatusFn,
  testDatabaseConnectionFn,
  saveDatabaseConfigFn,
  disconnectDatabaseFn,
} from "@/lib/scans.functions";
import {
  Database,
  X,
  Check,
  Copy,
  RefreshCw,
  Loader2,
  Key,
  ShieldCheck,
  AlertTriangle,
  Eye,
  EyeOff,
} from "lucide-react";

interface SupabaseDbModalProps {
  isOpen: boolean;
  onClose: () => void;
  onDatabaseChanged?: () => void;
}

export function SupabaseDbModal({ isOpen, onClose, onDatabaseChanged }: SupabaseDbModalProps) {
  const [projectName, setProjectName] = useState<string>("SmartKontrakt");
  const [projectRef, setProjectRef] = useState<string>("aadhpvhpjzkkeydzxxhk");
  const [host, setHost] = useState<string>("aws-1-us-west-2.pooler.supabase.com");
  const [user, setUser] = useState<string>("postgres.aadhpvhpjzkkeydzxxhk");
  const [port, setPort] = useState<number>(6543);
  const [database, setDatabase] = useState<string>("postgres");
  const [password, setPassword] = useState<string>("hX*+JxfrR4Q&3BB");
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [mode, setMode] = useState<"pooler" | "direct" | "custom">("pooler");
  const [region, setRegion] = useState<string>("us-west-2");
  const [customUrl, setCustomUrl] = useState<string>("");
  const [isActive, setIsActive] = useState<boolean>(false);
  const [activeUrlMasked, setActiveUrlMasked] = useState<string>("");
  const [copied, setCopied] = useState<boolean>(false);

  const [isTesting, setIsTesting] = useState<boolean>(false);
  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [statusMsg, setStatusMsg] = useState<{ ok: boolean; msg: string; details?: string } | null>(null);

  const fetchStatus = async () => {
    try {
      const res = await getDatabaseStatusFn();
      if (res?.config) {
        setProjectName(res.config.projectName || "SmartKontrakt");
        setProjectRef(res.config.projectRef || "aadhpvhpjzkkeydzxxhk");
        if (res.config.host) setHost(res.config.host);
        if (res.config.user) setUser(res.config.user);
        if (res.config.port) setPort(res.config.port);
        if (res.config.database) setDatabase(res.config.database);
        setMode((res.config.mode as "pooler" | "direct" | "custom") || "pooler");
        setRegion(res.config.region || "us-west-2");
        setCustomUrl(res.config.customUrl || "");
        setIsActive(Boolean(res.config.active));
      }
      if (res?.activeUrlMasked) {
        setActiveUrlMasked(res.activeUrlMasked);
      }
    } catch (err) {
      console.warn("[supabase-modal] Failed to fetch database status:", err);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchStatus();
      setStatusMsg(null);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  // Clean ref: remove protocol, domain suffix
  const cleanRef = projectRef.trim().replace(/^https?:\/\//i, "").replace(/\.supabase\.co.*$/i, "").replace(/\/.*$/, "");

  // Properly URL-encoded password for PostgreSQL URIs
  const encPw = encodeURIComponent(password);

  const previewConnectionUrl =
    mode === "custom"
      ? customUrl
      : host && user
      ? `postgresql://${user}:${encPw}@${host}:${port}/${database}`
      : mode === "direct"
      ? cleanRef
        ? `postgresql://postgres:${encPw}@db.${cleanRef}.supabase.co:5432/postgres`
        : `postgresql://postgres:${encPw}@db.[YOUR-PROJECT-REF].supabase.co:5432/postgres`
      : cleanRef
      ? `postgresql://postgres.${cleanRef}:${encPw}@aws-0-${region}.pooler.supabase.com:6543/postgres`
      : `postgresql://postgres.[YOUR-PROJECT-REF]:${encPw}@aws-0-${region}.pooler.supabase.com:6543/postgres`;

  const copyConnectionUrl = () => {
    navigator.clipboard.writeText(previewConnectionUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleTestConnection = async () => {
    setIsTesting(true);
    setStatusMsg(null);
    try {
      const res = await testDatabaseConnectionFn({
        data: {
          projectRef: cleanRef,
          host: mode === "pooler" ? host : undefined,
          user: mode === "pooler" ? user : undefined,
          port: mode === "pooler" ? port : undefined,
          database: mode === "pooler" ? database : undefined,
          password,
          mode,
          region,
          url: mode === "custom" ? customUrl : undefined,
        },
      });

      if (res.ok) {
        setStatusMsg({
          ok: true,
          msg: res.message,
          details: `Latency: ${res.latencyMs}ms | DB: ${res.database || "postgres"} | Version: ${res.version?.slice(0, 45) || "PostgreSQL"}`,
        });
      } else {
        setStatusMsg({
          ok: false,
          msg: res.message,
        });
      }
    } catch (err: unknown) {
      setStatusMsg({
        ok: false,
        msg: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setIsTesting(false);
    }
  };

  const handleConnectAndSave = async () => {
    if (!cleanRef && !host && mode !== "custom") {
      setStatusMsg({
        ok: false,
        msg: "Please enter your Supabase Project Reference ID or host.",
      });
      return;
    }

    setIsSaving(true);
    setStatusMsg(null);
    try {
      const res = await saveDatabaseConfigFn({
        data: {
          projectName,
          projectRef: cleanRef,
          host: mode === "pooler" ? host : undefined,
          user: mode === "pooler" ? user : undefined,
          port: mode === "pooler" ? port : undefined,
          database: mode === "pooler" ? database : undefined,
          password,
          mode,
          region,
          customUrl: mode === "custom" ? customUrl : undefined,
          active: true,
        },
      });

      if (res.ok) {
        setIsActive(true);
        setStatusMsg({
          ok: true,
          msg: `Connected to Supabase! ${res.message}`,
          details: `All contract audits, payloads, AST inventories, and RAG knowledge chunks will now persist to Supabase.`,
        });
        onDatabaseChanged?.();
      } else {
        setStatusMsg({ ok: false, msg: res.message });
      }
    } catch (err: unknown) {
      setStatusMsg({
        ok: false,
        msg: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setIsSaving(false);
    }
  };

  const handleSwitchToPglite = async () => {
    setIsSaving(true);
    try {
      await disconnectDatabaseFn();
      setIsActive(false);
      setActiveUrlMasked("");
      setStatusMsg({
        ok: true,
        msg: "Switched back to local embedded PGLite database.",
      });
      onDatabaseChanged?.();
    } catch (err: unknown) {
      setStatusMsg({
        ok: false,
        msg: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-[#1c1a16] border border-[#3a3428] rounded-2xl max-w-xl w-full p-6 shadow-2xl flex flex-col gap-5 text-xs font-mono my-8 animate-fadeIn">
        {/* Header */}
        <div className="flex items-center justify-between pb-3 border-b border-[#3a3428]">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-[#e8a54b]/10 border border-[#e8a54b]/30">
              <Database className="w-5 h-5 text-[#e8a54b]" />
            </div>
            <div>
              <h3 className="font-bold text-sm text-[#f4efe6] flex items-center gap-2">
                Supabase Database Wiring
                <span className="px-2 py-0.5 rounded text-[10px] bg-[#3a2c14] text-[#e8a54b] border border-[#e8a54b]/30">
                  {projectName}
                </span>
              </h3>
              <p className="text-[11px] text-[#a39886] font-sans">
                Wire durable PostgreSQL archive storage & RAG indexing to your Supabase project
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-[#a39886] hover:text-[#f4efe6] p-1 rounded-md transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Current Active Engine Badge */}
        <div className="flex items-center justify-between p-3 rounded-xl bg-[#12110e] border border-[#3a3428]">
          <div className="flex items-center gap-2">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                isActive ? "bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.6)] animate-pulse" : "bg-amber-400"
              }`}
            />
            <div>
              <div className="text-[10px] text-[#746c60] uppercase tracking-wider">Active Storage Engine</div>
              <div className="text-xs font-bold text-[#f4efe6] mt-0.5 flex items-center gap-1.5">
                {isActive ? (
                  <>
                    <span className="text-emerald-400">Supabase PostgreSQL (Live)</span>
                    <span className="text-[10px] text-[#a39886] font-normal">
                      {activeUrlMasked ? `• ${activeUrlMasked}` : ""}
                    </span>
                  </>
                ) : (
                  <>
                    <span className="text-[#e8a54b]">Local PGLite (Embedded WASM)</span>
                    <span className="text-[10px] text-[#a39886] font-normal">• In-memory dev fallback</span>
                  </>
                )}
              </div>
            </div>
          </div>

          {isActive && (
            <button
              onClick={handleSwitchToPglite}
              disabled={isSaving}
              className="px-2.5 py-1 text-[11px] rounded bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#a39886] hover:text-[#f4efe6] transition-colors"
            >
              Disconnect
            </button>
          )}
        </div>

        {/* Configuration Form */}
        <div className="flex flex-col gap-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {/* Project Name */}
            <div>
              <label className="text-[#a39886] text-[10px] uppercase block mb-1">Project Name</label>
              <input
                type="text"
                value={projectName}
                onChange={(e) => setProjectName(e.target.value)}
                placeholder="SmartKontrakt"
                className="w-full bg-[#12110e] border border-[#3a3428] rounded px-3 py-1.5 text-[#f4efe6] focus:outline-none focus:border-[#e8a54b]"
              />
            </div>

            {/* Region */}
            <div>
              <label className="text-[#a39886] text-[10px] uppercase block mb-1">Supabase Region</label>
              <select
                value={region}
                onChange={(e) => setRegion(e.target.value)}
                className="w-full bg-[#12110e] border border-[#3a3428] rounded px-3 py-1.5 text-[#f4efe6] focus:outline-none focus:border-[#e8a54b]"
              >
                <option value="us-east-1">AWS US East (N. Virginia) us-east-1</option>
                <option value="us-west-1">AWS US West (N. California) us-west-1</option>
                <option value="eu-central-1">AWS EU Central (Frankfurt) eu-central-1</option>
                <option value="eu-west-1">AWS EU West (Ireland) eu-west-1</option>
                <option value="ap-southeast-1">AWS Asia (Singapore) ap-southeast-1</option>
              </select>
            </div>
          </div>

          {/* Database Password */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-[#a39886] text-[10px] uppercase flex items-center gap-1.5">
                <Key className="w-3 h-3 text-[#e8a54b]" />
                <span>Database Password</span>
              </label>
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="text-[10px] text-[#e8a54b] hover:underline flex items-center gap-1"
              >
                {showPassword ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                <span>{showPassword ? "Hide" : "Show"}</span>
              </button>
            </div>
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Database password"
                className="w-full bg-[#12110e] border border-[#3a3428] rounded px-3 py-1.5 text-[#f4efe6] focus:outline-none focus:border-[#e8a54b]"
              />
            </div>
            <p className="text-[10px] text-[#746c60] mt-1 font-sans">
              Configured with your database password (contains special characters automatically encoded for URI safety).
            </p>
          </div>

          {/* Supabase Project Reference */}
          <div>
            <label className="text-[#a39886] text-[10px] uppercase block mb-1">
              Supabase Project Reference ID or URL
            </label>
            <input
              type="text"
              value={projectRef}
              onChange={(e) => setProjectRef(e.target.value)}
              placeholder="e.g. abcdefghijklmnopqrst or https://abcdefghijklmnopqrst.supabase.co"
              className="w-full bg-[#12110e] border border-[#3a3428] rounded px-3 py-1.5 text-[#f4efe6] focus:outline-none focus:border-[#e8a54b]"
            />
            <p className="text-[10px] text-[#a39886] mt-1 font-sans">
              Find your Project Reference ID in your Supabase dashboard URL:{" "}
              <code className="text-[#e8a54b]">supabase.com/dashboard/project/&lt;your-ref&gt;</code> or under Project Settings &rarr; General.
            </p>
          </div>

          {/* Connection Mode Selection */}
          <div>
            <label className="text-[#a39886] text-[10px] uppercase block mb-1.5">Connection Protocol</label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => setMode("pooler")}
                className={`p-2 rounded-lg border text-left flex flex-col gap-0.5 transition-all ${
                  mode === "pooler"
                    ? "bg-[#3a2c14] border-[#e8a54b] text-[#f4efe6]"
                    : "bg-[#12110e] border-[#3a3428] text-[#a39886] hover:border-[#746c60]"
                }`}
              >
                <div className="font-bold text-[11px] flex items-center justify-between">
                  <span>Pooler (Port 6543)</span>
                  {mode === "pooler" && <Check className="w-3 h-3 text-[#e8a54b]" />}
                </div>
                <div className="text-[9px] text-[#a39886] font-sans">Supavisor Transaction Pooler (Serverless)</div>
              </button>

              <button
                type="button"
                onClick={() => setMode("direct")}
                className={`p-2 rounded-lg border text-left flex flex-col gap-0.5 transition-all ${
                  mode === "direct"
                    ? "bg-[#3a2c14] border-[#e8a54b] text-[#f4efe6]"
                    : "bg-[#12110e] border-[#3a3428] text-[#a39886] hover:border-[#746c60]"
                }`}
              >
                <div className="font-bold text-[11px] flex items-center justify-between">
                  <span>Direct (Port 5432)</span>
                  {mode === "direct" && <Check className="w-3 h-3 text-[#e8a54b]" />}
                </div>
                <div className="text-[9px] text-[#a39886] font-sans">Direct PostgreSQL port connection</div>
              </button>

              <button
                type="button"
                onClick={() => setMode("custom")}
                className={`p-2 rounded-lg border text-left flex flex-col gap-0.5 transition-all ${
                  mode === "custom"
                    ? "bg-[#3a2c14] border-[#e8a54b] text-[#f4efe6]"
                    : "bg-[#12110e] border-[#3a3428] text-[#a39886] hover:border-[#746c60]"
                }`}
              >
                <div className="font-bold text-[11px] flex items-center justify-between">
                  <span>Custom URL</span>
                  {mode === "custom" && <Check className="w-3 h-3 text-[#e8a54b]" />}
                </div>
                <div className="text-[9px] text-[#a39886] font-sans">Full raw DATABASE_URL string</div>
              </button>
            </div>
          </div>

          {mode === "custom" && (
            <div>
              <label className="text-[#a39886] text-[10px] uppercase block mb-1">Raw DATABASE_URL</label>
              <input
                type="text"
                value={customUrl}
                onChange={(e) => setCustomUrl(e.target.value)}
                placeholder="postgresql://postgres:password@host:port/postgres"
                className="w-full bg-[#12110e] border border-[#3a3428] rounded px-3 py-1.5 text-[#f4efe6] focus:outline-none focus:border-[#e8a54b]"
              />
            </div>
          )}

          {/* Connection String Preview */}
          <div className="bg-[#12110e] p-3 rounded-xl border border-[#3a3428] flex flex-col gap-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-[#746c60] uppercase">Generated Connection URI</span>
              <button
                type="button"
                onClick={copyConnectionUrl}
                className="text-[10px] text-[#e8a54b] hover:text-[#f4efe6] flex items-center gap-1 transition-colors"
              >
                {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                <span>{copied ? "Copied URI" : "Copy URI"}</span>
              </button>
            </div>
            <div className="text-[11px] text-[#a39886] break-all font-mono select-all bg-[#1c1a16] p-2 rounded border border-[#3a3428]/60">
              {previewConnectionUrl}
            </div>
          </div>

          {/* Status Message */}
          {statusMsg && (
            <div
              className={`p-3 rounded-xl border text-[11px] flex flex-col gap-1 animate-fadeIn ${
                statusMsg.ok
                  ? "bg-emerald-950/50 text-emerald-300 border-emerald-800"
                  : "bg-red-950/50 text-red-300 border-red-800"
              }`}
            >
              <div className="font-bold flex items-center gap-1.5">
                {statusMsg.ok ? <ShieldCheck className="w-4 h-4 text-emerald-400" /> : <AlertTriangle className="w-4 h-4 text-red-400" />}
                <span>{statusMsg.msg}</span>
              </div>
              {statusMsg.details && (
                <div className="text-[10px] opacity-80 pl-5 font-sans">
                  {statusMsg.details}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between pt-3 border-t border-[#3a3428]">
          <button
            type="button"
            onClick={handleTestConnection}
            disabled={isTesting || (!cleanRef && mode !== "custom")}
            className="px-3 py-1.5 rounded-lg bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] flex items-center gap-1.5 disabled:opacity-50 transition-colors"
          >
            {isTesting ? <Loader2 className="w-3.5 h-3.5 animate-spin text-[#e8a54b]" /> : <RefreshCw className="w-3.5 h-3.5 text-[#e8a54b]" />}
            <span>Test Connection</span>
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded-lg text-[#a39886] hover:text-[#f4efe6] transition-colors"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleConnectAndSave}
              disabled={isSaving || (!cleanRef && mode !== "custom")}
              className="px-4 py-1.5 rounded-lg bg-gradient-to-r from-[#e8a54b] to-[#d97706] hover:brightness-110 text-[#12110e] font-bold shadow-md shadow-[#e8a54b]/20 flex items-center gap-1.5 disabled:opacity-50 transition-all active:scale-95"
            >
              {isSaving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Database className="w-3.5 h-3.5" />}
              <span>Connect & Run Migrations</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
