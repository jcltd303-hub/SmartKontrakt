import type { BatchItem } from "./audit/address-fetcher";
import { AsyncBatchWriter, type WriterStats } from "./audit/batch-writer.ts";

export type SupabaseConfig = {
  url: string;
  anonKey: string;
  tableName: string;
  enabled: boolean;
};

const STORAGE_KEY = "kiln_supabase_config";

export function getStoredSupabaseConfig(): SupabaseConfig {
  if (typeof window === "undefined") {
    return {
      url: "",
      anonKey: "",
      tableName: "kiln_batch_audits",
      enabled: false,
    };
  }

  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as Partial<SupabaseConfig>;
      if (parsed.anonKey) assertBrowserKey(parsed.anonKey);
      return {
        url: parsed.url || "",
        anonKey: parsed.anonKey || "",
        tableName: parsed.tableName || "kiln_batch_audits",
        enabled: Boolean(parsed.enabled && parsed.url && parsed.anonKey),
      };
    }
  } catch {
    // fallback
  }

  return {
    url: "",
    anonKey: "",
    tableName: "kiln_batch_audits",
    enabled: false,
  };
}

export function saveStoredSupabaseConfig(cfg: SupabaseConfig): void {
  if (typeof window === "undefined") return;
  if (cfg.anonKey) assertBrowserKey(cfg.anonKey);
  if (cfg.enabled) supabaseEndpoint(cfg);
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(cfg));
  } catch {
    // ignore
  }
}

/**
 * Validates Supabase REST endpoint connectivity
 */
export async function testSupabaseConnection(url: string, key: string, table = "kiln_batch_audits"): Promise<{ ok: boolean; message: string }> {
  try {
    const cfg = { url, anonKey: key, tableName: table, enabled: true };
    const endpoint = supabaseEndpoint(cfg);
    const res = await fetch(`${endpoint}?select=id&limit=1`, {
      headers: supabaseHeaders(cfg), signal: AbortSignal.timeout(15_000),
    });
    return res.ok
      ? { ok: true, message: `Connected to Supabase table '${table}'.` }
      : { ok: false, message: `Supabase returned HTTP ${res.status}. Create the table and configure its RLS policies before syncing.` };
  } catch (err) {
    return { ok: false, message: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Upserts a batch item into Supabase via REST PostgREST API
 */
export type SupabaseBatchRow = {
  id: string; address: string; label: string; chain_id: string; status: string;
  risk_score: number | null; findings_count: number; critical_count: number;
  high_count: number; error: string | null; bytecode_size: number | null;
  summary: string | null; completed_at: string;
};

export function toSupabaseBatchRow(item: BatchItem): SupabaseBatchRow {
  return {
    id: item.scanId ?? item.id, address: item.address, label: item.label, chain_id: item.chainId,
    status: item.status, risk_score: item.riskScore ?? null,
    findings_count: item.findingsCount ?? 0, critical_count: item.criticalCount ?? 0,
    high_count: item.highCount ?? 0, error: item.error ?? null,
    bytecode_size: item.bytecodeSize ?? null, summary: item.summary ?? item.report?.summary ?? null,
    completed_at: item.completedAt || new Date().toISOString(),
  };
}

function assertBrowserKey(key: string): void {
  let serviceRole = key.startsWith("sb_secret_");
  try { serviceRole ||= JSON.parse(atob(key.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))).role === "service_role"; } catch { /* Publishable keys are not JWTs. */ }
  if (!key || serviceRole) throw new Error("Browser sync requires a publishable or anon key; keep secret keys on the server.");
}

function supabaseEndpoint(cfg: SupabaseConfig): string {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(cfg.tableName)) throw new Error("Invalid Supabase table name");
  const url = new URL(cfg.url);
  if (url.protocol !== "https:") throw new Error("Supabase URL must use https://");
  assertBrowserKey(cfg.anonKey);
  return `${url.origin}/rest/v1/${cfg.tableName}`;
}

function supabaseHeaders(cfg: SupabaseConfig): Record<string, string> {
  return {
    apikey: cfg.anonKey,
    ...(!cfg.anonKey.startsWith("sb_publishable_") ? { Authorization: `Bearer ${cfg.anonKey}` } : {}),
  };
}

/** One PostgREST request per bounded batch. Errors propagate to the retrying writer. */
export async function saveBatchRowsToSupabase(rows: SupabaseBatchRow[], cfg: SupabaseConfig): Promise<void> {
  if (!rows.length || !cfg.enabled) return;
  if (rows.length > 50) throw new Error("Supabase batch limit is 50 rows");
  const endpoint = supabaseEndpoint(cfg);
  const res = await fetch(`${endpoint}?on_conflict=id`, {
    method: "POST", signal: AbortSignal.timeout(30_000),
    headers: { ...supabaseHeaders(cfg), "Content-Type": "application/json", Prefer: "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify(rows),
  });
  if (!res.ok) throw new Error(`Supabase batch write failed (HTTP ${res.status}). Check the table and RLS policies.`);
}

export async function saveBatchItemsToSupabase(items: BatchItem[], cfg: SupabaseConfig): Promise<void> {
  return saveBatchRowsToSupabase(items.map(toSupabaseBatchRow), cfg);
}

export function createSupabaseBatchWriter(getConfig: () => SupabaseConfig, onChange?: (stats: WriterStats) => void, onAcknowledged?: (rows: SupabaseBatchRow[]) => void): AsyncBatchWriter<SupabaseBatchRow> {
  return new AsyncBatchWriter<SupabaseBatchRow>({
    write: async (rows) => {
      const cfg = getConfig();
      if (!cfg.enabled) throw new Error("Re-enable Supabase sync to write its pending rows.");
      await saveBatchRowsToSupabase(rows, cfg);
      onAcknowledged?.(rows);
    },
    onChange,
  });
}

export async function saveBatchItemToSupabase(item: BatchItem, cfg: SupabaseConfig): Promise<boolean> {
  try { await saveBatchItemsToSupabase([item], cfg); return cfg.enabled; }
  catch { return false; }
}

/**
 * Loads previous batch runs from Supabase to resume processing
 */
export async function loadBatchFromSupabase(cfg: SupabaseConfig): Promise<BatchItem[]> {
  if (!cfg.enabled || !cfg.url || !cfg.anonKey) return [];

  try {
    const res = await fetch(`${supabaseEndpoint(cfg)}?select=id,address,label,chain_id,status,risk_score,findings_count,critical_count,high_count,error,bytecode_size,completed_at&order=completed_at.desc&limit=50`, {
      method: "GET",
      headers: supabaseHeaders(cfg),
      signal: AbortSignal.timeout(15_000),
    });

    if (!res.ok) return [];
    const data = (await res.json()) as Record<string, unknown>[];
    if (!Array.isArray(data)) return [];

    return data.map((row) => ({
      id: String(row.id || row.address),
      address: String(row.address),
      label: String(row.label || row.address),
      chainId: String(row.chain_id || "ethereum"),
      status: (row.status as BatchItem["status"]) || "completed",
      riskScore: typeof row.risk_score === "number" ? row.risk_score : undefined,
      findingsCount: typeof row.findings_count === "number" ? row.findings_count : undefined,
      criticalCount: typeof row.critical_count === "number" ? row.critical_count : undefined,
      highCount: typeof row.high_count === "number" ? row.high_count : undefined,
      error: typeof row.error === "string" ? row.error : undefined,
      completedAt: typeof row.completed_at === "string" ? row.completed_at : undefined,
    }));
  } catch {
    return [];
  }
}
