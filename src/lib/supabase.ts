import type { BatchItem } from "./audit/address-fetcher";

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
  const cleanUrl = url.replace(/\/+$/, "");
  if (!cleanUrl.startsWith("http")) {
    return { ok: false, message: "URL must start with https://" };
  }
  if (!key) {
    return { ok: false, message: "Missing Supabase Anon / Service Key" };
  }

  try {
    const res = await fetch(`${cleanUrl}/rest/v1/${table}?limit=1`, {
      method: "GET",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
      },
    });

    if (res.ok) {
      return { ok: true, message: `Connected to Supabase table '${table}'. Ready to sync.` };
    }

    if (res.status === 404 || res.status === 400) {
      // Table might not exist yet, check base API
      const rootRes = await fetch(`${cleanUrl}/rest/v1/`, {
        headers: { apikey: key, Authorization: `Bearer ${key}` },
      });
      if (rootRes.ok) {
        return {
          ok: true,
          message: `Connected to Supabase API. (Note: table '${table}' will be queried/created on save).`,
        };
      }
    }

    return { ok: false, message: `Supabase returned HTTP ${res.status}: ${res.statusText}` };
  } catch (err) {
    return { ok: false, message: `Connection failed: ${err instanceof Error ? err.message : String(err)}` };
  }
}

/**
 * Upserts a batch item into Supabase via REST PostgREST API
 */
export async function saveBatchItemToSupabase(item: BatchItem, cfg: SupabaseConfig): Promise<boolean> {
  if (!cfg.enabled || !cfg.url || !cfg.anonKey) return false;

  const cleanUrl = cfg.url.replace(/\/+$/, "");
  const payload = {
    id: item.id,
    address: item.address,
    label: item.label,
    chain_id: item.chainId,
    status: item.status,
    risk_score: item.riskScore ?? null,
    findings_count: item.findingsCount ?? 0,
    critical_count: item.criticalCount ?? 0,
    high_count: item.highCount ?? 0,
    error: item.error ?? null,
    bytecode_size: item.bytecodeSize ?? null,
    summary: item.report?.summary ?? null,
    completed_at: item.completedAt || new Date().toISOString(),
  };

  try {
    const res = await fetch(`${cleanUrl}/rest/v1/${cfg.tableName}`, {
      method: "POST",
      headers: {
        apikey: cfg.anonKey,
        Authorization: `Bearer ${cfg.anonKey}`,
        "Content-Type": "application/json",
        Prefer: "resolution=merge-duplicates",
      },
      body: JSON.stringify(payload),
    });

    return res.ok;
  } catch (err) {
    console.warn("[Kiln] Supabase upsert error:", err);
    return false;
  }
}

/**
 * Loads previous batch runs from Supabase to resume processing
 */
export async function loadBatchFromSupabase(cfg: SupabaseConfig): Promise<BatchItem[]> {
  if (!cfg.enabled || !cfg.url || !cfg.anonKey) return [];

  const cleanUrl = cfg.url.replace(/\/+$/, "");
  try {
    const res = await fetch(`${cleanUrl}/rest/v1/${cfg.tableName}?select=*&order=completed_at.desc&limit=50`, {
      method: "GET",
      headers: {
        apikey: cfg.anonKey,
        Authorization: `Bearer ${cfg.anonKey}`,
      },
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
