import { BatchQueue, checkpointItem, restoreItem } from "./batch-queue.ts";
import type { BatchItem } from "./address-fetcher.ts";

let database: Promise<IDBDatabase> | undefined;
function openCheckpoint(): Promise<IDBDatabase> {
  database ??= new Promise<IDBDatabase>((resolve, reject) => {
    if (typeof indexedDB === "undefined") { reject(new Error("IndexedDB is unavailable")); return; }
    const request = indexedDB.open("kiln-batch-checkpoint", 2);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains("queue")) request.result.createObjectStore("queue");
      if (!request.result.objectStoreNames.contains("meta")) request.result.createObjectStore("meta");
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  }).catch((err) => { database = undefined; throw err; });
  return database;
}

export async function loadBatchCheckpoint(): Promise<BatchItem[] | null> {
  const db = await openCheckpoint();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(["queue", "meta"]);
    const rows = tx.objectStore("queue").getAll();
    const initialized = tx.objectStore("meta").get("initialized");
    tx.oncomplete = () => resolve(rows.result.length || initialized.result ? rows.result.map(restoreItem) : null);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error ?? new Error("Checkpoint read was interrupted"));
  });
}

/** Whole-run writes happen only on import; processing checkpoints only changed slots. */
export async function saveBatchCheckpoint(updates: [number, BatchItem][], replace = false): Promise<void> {
  const db = await openCheckpoint();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(["queue", "meta"], "readwrite");
    const store = tx.objectStore("queue");
    if (replace) store.clear();
    tx.objectStore("meta").put(true, "initialized");
    for (const [index, item] of updates) store.put(checkpointItem(item), index);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error ?? new Error("Checkpoint was interrupted"));
  });
}

/** Restore once, or establish the entire initial queue before incremental writes. */
export async function initializeBatchQueue(queue: BatchQueue, options: {
  loadLegacy?: () => BatchItem[] | null;
  isCurrent?: () => boolean;
} = {}): Promise<boolean> {
  const initial = queue.items;
  const saved = await loadBatchCheckpoint().catch(() => null);
  if (queue.items !== initial || options.isCurrent?.() === false) return false;
  const items = saved ?? options.loadLegacy?.() ?? initial;
  queue.replace(items.map(restoreItem));
  if (saved === null) await saveBatchCheckpoint(queue.items.map((item, index) => [index, item]), true);
  return true;
}
