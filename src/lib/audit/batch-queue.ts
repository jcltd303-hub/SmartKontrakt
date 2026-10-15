import type { BatchItem } from "./address-fetcher.ts";

export function checkpointItem(item: BatchItem): BatchItem {
  const { rawBody: _body, report: _report, ...lean } = item;
  return lean;
}

export function restoreItem(item: BatchItem): BatchItem {
  const lean = checkpointItem(item);
  if (lean.status === "fetching" || lean.status === "analyzing" ||
    (lean.status === "completed" && !lean.persisted)) lean.status = "pending";
  return lean;
}

export function retargetBatchQueue(items: BatchItem[], chainId: string): BatchItem[] {
  return items.map((item, index) => ({
    id: `${chainId}:${item.address}:${index}`, address: item.address,
    label: item.label, chainId, status: "pending",
  }));
}

/** A run owns its array. Per-address updates change one slot and counters in O(1). */
export class BatchQueue {
  items: BatchItem[] = [];
  summary = { completed: 0, failed: 0, pending: 0, totalCrit: 0, totalHigh: 0, unsynced: 0 };
  constructor(items: BatchItem[]) { this.replace(items); }
  private count(item: BatchItem, sign: number) {
    if (item.status === "completed") this.summary.completed += sign;
    else if (item.status === "failed") this.summary.failed += sign;
    else if (item.status !== "skipped") this.summary.pending += sign;
    this.summary.totalCrit += sign * (item.criticalCount ?? 0);
    this.summary.totalHigh += sign * (item.highCount ?? 0);
    if (item.status === "completed" && item.supabaseSynced === false) this.summary.unsynced += sign;
  }
  replace(items: BatchItem[]): void {
    this.items = items.map(checkpointItem);
    this.summary = { completed: 0, failed: 0, pending: 0, totalCrit: 0, totalHigh: 0, unsynced: 0 };
    for (const item of this.items) this.count(item, 1);
  }
  update(index: number, patch: Partial<BatchItem>): void {
    const previous = this.items[index];
    if (!previous) return;
    this.count(previous, -1);
    this.items[index] = checkpointItem({ ...previous, ...patch });
    this.count(this.items[index], 1);
  }
}
