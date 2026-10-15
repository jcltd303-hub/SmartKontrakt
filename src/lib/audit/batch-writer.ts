export type WriterStats = {
  pendingCount: number;
  pendingBytes: number;
  totalFlushed: number;
  isFlushing: boolean;
  lastError: string | null;
};

export const serializedBytes = (value: unknown): number =>
  new TextEncoder().encode(JSON.stringify(value)).byteLength + 1;

type Options<T> = {
  write: (batch: T[]) => Promise<void>;
  sizeOf?: (value: T) => number;
  batchSize?: number;
  maxBatchBytes?: number;
  maxBufferedItems?: number;
  maxBufferedBytes?: number;
  flushIntervalMs?: number;
  maxRetries?: number;
  retryDelayMs?: number;
  onChange?: (stats: WriterStats) => void;
};

/** One serialized writer. Producers await capacity instead of retaining an unbounded backlog. */
export class AsyncBatchWriter<T> {
  private queue: { value: T; bytes: number }[] = [];
  private pendingBytes = 0;
  private flushed = 0;
  private error: string | null = null;
  private active: Promise<void> | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private closed = false;
  private options: Required<Omit<Options<T>, "onChange">> & Pick<Options<T>, "onChange">;

  constructor(options: Options<T>) {
    this.options = {
      sizeOf: serializedBytes, batchSize: 50, maxBatchBytes: 1_500_000,
      maxBufferedItems: 100, maxBufferedBytes: 8_000_000,
      flushIntervalMs: 2500, maxRetries: 3, retryDelayMs: 250,
      ...options,
    };
  }

  get stats(): WriterStats {
    return {
      pendingCount: this.queue.length, pendingBytes: this.pendingBytes,
      totalFlushed: this.flushed, isFlushing: this.active !== null, lastError: this.error,
    };
  }

  private publish() { this.options.onChange?.(this.stats); }

  async enqueue(value: T): Promise<void> {
    if (this.closed) throw new Error("Batch writer is closed");
    const bytes = this.options.sizeOf(value);
    if (bytes > Math.min(this.options.maxBatchBytes, this.options.maxBufferedBytes)) {
      throw new Error("Audit dossier exceeds the batch payload limit; save it individually.");
    }
    // Include the in-flight batch in both limits. A failed write remains queued.
    while (this.error || this.queue.length >= this.options.maxBufferedItems ||
      this.pendingBytes + bytes > this.options.maxBufferedBytes) {
      await this.flush();
      if (this.closed) throw new Error("Batch writer is closed");
    }
    this.queue.push({ value, bytes });
    this.pendingBytes += bytes;
    this.publish();
    if (this.queue.length >= this.options.batchSize || this.pendingBytes >= this.options.maxBatchBytes) {
      void this.flush().catch(() => undefined);
    } else if (!this.timer) {
      // A maximum age, not a debounce that can postpone low-volume writes forever.
      this.timer = setTimeout(() => { void this.flush().catch(() => undefined); }, this.options.flushIntervalMs);
    }
  }

  flush(): Promise<void> {
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
    if (this.active) return this.active;
    if (!this.queue.length) return Promise.resolve();
    this.error = null;
    this.active = Promise.resolve().then(async () => {
      this.publish();
      while (this.queue.length) {
        let count = 0;
        let bytes = 0;
        while (count < Math.min(this.queue.length, this.options.batchSize) &&
          bytes + this.queue[count].bytes <= this.options.maxBatchBytes) {
          bytes += this.queue[count++].bytes;
        }
        const batch = this.queue.slice(0, count).map((entry) => entry.value);
        for (let attempt = 0; ; attempt++) {
          try { await this.options.write(batch); break; }
          catch (err) {
            if (attempt >= this.options.maxRetries) throw err;
            await new Promise<void>((resolve) => setTimeout(resolve,
              Math.min(10_000, this.options.retryDelayMs * 2 ** attempt)));
          }
        }
        this.queue.splice(0, count);
        this.pendingBytes -= bytes;
        this.flushed += count;
        this.publish();
      }
    }).catch((err: unknown) => {
      this.error = err instanceof Error ? err.message : String(err);
      throw err;
    }).finally(() => { this.active = null; this.publish(); });
    return this.active;
  }

  dispose(): void {
    this.closed = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }
}

/** Bounds both entry count and retained source/report bytes; keys include chain. */
export class ByteLruCache<T> {
  private entries = new Map<string, { value: T; bytes: number }>();
  private retainedBytes = 0;
  private maxEntries: number;
  private maxBytes: number;
  private sizeOf: (value: T) => number;
  constructor(maxEntries: number, maxBytes: number, sizeOf: (value: T) => number = serializedBytes) {
    this.maxEntries = maxEntries; this.maxBytes = maxBytes; this.sizeOf = sizeOf;
  }
  get size() { return this.entries.size; }
  get bytes() { return this.retainedBytes; }
  get(key: string): T | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    this.entries.delete(key); this.entries.set(key, entry);
    return entry.value;
  }
  set(key: string, value: T): void {
    const previous = this.entries.get(key);
    if (previous) { this.retainedBytes -= previous.bytes; this.entries.delete(key); }
    const bytes = this.sizeOf(value);
    if (bytes > this.maxBytes) return;
    this.entries.set(key, { value, bytes }); this.retainedBytes += bytes;
    while (this.entries.size > this.maxEntries || this.retainedBytes > this.maxBytes) {
      const oldest = this.entries.keys().next().value!;
      this.retainedBytes -= this.entries.get(oldest)!.bytes;
      this.entries.delete(oldest);
    }
  }
  clear(): void { this.entries.clear(); this.retainedBytes = 0; }
}
