import { createServerFn } from "@tanstack/react-start";

const MAX_CHARS = 80_000;

export const listScans = createServerFn({ method: "GET" }).handler(async () => {
  const { listScanSummaries } = await import("./audit/persist.server");
  return listScanSummaries();
});

export const getScan = createServerFn({ method: "GET" })
  .validator((input: unknown) => {
    if (!input || typeof input !== "object" || !("id" in input) || typeof input.id !== "string") {
      throw new Error("Missing audit id");
    }
    if (!/^[0-9a-f-]{36}$/i.test(input.id)) throw new Error("Unknown audit id");
    return { id: input.id };
  })
  .handler(async ({ data }) => {
    const { loadScan } = await import("./audit/persist.server");
    const scan = await loadScan(data.id);
    if (!scan) throw new Error("That audit is no longer in the archive.");
    return scan;
  });

export const analyzeContract = createServerFn({ method: "POST" })
  .validator((input: unknown) => {
    if (!input || typeof input !== "object") throw new Error("Missing contract");
    const body = "body" in input && typeof input.body === "string" ? input.body.replaceAll("\0", "") : "";
    const labelRaw = "label" in input && typeof input.label === "string" ? input.label : "";
    if (!body.trim()) throw new Error("Paste Solidity source or runtime bytecode first.");
    if (body.length > MAX_CHARS) throw new Error("Keep the paste under 80,000 characters.");
    const label = labelRaw.replace(/\s+/g, " ").trim().slice(0, 80) || "Untitled contract";
    return { body, label };
  })
  .handler(async ({ data }) => {
    const { runAndStore } = await import("./audit/persist.server");
    return runAndStore(data);
  });

export const removeScan = createServerFn({ method: "POST" })
  .validator((input: unknown) => {
    if (!input || typeof input !== "object" || !("id" in input) || typeof input.id !== "string") {
      throw new Error("Missing audit id");
    }
    if (!/^[0-9a-f-]{36}$/i.test(input.id)) throw new Error("Unknown audit id");
    return { id: input.id };
  })
  .handler(async ({ data }) => {
    const { deleteScan } = await import("./audit/persist.server");
    await deleteScan(data.id);
    return { ok: true as const };
  });
