import { SAMPLES } from "@/lib/audit/samples";
import type { Severity } from "@/lib/audit/types";
import type { AuditorDisposition } from "@/lib/audit/adjudication";

/** Auditor disposition (migration 0015) display config, shared by the
 *  workbench findings tab and the PoC Audits page. */
export const DISPOSITION_CONFIG: Record<
  AuditorDisposition,
  { label: string; badge: string }
> = {
  confirmed: {
    label: "Confirmed real",
    badge: "bg-emerald-950 text-emerald-300 border-emerald-800",
  },
  false_positive: {
    label: "False positive",
    badge: "bg-purple-950 text-purple-300 border-purple-800",
  },
  needs_more_info: {
    label: "Needs info",
    badge: "bg-amber-950 text-amber-300 border-amber-800",
  },
};

export const DISPOSITION_ORDER: readonly AuditorDisposition[] = [
  "confirmed",
  "false_positive",
  "needs_more_info",
] as const;
export const SEVERITY_CONFIG: Record<
  Severity,
  { label: string; badge: string; bg: string; border: string; text: string; dot: string }
> = {
  critical: {
    label: "Critical",
    badge: "bg-red-950/80 text-red-400 border-red-700/60",
    bg: "bg-red-950/20",
    border: "border-red-900/40",
    text: "text-red-400",
    dot: "bg-red-500",
  },
  high: {
    label: "High",
    badge: "bg-amber-950/80 text-amber-400 border-amber-700/60",
    bg: "bg-amber-950/20",
    border: "border-amber-900/40",
    text: "text-amber-400",
    dot: "bg-amber-500",
  },
  medium: {
    label: "Medium",
    badge: "bg-yellow-950/80 text-yellow-300 border-yellow-700/60",
    bg: "bg-yellow-950/20",
    border: "border-yellow-900/40",
    text: "text-yellow-400",
    dot: "bg-yellow-500",
  },
  low: {
    label: "Low",
    badge: "bg-blue-950/80 text-blue-300 border-blue-700/60",
    bg: "bg-blue-950/20",
    border: "border-blue-900/40",
    text: "text-blue-400",
    dot: "bg-blue-500",
  },
  info: {
    label: "Info",
    badge: "bg-stone-900 text-stone-300 border-stone-700/60",
    bg: "bg-stone-900/30",
    border: "border-stone-800",
    text: "text-stone-400",
    dot: "bg-stone-500",
  },
};

export const defaultSample = SAMPLES[0] ?? {
  id: "relic",
  label: "RelicVault",
  blurb: "",
  body: "",
};

export function formatDate(iso: string): string {
  if (!iso) return "Recent";
  return iso.length >= 10 ? iso.slice(0, 10) : iso;
}
