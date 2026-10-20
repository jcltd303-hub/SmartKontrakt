import type { Finding } from "@/lib/audit/types";

export function getRiskColor(score: number) {
  if (score >= 80)
    return { text: "text-red-400", bg: "bg-red-500", ring: "ring-red-500/30", label: "CRITICAL" };
  if (score >= 50)
    return {
      text: "text-amber-400",
      bg: "bg-amber-500",
      ring: "ring-amber-500/30",
      label: "HIGH RISK",
    };
  if (score >= 20)
    return {
      text: "text-yellow-400",
      bg: "bg-yellow-500",
      ring: "ring-yellow-500/30",
      label: "MEDIUM RISK",
    };
  if (score > 0)
    return {
      text: "text-blue-400",
      bg: "bg-blue-500",
      ring: "ring-blue-500/30",
      label: "LOW RISK",
    };
  return {
    text: "text-emerald-400",
    bg: "bg-emerald-500",
    ring: "ring-emerald-500/30",
    label: "CLEAN / NO HITS",
  };
}

export function filterFindings(
  findings: readonly Finding[],
  severityFilter: string,
  findingSearch: string,
): Finding[] {
  return findings.filter((f) => {
    const matchesSeverity = severityFilter === "all" || f.severity === severityFilter;
    const q = findingSearch.toLowerCase().trim();
    const matchesSearch =
      !q ||
      f.title.toLowerCase().includes(q) ||
      f.detector.toLowerCase().includes(q) ||
      (f.swc && f.swc.toLowerCase().includes(q)) ||
      (f.locationFn && f.locationFn.toLowerCase().includes(q)) ||
      f.summary.toLowerCase().includes(q);
    return matchesSeverity && matchesSearch;
  });
}
