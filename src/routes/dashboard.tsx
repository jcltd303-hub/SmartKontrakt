import { createFileRoute, Link } from "@tanstack/react-router";
import { VulnerabilityDashboard } from "@/components/vulnerability-dashboard";
import { getDatabaseStatusFn, listScans } from "@/lib/scans.functions";
import { ArrowLeft, ShieldAlert } from "lucide-react";

export const Route = createFileRoute("/dashboard")({
  loader: async () => {
    let scans: Awaited<ReturnType<typeof listScans>> = [];
    try {
      scans = await listScans();
    } catch {
      scans = [];
    }

    // One line of storage diagnosis, rendered server-side. It answers "is this
    // deployment actually on Supabase, and if not, why not" without opening a
    // dialog — which also makes it readable by a plain page fetch.
    let storage: { ok: boolean; label: string; detail: string } | null = null;
    try {
      const status = await getDatabaseStatusFn();
      const info = status.dbInfo;
      storage = {
        ok: info.source === "supabase",
        label: info.source === "supabase" ? "Supabase PostgreSQL" : "embedded local database (ephemeral)",
        detail: info.message,
      };
    } catch (err) {
      storage = { ok: false, label: "unknown", detail: err instanceof Error ? err.message : String(err) };
    }

    return { scans, storage };
  },
  component: DashboardPage,
});

function DashboardPage() {
  const { scans, storage } = Route.useLoaderData();
  return (
    <div className="min-h-screen bg-[#12110e] text-[#f4efe6] p-6 sm:p-8 flex flex-col gap-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between border-b border-[#3a3428] pb-4">
        <div className="flex items-center gap-3">
          <Link
            to="/"
            className="p-2 rounded-lg bg-[#1c1a16] hover:bg-[#26231c] border border-[#3a3428] text-[#e8a54b] transition-colors"
            title="Back to Kiln Workbench"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <h1 className="text-xl font-bold flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-[#e8a54b]" />
              Security & Vulnerability Dashboard
            </h1>
            <p className="text-xs text-[#a39886] mt-0.5">
              Live audit distributions across scanned smart contracts and archived records.
            </p>
          </div>
        </div>

        <Link
          to="/"
          className="px-3 py-1.5 rounded-lg bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-xs font-mono text-[#f4efe6] flex items-center gap-1.5 transition-colors"
        >
          <span>Open Workbench</span>
        </Link>
      </div>

      {storage ? (
        <div className="text-[11px] rounded-lg border border-[#3a3428] bg-[#1c1a16] px-3 py-2">
          <span className="text-[#746c60] uppercase tracking-wider">Storage</span>{" "}
          <span className={storage.ok ? "text-emerald-400" : "text-amber-400"}>{storage.label}</span>
          {storage.detail ? <span className="text-[#a39886]"> — {storage.detail}</span> : null}
        </div>
      ) : null}

      <VulnerabilityDashboard scans={scans ?? []} />
    </div>
  );
}
