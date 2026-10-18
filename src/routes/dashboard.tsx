import { createFileRoute, Link } from "@tanstack/react-router";
import { VulnerabilityDashboard } from "@/components/vulnerability-dashboard";
import { listScans } from "@/lib/scans.functions";
import { ArrowLeft, ShieldAlert } from "lucide-react";

export const Route = createFileRoute("/dashboard")({
  loader: async () => {
    try {
      return await listScans();
    } catch {
      return [];
    }
  },
  component: DashboardPage,
});

function DashboardPage() {
  const scans = Route.useLoaderData();
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

      <VulnerabilityDashboard scans={scans ?? []} />
    </div>
  );
}
