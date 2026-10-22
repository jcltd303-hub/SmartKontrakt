import { createFileRoute } from "@tanstack/react-router";
import { Workbench } from "@/components/workbench";
import { listScans } from "@/lib/scans.functions";

export const Route = createFileRoute("/")({
  loader: async () => {
    try {
      // Payload shape since #2: { summaries, error, db }. The landing page
      // only needs the list; the Records tab owns error surfacing.
      const result = await listScans();
      return result.summaries;
    } catch {
      return [];
    }
  },
  component: Home,
});

function Home() {
  const scans = Route.useLoaderData();
  return (
    <div className="flex flex-col min-h-screen bg-[#12110e] text-[#f4efe6]">
      <nav className="px-6 py-2 border-b border-[#2d281f] bg-[#171512] flex items-center justify-between text-xs font-mono">
        <div className="flex items-center gap-2">
          <span className="font-bold text-[#e8a54b] tracking-wider uppercase">Kiln Workbench</span>
          <span className="text-[#746c60]">•</span>
          <span className="text-[#a39886]">EVM Smart Contract Security Suite</span>
        </div>
        <div className="flex items-center gap-3">
          <a
            href="/dashboard"
            className="px-2.5 py-1 rounded-md bg-[#26231c] hover:bg-[#3a3428] border border-[#3a3428] text-[#e8a54b] hover:text-[#f4efe6] transition-colors"
          >
            📊 Security Dashboard
          </a>
        </div>
      </nav>
      <Workbench initialScans={scans ?? []} />
    </div>
  );
}
