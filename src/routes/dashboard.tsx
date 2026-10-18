import { createFileRoute } from "@tanstack/react-router";
import { VulnerabilityDashboard } from "@/components/vulnerability-dashboard";
import { listScans } from "@/lib/scans.functions";

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
    <div className="p-8">
      <h1 className="text-2xl font-bold mb-6">Security Dashboard</h1>
      <VulnerabilityDashboard scans={scans ?? []} />
    </div>
  );
}
