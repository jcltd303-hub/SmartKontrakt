import { createFileRoute } from "@tanstack/react-router";
import { Workbench } from "@/components/workbench";
import { listScans } from "@/lib/scans.functions";

export const Route = createFileRoute("/")({
  loader: async () => {
    try {
      return await listScans();
    } catch {
      return [];
    }
  },
  component: Home,
});

function Home() {
  const scans = Route.useLoaderData();
  return (
    <div className="flex flex-col min-h-screen">
      <nav className="p-4 border-b">
        <a href="/dashboard" className="text-blue-500 hover:underline">Dashboard</a>
      </nav>
      <Workbench initialScans={scans ?? []} />
    </div>
  );
}
