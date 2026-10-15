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
  return <Workbench initialScans={scans ?? []} />;
}
