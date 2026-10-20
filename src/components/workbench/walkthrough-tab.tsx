import { ExploitWalkthroughGenerator } from "@/components/exploit-walkthrough-generator";
import type { WorkbenchController } from "./use-workbench-controller";

type WalkthroughTabProps = Pick<WorkbenchController, "activeTab" | "report" | "contractBody">;

export function WalkthroughTab({ activeTab, report, contractBody }: WalkthroughTabProps) {
  return (
    <>
      {activeTab === "walkthrough" && (
        <ExploitWalkthroughGenerator
          findings={report?.findings ?? []}
          contractName={report?.label ?? "TargetContract"}
          contractBody={contractBody}
        />
      )}
    </>
  );
}
