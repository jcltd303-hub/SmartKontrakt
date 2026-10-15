import { createServerFn } from "@tanstack/react-start";
import type { Finding } from "./types";

export const requestAiReview = createServerFn({ method: "POST" })
  .validator((input: unknown) => {
    if (!input || typeof input !== "object") {
      throw new Error("Invalid request payload");
    }
    const { contractName, body, findings } = input as {
      contractName?: string;
      body?: string;
      findings?: Finding[];
    };
    return {
      contractName: contractName || "TargetContract",
      body: typeof body === "string" ? body.slice(0, 30000) : "",
      findings: Array.isArray(findings) ? findings.slice(0, 20) : [],
    };
  })
  .handler(async ({ data }) => {
    const { generateAiSecurityReview } = await import("./ai-review.server");
    return generateAiSecurityReview(data.contractName, data.body, data.findings);
  });
