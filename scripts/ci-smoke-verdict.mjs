// The capture script's exit code checks HTTP/console errors. CI additionally
// rejects blank pages, overflow, warnings, and dev/production divergence.
import { readFileSync } from "node:fs";
import { exitCodeFor } from "./browser-smoke-verdict.mjs";

const [file, baselineFlag] = process.argv.slice(2);
const verdict = JSON.parse(readFileSync(file, "utf8"));
const failures = [];
if (exitCodeFor(verdict.viewports) !== 0) failures.push("HTTP or browser errors");
for (const name of ["desktop", "mobile"]) {
  const viewport = verdict.viewports?.[name];
  if (!viewport || viewport.bodyTextLen < 20) failures.push(`${name}: missing visible text`);
  if (viewport?.horizontalOverflow) failures.push(`${name}: horizontal overflow`);
}
for (const warning of [...(verdict.brandWarnings ?? []), ...(verdict.authWarnings ?? [])]) {
  failures.push(warning);
}
if (baselineFlag === "--require-baseline" && verdict.divergesFromBaseline !== false) {
  failures.push(...(verdict.baselineReasons ?? ["missing baseline comparison"]));
}
if (failures.length) {
  console.error(JSON.stringify({ file, failures }, null, 2));
  process.exitCode = 1;
} else {
  console.log(`${file}: desktop and mobile smoke passed`);
}
