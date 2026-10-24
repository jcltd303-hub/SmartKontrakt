import assert from "node:assert/strict";
import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { chromium } from "playwright";
const base = process.argv[2] ?? "http://127.0.0.1:8080/";
const mode = process.argv[3] ?? "dev";
const fixtures = JSON.parse(readFileSync("public/models/resnet1d-v1-parity.json", "utf8")).cases;
const browser = await chromium.launch({ headless: true });
const results = [];
mkdirSync("/workspace/screenshots/image-ml", { recursive: true });
try {
  for (const [name, viewport] of Object.entries({
    desktop: { width: 1440, height: 1000 },
    mobile: { width: 390, height: 844 },
  })) {
    const page = await browser.newPage({ viewport });
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    const cdp = await page.context().newCDPSession(page);
    if (name === "mobile") await cdp.send("Emulation.setCPUThrottlingRate", { rate: 4 });
    await page.addInitScript(() => {
      const NativeWorker = window.Worker;
      window.Worker = class extends NativeWorker {
        constructor(...args) {
          super(...args);
          this.addEventListener("message", (event) => {
            window.__mlResult = event.data;
          });
        }
      };
    });
    await page.goto(base, { waitUntil: "networkidle", timeout: 60000 });
    const input = page.getByPlaceholder(
      "// Paste Solidity contract or runtime bytecode (0x...)...",
    );
    await input.fill(fixtures[0].bytecode);
    await page.getByRole("button", { name: "Bytecode & CFG", exact: true }).click();
    const panel = page.getByRole("region", { name: "Experimental image machine learning" });
    assert.equal(await panel.getByLabel("ML model").inputValue(), "resnet");
    for (const [index, fixture] of fixtures.entries()) {
      await input.fill(fixture.bytecode);
      await page.evaluate(() => {
        window.__mlResult = null;
      });
      await panel.getByRole("button", { name: "Run Image ML", exact: true }).click();
      await panel.getByText(/Model: resnet1d-/).waitFor({ timeout: 120000 });
      const result = await page.evaluate(() => window.__mlResult);
      assert.equal(result.ok, true);
      for (let i = 0; i < 5; i++)
        assert.ok(
          Math.abs(result.predictions[i].score - fixture.probabilities[i]) <= 1e-5,
          `${name} case ${index} score ${i}`,
        );
      assert.ok(
        result.timing.inferenceMs < 30000,
        "inference must finish within 30 seconds on throttled mobile",
      );
      results.push({ viewport: name, fixture: index, ...result.timing });
      if (index === 0)
        await panel.screenshot({
          path: `/workspace/screenshots/image-ml/${mode}-resnet-${name}.png`,
        });
    }
    // Cancel while a fresh worker loads; editing also clears both successful and in-flight results.
    await panel.getByRole("button", { name: "Run Image ML", exact: true }).click();
    await panel.getByRole("button", { name: "Cancel", exact: true }).click();
    assert.equal(await panel.locator("tbody tr").count(), 0);
    await input.fill("contract Changed {}");
    assert.equal(
      await panel.getByRole("button", { name: "Run Image ML", exact: true }).isDisabled(),
      true,
    );
    assert.equal(await panel.locator("tbody tr").count(), 0);
    assert.deepEqual(errors, []);
    await page.close();
  }
  writeFileSync(
    `/workspace/screenshots/image-ml/${mode}-resnet-performance.json`,
    JSON.stringify(results, null, 2),
  );
  console.log(JSON.stringify(results));
} finally {
  await browser.close();
}
