import assert from "node:assert/strict";
import { readFileSync, mkdirSync } from "node:fs";
import { chromium } from "playwright";

const url = process.argv[2] ?? "http://127.0.0.1:8080/";
const mode = process.argv[3] ?? "dev";
const fixture = JSON.parse(readFileSync("public/models/bytecode-image-v1-parity.json", "utf8"))
  .cases[0];
mkdirSync("/workspace/screenshots/image-ml", { recursive: true });
const browser = await chromium.launch({ headless: true });
try {
  for (const [name, viewport] of Object.entries({
    desktop: { width: 1440, height: 1000 },
    mobile: { width: 390, height: 844 },
  })) {
    const page = await browser.newPage({ viewport });
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await page.goto(url, { waitUntil: "networkidle", timeout: 60000 });
    await page
      .getByPlaceholder("// Paste Solidity contract or runtime bytecode (0x...)...")
      .fill(fixture.bytecode);
    await page.getByRole("button", { name: "Bytecode & CFG", exact: true }).click();
    const panel = page.getByRole("region", { name: "Experimental image machine learning" });
    await panel.getByRole("button", { name: "Run Image ML", exact: true }).click();
    await panel.getByText(/Model: .*Experimental ML signal/).waitFor({ timeout: 30000 });
    const rows = panel.locator("tbody tr");
    assert.equal(await rows.count(), 5);
    for (let i = 0; i < 5; i++) {
      const score = await rows.nth(i).locator("td").first().innerText();
      assert.equal(
        score,
        fixture.probabilities[i].toFixed(3),
        `${name} class ${i} must match independent Torch prediction`,
      );
    }
    assert.equal(await panel.locator("canvas").count(), 2);
    await panel.screenshot({ path: `/workspace/screenshots/image-ml/${mode}-${name}.png` });
    await page
      .getByPlaceholder("// Paste Solidity contract or runtime bytecode (0x...)...")
      .fill("contract Changed {}");
    await panel.getByRole("button", { name: "Run Image ML", exact: true }).waitFor();
    assert.equal(
      await panel.getByRole("button", { name: "Run Image ML", exact: true }).isDisabled(),
      true,
    );
    assert.equal(await panel.locator("tbody tr").count(), 0, "edited input clears predictions");
    assert.deepEqual(errors, [], "no browser runtime errors");
    console.log(
      `${mode} ${name}: real worker/model parity, previews, invalid-input and stale-result checks passed`,
    );
    await page.close();
  }
} finally {
  await browser.close();
}
