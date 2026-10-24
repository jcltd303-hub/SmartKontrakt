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
    prefixed: { width: 1440, height: 1000 },
  })) {
    const context = await browser.newContext({ viewport });
    const requests = [];
    context.on("request", (request) => requests.push(request.url()));
    const proxyPrefix = "/hds-abc-8080-test";
    if (name === "prefixed")
      await context.route("https://preview.grok.mil/**", async (route) => {
        const requestUrl = new URL(route.request().url());
        const pathname = requestUrl.pathname.startsWith(proxyPrefix)
          ? requestUrl.pathname.slice(proxyPrefix.length)
          : requestUrl.pathname;
        const response = await route.fetch({
          url: new URL(`${pathname}${requestUrl.search}`, base).href,
        });
        await route.fulfill({ response });
      });
    const page = await context.newPage();
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("console", (message) => {
      if (message.type() === "error") console.log("browser console:", message.text());
    });
    page.on("requestfailed", (request) =>
      console.log("request failed:", request.url(), request.failure()?.errorText),
    );
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
    await page.goto(name === "prefixed" ? `https://preview.grok.mil${proxyPrefix}/` : base, {
      waitUntil: "networkidle",
      timeout: 60000,
    });
    const input = page.getByPlaceholder(
      "// Paste Solidity contract or runtime bytecode (0x...)...",
    );
    await input.fill(fixtures[0].bytecode);
    await page.getByRole("button", { name: "Bytecode & CFG", exact: true }).click();
    const panel = page.getByRole("region", { name: "Experimental image machine learning" });
    assert.equal(await panel.getByLabel("ML model").inputValue(), "resnet");
    for (const [index, fixture] of (name === "prefixed"
      ? fixtures.slice(0, 1)
      : fixtures
    ).entries()) {
      await input.fill(fixture.bytecode);
      await page.evaluate(() => {
        window.__mlResult = null;
      });
      await panel.getByRole("button", { name: "Run Image ML", exact: true }).click();
      await Promise.race([
        panel.getByText(/Model: resnet1d-/).waitFor({ timeout: 120000 }),
        panel
          .getByRole("alert")
          .waitFor({ timeout: 120000 })
          .then(async () => {
            throw new Error(await panel.getByRole("alert").innerText());
          }),
      ]);
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
    await context.route("**/models/resnet1d-v1.json", (route) => route.abort());
    await panel.getByRole("button", { name: "Run Image ML", exact: true }).click();
    await panel.getByRole("alert").waitFor({ timeout: 10000 });
    assert.equal(
      await panel.locator("tbody tr").count(),
      0,
      "failed model download must not produce scores",
    );
    await input.fill("contract Changed {}");
    assert.equal(
      await panel.getByRole("button", { name: "Run Image ML", exact: true }).isDisabled(),
      true,
    );
    assert.equal(await panel.locator("tbody tr").count(), 0);
    assert.deepEqual(errors, []);
    if (name === "prefixed") {
      const runtimeRequests = requests.filter((url) => /ort-wasm.*\.(mjs|wasm)$/.test(url));
      assert.ok(
        runtimeRequests.some((url) => url.endsWith(".wasm")),
        "actual prefixed WASM was downloaded",
      );
      assert.ok(
        runtimeRequests.every((url) => new URL(url).pathname.startsWith(proxyPrefix + "/")),
        "runtime requests preserve preview prefix",
      );
    }
    await context.close();
  }
  writeFileSync(
    `/workspace/screenshots/image-ml/${mode}-resnet-performance.json`,
    JSON.stringify(results, null, 2),
  );
  console.log(JSON.stringify(results));
} finally {
  await browser.close();
}
