// src/lib/admin-token.test.ts
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { getAdminToken, setAdminToken, installAdminTokenFetch } from "./admin-token.ts";

describe("admin-token", () => {
  it("safely handles getAdminToken and setAdminToken in Node environment", () => {
    // In Node (no window/localStorage), should return ""
    assert.equal(getAdminToken(), "");
    assert.doesNotThrow(() => setAdminToken("test-token"));
  });

  it("installAdminTokenFetch does not throw when window.fetch has only a getter", () => {
    const originalGlobalWindow = (globalThis as unknown as { window?: unknown }).window;
    try {
      const mockWindow: Record<string, unknown> = {
        location: { origin: "https://example.com" },
      };

      // Define fetch as a getter-only property to simulate the reported browser environment
      const originalFetch = () => Promise.resolve(new Response());

      Object.defineProperty(mockWindow, "fetch", {
        get() {
          return originalFetch;
        },
        // getter-only: no setter provided
        configurable: true,
      });

      (globalThis as unknown as { window: unknown }).window = mockWindow;

      // This must not throw TypeError: Cannot set property fetch of #<Window> which has only a getter
      assert.doesNotThrow(() => {
        installAdminTokenFetch();
      });
    } finally {
      (globalThis as unknown as { window?: unknown }).window = originalGlobalWindow;
    }
  });

  it("installAdminTokenFetch does not throw when window.fetch is non-configurable and getter-only", () => {
    const originalGlobalWindow = (globalThis as unknown as { window?: unknown }).window;
    try {
      const mockWindow: Record<string, unknown> = {
        location: { origin: "https://example.com" },
      };

      const originalFetch = () => Promise.resolve(new Response());

      Object.defineProperty(mockWindow, "fetch", {
        get() {
          return originalFetch;
        },
        configurable: false, // completely non-configurable
      });

      (globalThis as unknown as { window: unknown }).window = mockWindow;

      assert.doesNotThrow(() => {
        installAdminTokenFetch();
      });
    } finally {
      (globalThis as unknown as { window?: unknown }).window = originalGlobalWindow;
    }
  });
});
