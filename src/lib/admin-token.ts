/**
 * Client-side admin-token plumbing (browser only).
 *
 * The app has no sign-in; a deployment can optionally be locked down with a
 * shared secret (`KILN_ADMIN_TOKEN` on the server — see `admin-guard.server.ts`).
 * When a token is stored here, every same-origin request automatically carries
 * it in the `x-kiln-admin-token` header, so the guarded server functions accept
 * the call. When no token is stored the interceptor is a no-op.
 *
 * Set it once from the browser console:
 *   localStorage.setItem("kiln_admin_token", "<the token>")
 */

const STORAGE_KEY = "kiln_admin_token";
const HEADER = "x-kiln-admin-token";

type FetchPatched = typeof globalThis & { __kilnAdminTokenInstalled?: boolean };

export function getAdminToken(): string {
  try {
    return localStorage.getItem(STORAGE_KEY) ?? "";
  } catch {
    return "";
  }
}

export function setAdminToken(token: string): void {
  try {
    if (token) localStorage.setItem(STORAGE_KEY, token);
    else localStorage.removeItem(STORAGE_KEY);
  } catch {
    // storage unavailable (private mode) — the guard simply stays unsatisfied
  }
}

/**
 * Wrap `window.fetch` once so same-origin requests carry the stored admin
 * token. Only ever ADDS a header to same-origin requests; it never blocks a
 * call, and it is inert when no token is stored or when `fetch` is already
 * wrapped.
 */
export function installAdminTokenFetch(): void {
  if (typeof window === "undefined") return;
  const w = window as FetchPatched;
  if (w.__kilnAdminTokenInstalled) return;
  w.__kilnAdminTokenInstalled = true;

  const original = window.fetch.bind(window);
  window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
    try {
      const token = getAdminToken();
      if (token) {
        const url =
          typeof input === "string"
            ? input
            : input instanceof URL
              ? input.href
              : input.url;
        const sameOrigin = new URL(url, window.location.origin).origin === window.location.origin;
        if (sameOrigin) {
          const baseHeaders =
            init?.headers ?? (input instanceof Request ? input.headers : undefined);
          const headers = new Headers(baseHeaders);
          if (!headers.has(HEADER)) {
            headers.set(HEADER, token);
            return original(input, { ...init, headers });
          }
        }
      }
    } catch {
      // fall through to the untouched call
    }
    return original(input, init);
  };
}
