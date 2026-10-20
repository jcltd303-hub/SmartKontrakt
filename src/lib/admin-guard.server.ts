import { getRequest } from "@tanstack/react-start/server";

/**
 * Opt-in shared-secret guard for the app's mutating and destructive server
 * functions — deleting an audit record, deleting a RAG chunk, changing the
 * database configuration, or spending an AI call.
 *
 * The app has no sign-in (that was removed deliberately), which also means a
 * deployed instance is reachable by anyone who can load it. Set
 * `KILN_ADMIN_TOKEN` in the environment to require callers to present the same
 * value in the `x-kiln-admin-token` request header. When the variable is unset
 * the guard is a no-op, so local development and single-user deployments behave
 * exactly as before — nothing is enforced unless the operator opts in.
 *
 * The client attaches the header automatically when a token is stored (see
 * `admin-token.ts`); an operator can also inject it at a reverse proxy.
 */
export class AdminTokenRequiredError extends Error {
  readonly status = 403;
  constructor() {
    super("Forbidden: a valid admin token is required for this operation");
    this.name = "AdminTokenRequiredError";
  }
}

/** True when an admin token is configured, i.e. the guard is enforcing. */
export function adminTokenConfigured(): boolean {
  return Boolean(process.env.KILN_ADMIN_TOKEN?.trim());
}

/**
 * Throw `AdminTokenRequiredError` unless the configured admin token matches.
 * A no-op when `KILN_ADMIN_TOKEN` is unset.
 */
export function assertAdminToken(): void {
  const expected = process.env.KILN_ADMIN_TOKEN?.trim();
  if (!expected) return; // guard off
  const header = getRequest()?.headers?.get("x-kiln-admin-token") ?? null;
  if (header && header.trim() === expected) return;
  throw new AdminTokenRequiredError();
}
