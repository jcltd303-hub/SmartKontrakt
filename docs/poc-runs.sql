-- docs/poc-runs.sql
--
-- DO NOT APPLY until the SmartKontrakt Supabase project is identified.
-- Only lo-lyfe-dev is currently visible; do not create a paid project
-- automatically, and do not apply this SQL to any other project.
--
-- Anonymous insert-only is intentional for a private deployment: the
-- workbench saves terminal PoC run results with the browser's
-- publishable/anon key, and no read path is needed (results are shown
-- from the in-memory run, never re-read from the table). Cross-device
-- history needs authenticated ownership and is out of scope.

CREATE TABLE poc_runs (
  id uuid PRIMARY KEY,
  source text NOT NULL,
  status text NOT NULL CHECK (status IN ('passed', 'failed', 'error', 'timed_out')),
  started_at timestamptz NOT NULL,
  finished_at timestamptz NOT NULL,
  duration_ms integer NOT NULL CHECK (duration_ms >= 0),
  chain_id integer NOT NULL,
  exit_code integer,
  output text NOT NULL,
  truncated boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE poc_runs ENABLE ROW LEVEL SECURITY;

-- Exactly ONE policy: anonymous insert-only. There is deliberately NO
-- SELECT / UPDATE / DELETE policy for anon: saved runs cannot be read
-- back, changed, or removed through the anonymous key.
CREATE POLICY poc_runs_insert_only ON poc_runs FOR INSERT TO anon WITH CHECK (true);

-- RLS policies are checked IN ADDITION TO table privileges: without
-- this GRANT, anon gets "permission denied for table" before the
-- policy is even evaluated. Insert-only: no SELECT/UPDATE/DELETE grant.
GRANT INSERT ON poc_runs TO anon;
