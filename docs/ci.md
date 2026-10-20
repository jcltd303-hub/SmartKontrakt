# CI checks

Every push and pull request runs on Node 24 with a clean `npm ci`, followed by
unit tests, type checking, linting, and a production build. The build skips database
migrations when connection variables are absent. CI provides no API keys or database
credentials and does not use `pull_request_target`.

Chromium then runs the existing browser smoke capture against both `npm run dev`
and `npm run preview` (the already-built output). Each capture covers desktop
1280×800 and mobile 390×844. CI rejects HTTP/browser errors, missing page text,
horizontal overflow, brand/auth warnings, and divergence from the dev baseline.
This includes the committed share-card asset; a missing asset remains a failure.

The Linux runner script owns and cleans up each server process group, refuses
occupied ports, and bounds readiness and browser execution. To reproduce after
installing dependencies, building, and installing Chromium, run:

```sh
bash scripts/ci-browser-smoke.sh
```

The existing browser guard requires `/workspace/screenshots/ci` to be writable.
On every run, the workflow retains available desktop/mobile screenshots, JSON
verdicts, and server/browser logs as a seven-day Actions artifact. A startup
failure may only produce a server log. These logs are generated without CI secrets;
do not add credential-bearing environment variables to this job.

A successful HTTP readiness probe alone is not the browser test. Both actual
browser captures and their stricter CI verdict checks must pass. Human review of
the retained screenshots remains useful for visual layout issues.

The pipeline remains mounted across view changes, while its optional phone-worker monitor polls only when the pipeline view is active. This prevents hidden panels from issuing background requests to an absent local backend.
