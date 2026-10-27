# SmartBugs Curated — vendored fixture corpus

Source: https://github.com/smartbugs/smartbugs-curated (commit snapshot taken
2026-10-27). Licence: Apache 2.0 — see `LICENSE` in this directory.

Vendored so the detection benchmark (`scripts/benchmark-smartbugs.ts`) runs
offline and deterministically in CI. The files are unmodified.

- `dataset/` — 143 annotated vulnerable contracts, one directory per DASP
  category.
- `vulnerabilities.json` — the ground truth: one entry per file with the
  category and line numbers of each annotated vulnerability.
- `DATASET-README.md` — the upstream README, for the category definitions.

The benchmark measures this repository's detectors against that ground truth
per category. It is a *dataset* measurement, not a live-target one: these are
2018-era contracts compiled with 0.4.x/0.5.x, so a detector that needs a
modern construct (a hook callback, an EIP-7702 guard) cannot fire here and is
reported as "not applicable to this corpus" rather than as a miss.
