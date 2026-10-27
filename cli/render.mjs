// cli/render.mjs
//
// Pure frame builders for the audit TUI (2026-10-27).
//
// Rendering is separated from I/O on purpose: every function here takes state and
// returns a string, so the whole interface is testable without a TTY, a worker or
// a database. The loop in audit-tui.mjs only polls, keys and paints.
//
// No dependencies. Raw ANSI, honouring NO_COLOR and TERM=dumb, because this runs
// over SSH on the box that has the worker — installing a UI toolkit there is the
// thing we are trying to avoid.

const ESC = "\x1b[";
const noColor = Boolean(process.env.NO_COLOR) || process.env.TERM === "dumb";

export const colour = (code) => (s) => (noColor ? String(s) : `${ESC}${code}m${s}${ESC}0m`);
export const bold = colour("1");
export const dim = colour("2");
export const red = colour("31");
export const green = colour("32");
export const yellow = colour("33");
export const blue = colour("34");
export const magenta = colour("35");
export const cyan = colour("36");
export const grey = colour("90");

/** Strip ANSI — used by the tests to measure visible width. */
export function visibleLength(s) {
  return String(s).replace(/\x1b\[[0-9;]*m/g, "").length;
}

export function truncate(s, width) {
  const plain = String(s);
  if (visibleLength(plain) <= width) return plain;
  // Trim on visible characters, keeping escapes intact is overkill here: callers
  // pass uncoloured strings to truncate, then colour the result.
  return plain.slice(0, Math.max(0, width - 1)) + "…";
}

export function bar(fraction, width) {
  const f = Math.max(0, Math.min(1, Number.isFinite(fraction) ? fraction : 0));
  const filled = Math.round(f * width);
  return "█".repeat(filled) + "░".repeat(Math.max(0, width - filled));
}

export function humanDuration(ms) {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m${String(s % 60).padStart(2, "0")}s`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h${String(m % 60).padStart(2, "0")}m`;
  return `${Math.floor(h / 24)}d${String(h % 24).padStart(2, "0")}h`;
}

export function humanCount(n) {
  const v = Number(n);
  if (!Number.isFinite(v)) return "—";
  if (v >= 1e9) return `${(v / 1e9).toFixed(1)}B`;
  if (v >= 1e6) return `${(v / 1e6).toFixed(1)}M`;
  if (v >= 1e4) return `${(v / 1e3).toFixed(1)}k`;
  return String(v);
}

const SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
export function spinnerFrame(tick) {
  return SPINNER[Math.abs(Math.trunc(tick)) % SPINNER.length];
}

const STATE_COLOUR = { running: green, paused: yellow, idle: grey, stopped: red };

/** The header: worker identity, state, and the spinner while it runs. */
export function renderHeader(state, tick) {
  const st = state.status ?? {};
  const paint = STATE_COLOUR[st.state] ?? grey;
  const spin = st.state === "running" ? `${spinnerFrame(tick)} ` : "";
  const shard = st.shard ? ` shard ${st.shard}` : "";
  const chain = st.chainId ? ` ${st.chainId}` : "";
  return `${bold("SmartKontrakt")} ${dim("audit")}  ${paint(spin + (st.state ?? "unknown"))}${dim(chain + shard)}`;
}

/** Progress: the numbers that decide whether the run is worth waiting for. */
export function renderProgress(state) {
  const st = state.status ?? {};
  const total = Number(st.total ?? 0);
  const done = Number(st.completed ?? 0) + Number(st.failed ?? 0);
  const pct = total > 0 ? done / total : 0;
  const lines = [];
  lines.push(
    `${bar(pct, 32)} ${bold(`${(pct * 100).toFixed(1)}%`)}  ${humanCount(done)}/${humanCount(total)}`,
  );

  // Rate and ETA from the run's own clock, not from a sample window: a run that
  // has been going for hours is a better estimator than the last two ticks.
  const started = st.startedAt ? Date.parse(st.startedAt) : NaN;
  const elapsed = Number.isFinite(started) ? Date.now() - started : NaN;
  const rate = Number.isFinite(elapsed) && elapsed > 0 ? done / (elapsed / 1000) : NaN;
  const remaining = Number.isFinite(rate) && rate > 0 ? ((total - done) / rate) * 1000 : NaN;
  const bits = [];
  if (Number.isFinite(rate)) bits.push(`${rate.toFixed(2)} addr/s`);
  if (Number.isFinite(remaining)) bits.push(`ETA ${humanDuration(remaining)}`);
  if (Number.isFinite(elapsed)) bits.push(`elapsed ${humanDuration(elapsed)}`);
  lines.push(dim(bits.join("  ·  ")));

  const counts = [];
  if (st.failed) counts.push(red(`${st.failed} failed`));
  if (st.skipped) counts.push(grey(`${st.skipped} skipped`));
  if (st.stale) counts.push(yellow(`${st.stale} stale`));
  if (st.pending) counts.push(blue(`${st.pending} pending flush`));
  if (counts.length) lines.push(counts.join(dim("  ·  ")));
  if (st.current) lines.push(dim(`current: ${truncate(st.current, 60)}`));
  if (st.lastError) lines.push(red(`last error: ${truncate(String(st.lastError), 72)}`));
  return lines.join("\n");
}

/** LLM health, from /health/llm — or an explicit "off" when the pass is disabled. */
export function renderLlm(state) {
  const llm = state.llm ?? {};
  const verdict = llm.verdict ?? {};
  const paint = { smooth: green, off: grey, waiting: blue, degraded: yellow, dead: red }[verdict.state] ?? grey;
  const calls = `${llm.ok ?? 0}/${(llm.ok ?? 0) + (llm.empty ?? 0) + (llm.error ?? 0)} usable`;
  return `${dim("LLM")} ${paint(verdict.state ?? "unknown")} ${dim(calls)} ${dim(truncate(verdict.reason ?? "", 70))}`;
}

/** The read queue: the product's actual output, one line per contract. */
export function renderQueue(queue, limit = 8) {
  const rows = (queue?.rows ?? []).slice(0, limit);
  const counts = queue?.counts ?? {};
  const head = `${bold("Read queue")} ${dim(
    `${counts.readNow ?? 0} now · ${counts.readNext ?? 0} next · ${counts.needsLiveState ?? 0} live · ${counts.background ?? 0} background`,
  )}`;
  if (rows.length === 0) return `${head}\n${dim("  (nothing yet — findings arrive as scans land)")}`;
  const lines = rows.map((r) => {
    const band = { "read-now": red("now "), "read-next": yellow("next"), "needs-live-state": blue("live"), background: grey("bg  ") }[r.band] ?? grey("?   ");
    const who = (r.address ?? r.scanId ?? "").slice(0, 10);
    return `  ${band} ${dim(who)} ${truncate(r.title ?? r.detector ?? "", 58)}`;
  });
  return [head, ...lines].join("\n");
}

/** Archive stats, straight from the DB. */
export function renderStats(state) {
  const s = state.db ?? {};
  if (s.error) return `${bold("Archive")} ${red(s.error)}`;
  const parts = [
    `${humanCount(s.scans ?? 0)} scans`,
    `${humanCount(s.findings ?? 0)} findings`,
    `${humanCount(s.critical ?? 0)} critical`,
    `${humanCount(s.high ?? 0)} high`,
  ];
  if (s.dbState) parts.push(dim(s.dbState));
  return `${bold("Archive")} ${parts.join(dim("  ·  "))}`;
}

/** The menu, with the selected row inverted. */
export const MENU = [
  { key: "r", label: "Run control", hint: "start / pause / resume / stop" },
  { key: "q", label: "Read queue", hint: "what to open next, by band" },
  { key: "s", label: "Stats", hint: "archive counts, per-detector" },
  { key: "g", label: "Settings", hint: "shard, delay, RPC, LLM, autoPoC" },
  { key: "d", label: "Database", hint: "schema check, backup, wipe" },
  { key: "?", label: "Keys", hint: "shortcuts" },
  { key: "x", label: "Quit", hint: "" },
];

export function renderMenu(selected) {
  return MENU.map((item, i) => {
    const row = ` ${item.key}  ${item.label.padEnd(14)} ${dim(item.hint)}`;
    return i === selected ? cyan(`▸${row.slice(1)}`) : row;
  }).join("\n");
}

/** A full frame: header, progress, llm, stats, queue, menu, footer. */
export function renderFrame(state, selected, tick) {
  const width = state.width ?? 100;
  const rule = dim("─".repeat(Math.min(width, 100)));
  return [
    renderHeader(state, tick),
    rule,
    renderProgress(state),
    "",
    renderLlm(state),
    renderStats(state),
    "",
    renderQueue(state.queue, state.queueLimit ?? 8),
    rule,
    renderMenu(selected),
    dim(` [tab] next  [enter] open  [q] quit   ${state.notice ?? ""}`),
  ].join("\n");
}
