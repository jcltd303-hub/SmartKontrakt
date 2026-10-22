/**
 * The single-guess lint — every shape in which a PoC harness can reach a
 * verdict it has not earned.
 *
 * The core defect: a harness calls ONE guessed name (an entry point, or the
 * reader it observes through) and reports "not reproduced" when that name
 * misses. That is indistinguishable from "the vulnerability is absent", and it
 * is the failure that matters most — a missed positive. The second defect is
 * judging by whether a call RETURNED: a no-op or already-guarded function
 * returns successfully and changes nothing, so the call result is not evidence.
 *
 * Each shape below is a distinct way to produce an unearned verdict. Every rule
 * carries a synthetic positive (must fire) and negative (must not) in
 * single-guess-lint.test.mjs, because a lint with a broken rule gives false
 * confidence in exactly the direction that hides real findings.
 *
 * Plain ESM, no dependencies, so the Node test runner can import it directly.
 */

/** Extract a top-level function body by brace matching (good enough for tests). */
function functionBody(source, name) {
  const at = source.indexOf(`function ${name}(`);
  if (at === -1) return "";
  const open = source.indexOf("{", at);
  if (open === -1) return "";
  let depth = 0;
  for (let i = open; i < source.length; i += 1) {
    const c = source[i];
    if (c === "{") depth += 1;
    else if (c === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(open, i + 1);
    }
  }
  return source.slice(open);
}

/** Every distinct call shape the file can send, however it is encoded. */
export function callShapes(source) {
  const shapes = new Set();
  for (const m of source.matchAll(/abi\.encodeWithSignature\(\s*"([^"]+)"/g)) shapes.add(m[1]);
  for (const m of source.matchAll(/abi\.encodeWithSelector\(\s*([^,)]+)/g)) shapes.add(m[1].trim());
  for (const m of source.matchAll(/abi\.encodeCall\(\s*([^,)]+)/g)) shapes.add(m[1].trim());
  for (const m of source.matchAll(/bytes4\(\s*keccak256\(\s*"([^"]+)"/g)) shapes.add(m[1]);
  for (const m of source.matchAll(/\bI[A-Z]\w*\(\s*target\s*\)\s*\.\s*(\w+)\s*\(/g)) shapes.add(m[1]);
  return shapes;
}

/** Does the file talk to the target at all? */
export function touchesTarget(source) {
  return (
    /abi\.encodeWithSignature\s*\(/.test(source) ||
    /abi\.encodeWithSelector\s*\(/.test(source) ||
    /abi\.encodeCall\s*\(/.test(source) ||
    /\btarget\s*\.\s*(call|staticcall|delegatecall)\b/.test(source) ||
    /\bI[A-Z]\w*\(\s*target\s*\)\s*\./.test(source)
  );
}

/** Does the file loop over candidates rather than naming one? */
export function walksCandidates(source) {
  return /\bfor\s*\(/.test(source) || callShapes(source).size >= 2;
}

const SHAPES = [
  {
    id: "adapt-precondition",
    severity: "error",
    title: "A guessed call is guarded by require(..., \"... adapt ...\")",
    why:
      "The verdict becomes 'not reproduced' the moment one guessed name misses, which is exactly the missed positive the whole exercise is about.",
    test: (s) =>
      /require\(\s*[\w.]+\s*,\s*"[^"]*\badapt/i.test(s) ||
      /require\(\s*[\w.]+\s*,\s*"[^"]*(adapt|adjust) (it|the)/i.test(s),
  },
  {
    id: "stub",
    severity: "error",
    title: "The test reverts before doing anything (an unadapted stub)",
    why:
      "A stub reports 'not reproduced' every single time, for every target, forever. It cannot ever produce a finding.",
    test: (s) => /TEMPLATE_NOT_ADAPTED/.test(s),
  },
  {
    id: "skipped",
    severity: "error",
    title: "The test is skipped",
    why: "A skipped test passes vacuously and reports nothing about the target.",
    test: (s) => /vm\.skip\s*\(/.test(s),
  },
  {
    id: "call-success-assert",
    severity: "error",
    title: "The verdict is that a call returned",
    why:
      "A no-op or already-guarded function returns successfully and changes nothing. Observed on a real run: kill() returned [Stop], moved 0 wei, and the harness called it 'not reproduced'. This is a false-positive machine as much as a false-negative one.",
    // assertTrue(ok), assertTrue(secondOk), assertTrue(upOk), assertTrue(success), assertEq(callOk, true)
    test: (s) => {
      if (/assertTrue\(\s*[A-Za-z_]*[Oo]k\s*[,)]/.test(s)) return true;
      if (/assertTrue\(\s*success\s*[,)]/.test(s)) return true;
      if (/assertTrue\(\s*[A-Za-z_]*[Oo]k\s*$/m.test(s)) return true;
      return /assertEq\(\s*[A-Za-z_]*[Oo]k\s*,\s*true\s*[,)]/.test(s);
    },
  },
  {
    id: "vacuous-catch",
    severity: "error",
    title: "An empty catch swallows the failure",
    why:
      "try/catch with an empty catch turns a reverting exploit into a silent pass — the harness reports reproduction because nothing was checked.",
    test: (s) => /catch\s*(\([^)]*\))?\s*\{\s*\}/.test(s),
  },
  {
    id: "always-pass",
    severity: "error",
    title: "An assertion that cannot fail",
    why: "assertTrue(true) and assertEq(x, x) assert nothing, so the harness always passes.",
    test: (s) =>
      /assertTrue\(\s*true\s*[,)]/.test(s) ||
      /assertEq\(\s*([A-Za-z_]\w*)\s*,\s*\1\s*[,)]/.test(s),
  },
  {
    id: "early-return-void",
    severity: "error",
    title: "An early return on a call result empties the verdict",
    why:
      "if (!ok) return; makes the exploit path optional, so the assertion below runs only when the exploit already worked — or never runs at all.",
    test: (s) => /if\s*\(\s*![A-Za-z_]*[Oo]k\s*\)\s*\{?\s*return\s*;/.test(s),
  },
  {
    id: "no-verdict-assert",
    severity: "error",
    title: "test_exploit contains no assertion at all",
    why:
      "A test with nothing to fail cannot fail, so it reports neither reproduction nor safety — but the pipeline records a result either way.",
    test: (s) => {
      const body = functionBody(s, "test_exploit");
      if (!body) return false;
      return !/\b(assert\w*|require|fail)\s*\(/.test(body);
    },
  },
  {
    id: "single-shape-guess",
    severity: "error",
    title: "One guessed call shape, with no alternatives",
    why:
      "A single guess cannot distinguish 'the vulnerability does not exist' from 'the entry point is called something else'. The second is a missed positive, and it is invisible.",
    test: (s) => {
      if (!touchesTarget(s)) return false;
      if (/\bfor\s*\(/.test(s)) return false; // loops over candidates
      return callShapes(s).size < 2;
    },
  },
  {
    id: "undisclosed-failure",
    severity: "error",
    title: "The failure message does not say what was tried",
    why:
      "If a miss does not name the candidates tried and state that it does not establish safety, a reader cannot tell 'not reproduced' from 'we guessed wrong' — which is the entire problem restated in the output.",
    test: (s) => {
      if (!touchesTarget(s)) return false;
      const body = functionBody(s, "test_exploit") || s;
      const msgs = [...body.matchAll(/\b(?:assert\w*|require)\s*\([\s\S]*?"([^"]{20,})"/g)].map((m) => m[1]);
      if (msgs.length === 0) return false;
      return !msgs.some((m) => /\btried\b/i.test(m) || /does NOT establish safety/i.test(m));
    },
  },
  {
    id: "delegatecall-single",
    severity: "error",
    title: "A single delegatecall into a guessed target",
    why:
      "Same single-guess defect through the delegatecall door: one address, one shape, no alternatives.",
    test: (s) => /\.delegatecall\s*\(/.test(s) && !walksCandidates(s),
  },
  {
    id: "todo-in-verdict",
    severity: "warning",
    title: "A TODO sits inside the verdict path",
    why:
      "Legitimate for configuration (a price, an address), but a TODO on the assertion itself usually means the verdict was never finished.",
    test: (s) => {
      const body = functionBody(s, "test_exploit");
      if (!body) return false;
      return /\/\/\s*TODO/i.test(body);
    },
  },
  {
    id: "bare-call-precondition",
    severity: "warning",
    title: "A require on a call result that names no alternative",
    why:
      "Setup preconditions are legitimate, but a bare require(ok, \"... failed\") on a target call is the same trap: it aborts with no hint that another name might work.",
    test: (s) => /require\(\s*[A-Za-z_]*[Oo]k\w*\s*,\s*"[^"]*failed[^"]*"\s*\)/.test(s),
  },
];

export const SHAPE_IDS = SHAPES.map((s) => s.id);

export function lintTemplate(source) {
  const findings = [];
  for (const shape of SHAPES) {
    let hit;
    try {
      hit = Boolean(shape.test(source));
    } catch (err) {
      // A rule that throws must never read as "clean": that is the same
      // false-confidence failure this lint exists to prevent. Fail loudly.
      throw new Error(`single-guess rule "${shape.id}" threw: ${err && err.message}`);
    }
    if (hit) findings.push({ shape: shape.id, severity: shape.severity, title: shape.title, why: shape.why });
  }
  return findings;
}

export function lintErrors(source) {
  return lintTemplate(source).filter((f) => f.severity === "error");
}
