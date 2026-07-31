// Tests for the GitHub Action wrapper (action/report.mjs).
//
// THE ONE THAT MATTERS MOST is "a scan that did not run must never come back
// green". Every other check here is about presentation; that one is about a
// developer merging an extension nobody looked at, because the build was green.
// It has a positive control beside it for the same reason the rest do: exit 1 is
// also what a reporter that is simply broken returns, so a real clean run must
// come back 0 in the same test or the assertion proves nothing.
//
// THE SECOND THEME is that fail-on cannot be tested on the bad fixture alone.
// That fixture has 4 failures AND 8 warnings, so "fail-on: warn exits 1" is
// satisfied by the failures on their own and would pass even if the warn tier
// were ignored entirely. There is a warn-only fixture built below for exactly
// that reason: 0 failing, 2 needing judgement, so the escalation is the only
// thing that can turn it red.

import { annotation, summary, exitCodeFor, run } from "../action/report.mjs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync, cpSync } from "node:fs";
import { tmpdir } from "node:os";

const here = dirname(fileURLToPath(import.meta.url));
let pass = 0, fail = 0;
const check = (name, cond, extra = "") => {
  if (cond) { pass++; }
  else { fail++; console.log(`  FAIL  ${name}${extra ? `\n        ${extra}` : ""}`); }
};

const BAD = join(here, "fixtures", "bad");
const CLEAN = join(here, "fixtures", "clean");

// A fixture with warnings and no failures. Without it, nothing here can tell
// "fail-on: warn escalates" from "fail-on: warn is ignored".
const WARNONLY = mkdtempSync(join(tmpdir(), "wsl-warn-"));
cpSync(CLEAN, WARNONLY, { recursive: true });
{
  const m = JSON.parse(readFileSync(join(CLEAN, "manifest.json"), "utf8"));
  m.host_permissions = ["<all_urls>"];
  writeFileSync(join(WARNONLY, "manifest.json"), JSON.stringify(m, null, 2));
}

// Drive run() in process, capturing what it would have written, with a scratch
// GITHUB_OUTPUT and GITHUB_STEP_SUMMARY so the real ones are never touched.
function invoke(env = {}) {
  const dir = mkdtempSync(join(tmpdir(), "wsl-gh-"));
  const outFile = join(dir, "out"), sumFile = join(dir, "sum");
  writeFileSync(outFile, ""); writeFileSync(sumFile, "");
  const out = [], err = [];
  const code = run({
    env: { WSL_PATH: CLEAN, GITHUB_OUTPUT: outFile, GITHUB_STEP_SUMMARY: sumFile, ...env },
    out: (s) => out.push(s),
    err: (s) => err.push(s),
  });
  const outputs = Object.fromEntries(
    readFileSync(outFile, "utf8").split("\n").filter(Boolean).map((l) => l.split("=")),
  );
  return {
    code,
    out, err,
    stdout: out.join("\n"), stderr: err.join("\n"),
    outputs,
    summaryText: readFileSync(sumFile, "utf8"),
    annotations: out.filter((l) => l.startsWith("::")),
  };
}

// --- fail-on is validated, not silently defaulted ---------------------------

{
  const bad = invoke({ WSL_PATH: BAD, WSL_FAIL_ON: "failure" });
  check("fail-on: an unrecognised value exits 2", bad.code === 2, `got ${bad.code}`);
  check("fail-on: ...and names the bad value", /failure/.test(bad.stderr), bad.stderr);
  check("fail-on: ...and lists the legal ones", /fail, warn, never/.test(bad.stderr), bad.stderr);
  // The point of exiting 2 is that nothing ran. A version that validated the
  // input and then linted anyway would pass the checks above.
  check("fail-on: ...and nothing was checked", bad.annotations.length === 0 && bad.summaryText === "");
  // THE CONTROL: the three legal values must not be rejected, or the assertions
  // above would also pass on a validator that refuses everything.
  for (const v of ["fail", "warn", "never"]) {
    check(`fail-on: ${v} is accepted`, invoke({ WSL_PATH: CLEAN, WSL_FAIL_ON: v }).code !== 2);
  }
  check("fail-on: an unset value defaults to fail", invoke({ WSL_PATH: BAD }).code === 1);
}

// --- exit codes -------------------------------------------------------------

{
  check("exit: bad fixture with fail-on=fail is 1", invoke({ WSL_PATH: BAD, WSL_FAIL_ON: "fail" }).code === 1);
  check("exit: bad fixture with fail-on=never is 0", invoke({ WSL_PATH: BAD, WSL_FAIL_ON: "never" }).code === 0);
  check("exit: clean fixture with fail-on=fail is 0", invoke({ WSL_PATH: CLEAN, WSL_FAIL_ON: "fail" }).code === 0);
  // Clean has no warnings either, so warn must not invent one.
  check("exit: clean fixture with fail-on=warn is 0", invoke({ WSL_PATH: CLEAN, WSL_FAIL_ON: "warn" }).code === 0);

  // The escalation, on the fixture where failures cannot account for it.
  const w = invoke({ WSL_PATH: WARNONLY, WSL_FAIL_ON: "fail" });
  check("exit: warn-only fixture really has no failures", w.outputs.fail === "0" && Number(w.outputs.warn) > 0,
    JSON.stringify(w.outputs));
  check("exit: warn-only fixture with fail-on=fail is 0", w.code === 0);
  check("exit: warn-only fixture with fail-on=warn is 1",
    invoke({ WSL_PATH: WARNONLY, WSL_FAIL_ON: "warn" }).code === 1);
}

// --- an extension that could not be read is not a clean result --------------

{
  const missing = invoke({ WSL_PATH: join(here, "fixtures", "no-such-directory"), WSL_FAIL_ON: "never" });
  check("unreadable: fails even under fail-on=never", missing.code === 1, `got ${missing.code}`);
  check("unreadable: ...and says nothing was checked", /nothing was checked/i.test(missing.stderr), missing.stderr);
  check("unreadable: ...and sets the unreadable output", missing.outputs.unreadable === "true");
  check("unreadable: ...and the summary does not read as clean",
    !/No findings/.test(missing.summaryText) && /could not be read/i.test(missing.summaryText),
    missing.summaryText);
  // THE CONTROL: fail-on=never is genuinely honoured on a fixture with real
  // failures, so the 1 above comes from the unreadable path and not from
  // fail-on=never being broken.
  check("unreadable: control, fail-on=never does work on real failures",
    invoke({ WSL_PATH: BAD, WSL_FAIL_ON: "never" }).code === 0);
  check("unreadable: control, a readable extension reports unreadable=false",
    invoke({ WSL_PATH: CLEAN }).outputs.unreadable === "false");
}

// --- a scan that did not produce a report must not come back green ----------

{
  const dir = mkdtempSync(join(tmpdir(), "wsl-cli-"));
  const fake = (name, body) => {
    const p = join(dir, name);
    writeFileSync(p, body);
    return p;
  };
  const cases = {
    "prints nothing and exits 0": fake("silent.mjs", "process.exit(0)"),
    "prints garbage and exits 0": fake("garbage.mjs", "console.log('Killed: 9'); process.exit(0)"),
    "prints valid JSON with no counts": fake("nocounts.mjs", "console.log(JSON.stringify({findings:[]})); process.exit(0)"),
    "prints counts that are not numbers": fake("notnum.mjs", "console.log(JSON.stringify({counts:{fail:'0'},findings:[]}))"),
    "crashes": fake("crash.mjs", "throw new Error('boom')"),
    "does not exist": join(dir, "absent.mjs"),
  };
  for (const [what, cli] of Object.entries(cases)) {
    const r = invoke({ WSL_PATH: CLEAN, WSL_CLI: cli, WSL_FAIL_ON: "never" });
    // fail-on=never is set deliberately: under it a genuine clean scan returns 0,
    // so a 1 here can only come from the report being missing.
    check(`no-report: a linter that ${what} exits 1`, r.code === 1, `got ${r.code}`);
    check(`no-report: a linter that ${what} says nothing was checked`,
      /did not produce a report/.test(r.stderr), r.stderr);
    check(`no-report: a linter that ${what} writes no summary`, r.summaryText === "");
  }
  // THE CONTROL for the whole block: the real linter under the same fail-on=never
  // comes back 0. Without this, every assertion above is satisfied by a reporter
  // that returns 1 unconditionally.
  check("no-report: control, the real linter under fail-on=never exits 0",
    invoke({ WSL_PATH: CLEAN, WSL_FAIL_ON: "never" }).code === 0);
}

// --- annotations ------------------------------------------------------------

// Parse "::error title=a,file=b,line=3::message" back into its parts, so the
// tests can assert on the property KEYS rather than on a substring. A substring
// test cannot tell a comma inside a title from a comma separating properties,
// which is the bug this is here to catch.
function parseAnnotation(line) {
  const m = /^::(error|warning|notice) ([^:]*)::([\s\S]*)$/.exec(line);
  if (!m) return null;
  const props = {};
  for (const pair of m[2].split(",")) {
    const i = pair.indexOf("=");
    props[pair.slice(0, i)] = pair.slice(i + 1);
  }
  return { level: m[1], props, message: m[3] };
}

// Same reasoning as the defensive parse below: an annotation that does not parse
// is a real failure mode, so every check that reads one must be able to REPORT
// that rather than throw on a null and take the rest of the suite with it.
const propsOf = (line) => parseAnnotation(line)?.props ?? {};

{
  const r = invoke({ WSL_PATH: BAD, WSL_FAIL_ON: "never" });
  check("annotations: the bad fixture produces some", r.annotations.length > 0);
  check("annotations: every one is a single line",
    r.annotations.every((a) => !/[\r\n]/.test(a)),
    r.annotations.find((a) => /[\r\n]/.test(a)));
  check("annotations: every one parses", r.annotations.every(parseAnnotation),
    r.annotations.find((a) => !parseAnnotation(a)));
  // Parsed once, defensively. An unparseable annotation is a real failure mode -
  // it is what dropping the property escaping produces - and the checks below
  // must report it rather than throw on a null, because a crash here stops the
  // suite and every later check silently never runs.
  const parsed = r.annotations.map(parseAnnotation).filter(Boolean);
  check("annotations: failures are errors and judgement calls are warnings",
    parsed.some((a) => a.level === "error") && parsed.some((a) => a.level === "warning"));

  // The real title of the unused-permissions finding is "Declared but never
  // used: bookmarks, downloads, topSites" - a colon and two commas, in the
  // package's own output rather than a synthetic case. Unescaped, GitHub reads
  // "downloads" and " topSites" as two more properties and drops the annotation.
  const up = parsed.find((a) => /Declared but never used/.test(a.props.title || ""));
  check("annotations: a title with commas and a colon survives", !!up,
    r.annotations.find((a) => /Declared/.test(a)));
  if (up) {
    check("annotations: ...without inventing properties",
      Object.keys(up.props).every((k) => ["title", "file", "line", "col"].includes(k)),
      JSON.stringify(Object.keys(up.props)));
    check("annotations: ...and the comma is percent-encoded", /%2C/.test(up.props.title), up.props.title);
    check("annotations: ...and the colon is too", /%3A/.test(up.props.title), up.props.title);
  }

  // Evidence that is a file and a line must land on that line, because inline
  // placement is the whole reason this wrapper exists rather than a run: step.
  const rc = parsed.find((a) => /script.*outside the extension/i.test(a.props.title || ""));
  check("annotations: remote-code lands on the file and line of the evidence",
    rc && rc.props.file === "popup.html" && rc.props.line === "3",
    rc ? JSON.stringify(rc.props) : "no remote-code annotation");

  // A finding with no place in a file must not be given one, because pointing at
  // manifest.json line 1 would be a guess dressed as a citation. No rule in the
  // bad fixture is evidence-free - checked, rather than assumed, which is how
  // this test started out asserting the opposite about unused-permissions - so
  // the case is driven directly. The manifest-error finding is the real shape.
  check("annotations: every finding in the bad fixture does carry a file",
    parsed.length > 0 && parsed.every((a) => a.props.file),
    "premise of the next check");
  {
    const f = { severity: "fail", title: "manifest.json is not valid JSON", detail: "d", evidence: [], citation: null };
    const a = parseAnnotation(annotation(f, null));
    // "no file property" is ALSO true of an annotation that failed to parse, so
    // parseability is asserted in the same breath. Without it this check passes
    // on a reporter whose output GitHub would discard entirely.
    check("annotations: a finding with no evidence still parses", a !== null, annotation(f, null));
    check("annotations: ...and gets no file property", a !== null && a.props.file === undefined,
      JSON.stringify(propsOf(annotation(f, null))));
    check("annotations: ...and no line either", a !== null && a.props.line === undefined);
    // THE CONTROL: the same function with a place does emit one, so the check
    // above is not satisfied by annotation() dropping file properties entirely.
    const withFile = propsOf(annotation(f, { file: "sw.js", line: 7 }));
    check("annotations: control, evidence with a place does emit file and line",
      withFile.file === "sw.js" && withFile.line === "7", JSON.stringify(withFile));
    // Evidence with a file but no line is real: the privacy policy check reports
    // a url and a status. A line of "undefined" would point at nothing.
    const noLine = { props: propsOf(annotation(f, { file: "sw.js" })) };
    check("annotations: evidence with a file but no line omits the line",
      noLine.props.file === "sw.js" && noLine.props.line === undefined,
      JSON.stringify(noLine.props));
  }

  // Multi-line details are real in this package, so this is not vacuous.
  check("annotations: a multi-line message is encoded rather than truncated",
    parsed.some((a) => /%0A/.test(a.message)));

  const off = invoke({ WSL_PATH: BAD, WSL_FAIL_ON: "never", WSL_ANNOTATIONS: "false" });
  check("annotations: can be switched off", off.annotations.length === 0);
  check("annotations: ...and the summary is still written", off.summaryText.length > 0);
}

// --- the summary ------------------------------------------------------------

{
  const clean = invoke({ WSL_PATH: CLEAN });
  check("summary: a clean run says so", /No findings/.test(clean.summaryText), clean.summaryText);
  check("summary: ...and does not promise approval",
    /not a promise of approval/.test(clean.summaryText), clean.summaryText);

  const bad = invoke({ WSL_PATH: BAD, WSL_FAIL_ON: "never" });
  check("summary: counts are reported", /4 failing, 8 needing your judgement/.test(bad.summaryText), bad.summaryText);
  check("summary: findings are listed", /remote-code|outside the extension/i.test(bad.summaryText));
  check("summary: the policy citation is linked", /developer\.chrome\.com/.test(bad.summaryText));

  // A pipe in a title would shear the markdown table into a different shape.
  const sheared = summary(
    { root: "x", counts: { fail: 1, warn: 0, info: 0 }, manifestError: null,
      findings: [{ severity: "fail", title: "a | b", evidence: [], citation: null }] },
    null,
  );
  const row = sheared.split("\n").find((l) => /a \\\| b/.test(l));
  check("summary: a pipe in a title is escaped", !!row, sheared);
  // Count cells by splitting on unescaped pipes and dropping the empty strings
  // either side of the leading and trailing delimiter. Empty CELLS in the middle
  // are legitimate here (this finding has no evidence and no citation) and must
  // still be counted, or a sheared row and a correct one score the same.
  const cells = row ? row.split(/(?<!\\)\|/).slice(1, -1) : [];
  check("summary: ...so the row keeps four columns", cells.length === 4, JSON.stringify(cells));
  // THE CONTROL: an unescaped pipe really would score 5, so the check above is
  // measuring the escaping and not just the shape of any row at all.
  check("summary: control, an unescaped pipe would have sheared the row",
    "| FAIL | a | b |  |  |".split(/(?<!\\)\|/).slice(1, -1).length === 5);
}

// --- outputs ----------------------------------------------------------------

{
  const r = invoke({ WSL_PATH: BAD, WSL_FAIL_ON: "never" });
  check("outputs: counts are written for later steps",
    r.outputs.fail === "4" && r.outputs.warn === "8" && r.outputs.info === "0",
    JSON.stringify(r.outputs));
}

// --- exitCodeFor in isolation ----------------------------------------------

{
  const res = (fail, warn, manifestError = null) => ({ counts: { fail, warn, info: 0 }, manifestError });
  check("exitCodeFor: fail tier ignores warnings", exitCodeFor(res(0, 9), "fail") === 0);
  check("exitCodeFor: warn tier catches them", exitCodeFor(res(0, 1), "warn") === 1);
  check("exitCodeFor: never is never", exitCodeFor(res(9, 9), "never") === 0);
  check("exitCodeFor: unreadable beats never", exitCodeFor(res(1, 0, "gone"), "never") === 1);
}

// --- action.yml metadata, which the Marketplace validates before it will list us

// GitHub refused the Marketplace publish on 2026-07-31 for one reason: the
// description was 235 characters against a limit of 125. Nothing in this repo
// could have caught that, because the limit lives at the venue and the file
// reads fine. So the limit is asserted here.
//
// THE EXTRACTOR IS THE PART THAT CAN LIE. "Under 125" is also what you measure
// when you extract nothing at all, so it is exercised on both spellings of the
// field with a known answer before it is pointed at the real file: the old
// folded block must come back at 235, and it must survive being rewritten as a
// quoted one-liner. A guard whose failure mode is silently measuring "" would
// pass forever on any reformat.
const MARKETPLACE_DESCRIPTION_MAX = 125;

function yamlDescription(text) {
  const lines = text.split("\n");
  const i = lines.findIndex((l) => /^description:/.test(l));
  if (i < 0) throw new Error("no top-level description in action.yml");
  const head = lines[i].slice("description:".length).trim();
  if (head && !/^[>|][-+]?$/.test(head)) {
    return head.replace(/^"([\s\S]*)"$/, "$1").replace(/^'([\s\S]*)'$/, "$1");
  }
  const folded = [];
  for (let j = i + 1; j < lines.length; j++) {
    if (!/^\s+\S/.test(lines[j])) break;
    folded.push(lines[j].trim());
  }
  return folded.join(" ");
}

{
  const OLD_FOLDED = [
    "description: >-",
    "  Check an unpacked Chrome extension against the Chrome Web Store program",
    "  policies, including the 1 August 2026 updates. Findings are annotated on the",
    "  offending line and cite Google's own rejection notification ID and verbatim",
    "  policy text.",
    "author: \"Circadian-agent\"",
  ].join("\n");
  check("action.yml: extractor reads a folded block to its real length",
    yamlDescription(OLD_FOLDED).length === 237, `got ${yamlDescription(OLD_FOLDED).length}`);
  check("action.yml: extractor stops at the next key",
    !yamlDescription(OLD_FOLDED).includes("Circadian-agent"));
  check("action.yml: extractor unwraps a quoted one-liner",
    yamlDescription('description: "hello there"') === "hello there");
  check("action.yml: the limit rejects the wording GitHub rejected",
    yamlDescription(OLD_FOLDED).length >= MARKETPLACE_DESCRIPTION_MAX);

  // Read defensively: a missing file must fail this suite, not skip past it.
  let real = null;
  try { real = readFileSync(join(here, "..", "action.yml"), "utf8"); }
  catch (e) { check("action.yml: is readable", false, e.message); }

  if (real) {
    const d = yamlDescription(real);
    check(`action.yml: description fits the Marketplace limit (${d.length} chars)`,
      d.length > 0 && d.length < MARKETPLACE_DESCRIPTION_MAX, d);
    // Outward copy, so the same house rules as every other public surface.
    check("action.yml: description has no em dash or accented characters",
      !/[–—]/.test(d) && !/[^\x00-\x7F]/.test(d), d);
  }
}

console.log(`\nwebstore-lint action: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
