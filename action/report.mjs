#!/usr/bin/env node
// The GitHub Action entry point: run the linter, then say what it found in the
// two places GitHub actually shows a developer.
//
// WHY THIS EXISTS AT ALL, since `npx webstore-lint .` in a `run:` step already
// works. That step puts its answer in the build log, which nobody opens unless
// something is already red. This one writes findings as ANNOTATIONS, so a
// remote-code finding appears on the offending line of popup.html in the pull
// request diff, and as a JOB SUMMARY, so the verdict is on the checks tab. The
// evidence the linter already collects carries a file and a line for exactly
// this, and until now nothing consumed it.
//
// WHY ALL THE LOGIC IS HERE AND THE YAML IS ONE LINE. Shell inside a composite
// action is the least testable surface in the whole package: it cannot be run by
// the suite, and it fails at the worst moment, on somebody else's runner. So
// action.yml does nothing but call this file, and this file is covered by
// test/action.test.mjs like everything else.

import { spawnSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

// Resolved from the env run() is GIVEN, not from process.env at import time.
// Reading it at module scope meant the seam existed but did nothing: the tests
// that point this at a deliberately broken linter went on running the real one
// and passed on a clean fixture, so the check that a failed scan never reports
// green was itself never exercised.
const cliPath = (env) => env.WSL_CLI || join(HERE, "..", "bin", "webstore-lint.mjs");

const FAIL_ON = new Set(["fail", "warn", "never"]);

// A WORKFLOW COMMAND IS NOT PLAIN TEXT. Newlines end the command, so a multi-line
// detail would truncate the annotation and leave the rest of the sentence sitting
// in the build log as if it were output. Percent has to go first or it would
// re-encode the escapes written after it.
const encData = (s) =>
  String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");

// Property values escape two more characters, because the property list is
// comma-separated with colon-terminated keys. A finding titled "Declared but
// never used: bookmarks, downloads" would otherwise be read as extra properties.
const encProp = (s) => encData(s).replace(/:/g, "%3A").replace(/,/g, "%2C");

export function annotation(f, e) {
  const level = f.severity === "fail" ? "error" : f.severity === "warn" ? "warning" : "notice";
  const props = [`title=${encProp(`webstore-lint: ${f.title}`)}`];
  // Not all evidence is a place in a file. The privacy policy check's evidence is
  // a url and an HTTP status, and a manifest-level finding has no evidence at
  // all. GitHub accepts an annotation with no file, and inventing one would point
  // a developer at a line that has nothing to do with the finding.
  if (e?.file) {
    props.push(`file=${encProp(e.file)}`);
    if (e.line) {
      props.push(`line=${encProp(e.line)}`);
      props.push(`col=1`);
    }
  }
  const cite = f.citation?.notificationIds?.length
    ? ` [${f.citation.notificationIds.join(", ")}]`
    : "";
  // Google's policy page first, because it is the authority; the explainer
  // second, because it is what the codename actually means and how to fix it.
  const body = [f.detail, f.citation?.policyUrl, f.citationUrl].filter(Boolean).join("\n");
  return `::${level} ${props.join(",")}::${encData(`${f.title}${cite}\n${body}`)}`;
}

// The summary footer dates the policy data, so a reader can tell a stale build
// from a current one. It is cosmetic, and a build with an unreadable data file
// should still report its findings, so a failure here drops the footer rather
// than the report.
function readPolicyMeta() {
  try {
    const p = JSON.parse(readFileSync(join(HERE, "..", "data", "policy.json"), "utf8"));
    return { datasetPulledAt: p.datasetPulledAt, enforcedFrom: p.enforcedFrom };
  } catch {
    return null;
  }
}

export function summary(result, policy) {
  const { fail, warn, info } = result.counts;
  const lines = [];
  lines.push(`## webstore-lint`);
  lines.push("");
  if (result.manifestError) {
    lines.push(`**The extension could not be read.** ${result.manifestError}`);
    lines.push("");
    lines.push(
      "Nothing was checked, so this is not a clean result. Point the action at the " +
        "directory holding manifest.json with the `path` input.",
    );
    return lines.join("\n");
  }
  lines.push(
    `**${fail} failing, ${warn} needing your judgement, ${info} informational** in \`${result.root}\``,
  );
  lines.push("");
  if (!result.findings.length) {
    lines.push("No findings. This reads your package only. Your store listing, privacy policy page");
    lines.push("and screenshots are where several policies are actually satisfied, and no local");
    lines.push("tool can see them, so a clean run is not a promise of approval.");
    return lines.join("\n");
  }
  const MARK = { fail: "FAIL", warn: "WARN", info: "INFO" };
  lines.push("| | Finding | Where | Policy |");
  lines.push("|---|---|---|---|");
  for (const f of result.findings) {
    const where = (f.evidence || [])
      .slice(0, 3)
      .map((e) => (e.file ? `\`${e.file}${e.line ? ":" + e.line : ""}\`` : ""))
      .filter(Boolean)
      .join(" ");
    const more = (f.evidence || []).length > 3 ? ` +${f.evidence.length - 3}` : "";
    // The codename links to Google, who decide; "explained" links to our page
    // for that exact codename. Both, never one instead of the other - replacing
    // the authority with ourselves would be the wrong trade in a compliance tool.
    const cite = f.citation?.notificationIds?.length
      ? `[${f.citation.notificationIds.join(", ")}](${f.citation.policyUrl})` +
        (f.citationUrl ? ` - [explained](${f.citationUrl})` : "")
      : "";
    // A pipe inside a cell would start a new column and shear the table.
    const cell = (s) => String(s).replace(/\|/g, "\\|").replace(/\n/g, " ");
    lines.push(`| ${MARK[f.severity]} | ${cell(f.title)} | ${where}${more} | ${cite} |`);
  }
  lines.push("");
  if (policy?.enforcedFrom) {
    lines.push(`Policy data pulled ${policy.datasetPulledAt}, ${policy.enforcedFrom} updates included.`);
  }
  lines.push("");
  lines.push("Run it yourself: `npx webstore-lint ./my-extension`");
  return lines.join("\n");
}

// EXIT CODE. `fail-on` governs FINDINGS, and an unreadable extension is not a
// finding - it is the tool not having done its job. So it fails whatever
// `fail-on` says. The alternative is that somebody types the path wrong, sets
// `fail-on: never` for advisory annotations, and gets a green check on an
// extension that was never opened. This package's own rule, from bin/: a tool
// that says "clean" about a question it never answered is worse than one that
// refuses.
export function exitCodeFor(result, failOn) {
  if (result.manifestError) return 1;
  if (failOn === "never") return 0;
  if (failOn === "warn") return result.counts.fail + result.counts.warn ? 1 : 0;
  return result.counts.fail ? 1 : 0;
}

export function run({ env = process.env, out = console.log, err = console.error } = {}) {
  const failOn = (env.WSL_FAIL_ON || "fail").trim();
  // Same reasoning as the CLI's unknown-flag check, applied at a new call site:
  // a value we do not recognise must not quietly become the default. "failure",
  // "true" and "all" are all things a person would plausibly type here, and each
  // of them silently meaning "fail" is a build that does not block when its
  // author believes it does.
  if (!FAIL_ON.has(failOn)) {
    err(`fail-on: ${JSON.stringify(failOn)} is not one of ${[...FAIL_ON].join(", ")}.`);
    err(`Nothing was checked. Fix the value in your workflow file.`);
    return 2;
  }
  const annotate = (env.WSL_ANNOTATIONS || "true").trim() !== "false";

  const args = [cliPath(env), env.WSL_PATH || ".", "--json"];
  const url = (env.WSL_PRIVACY_POLICY || "").trim();
  if (url) args.push("--privacy-policy", url);

  const r = spawnSync(process.execPath, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });

  // THE LOAD-BEARING CHECK. "No findings" and "the linter never produced a
  // report" print the same empty list if you are careless, and the second one
  // must never come out green. So the report is only believed when it parses and
  // carries the counts object the linter always writes; anything else is the
  // scan having failed, and it is reported as that rather than as a clean run.
  let result = null;
  try {
    const parsed = JSON.parse(r.stdout);
    if (parsed && typeof parsed === "object" && parsed.counts && typeof parsed.counts.fail === "number") {
      result = parsed;
    }
  } catch {
    /* handled below */
  }
  if (!result) {
    err("webstore-lint did not produce a report, so nothing was checked.");
    if (r.error) err(String(r.error.message || r.error));
    if (r.stderr) err(r.stderr.trim());
    if (r.stdout) err(`unparsed output: ${r.stdout.slice(0, 2000)}`);
    err(`exit code was ${r.status}`);
    return 1;
  }

  if (annotate) {
    for (const f of result.findings) {
      const ev = (f.evidence || []).length ? f.evidence.slice(0, 10) : [null];
      for (const e of ev) out(annotation(f, e));
    }
  }

  const md = summary(result, readPolicyMeta());
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, md + "\n");
  else out(md);

  if (env.GITHUB_OUTPUT) {
    const { fail, warn, info } = result.counts;
    appendFileSync(
      env.GITHUB_OUTPUT,
      `fail=${fail}\nwarn=${warn}\ninfo=${info}\nunreadable=${result.manifestError ? "true" : "false"}\n`,
    );
  }

  const code = exitCodeFor(result, failOn);
  if (code === 1 && result.manifestError) {
    err(`The extension could not be read, so nothing was checked: ${result.manifestError}`);
  }
  return code;
}

// Only act when run as a program. Imported by the test suite, where exiting the
// process would take the suite with it.
if (process.argv[1] && process.argv[1].endsWith("report.mjs")) process.exit(run());
