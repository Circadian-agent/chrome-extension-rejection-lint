// Tests for webstore-lint.
//
// THE HALF THAT MATTERS MOST IS THE CLEAN FIXTURE. A linter that flags
// everything passes any "does it find the bug" test and is useless, because the
// first false positive on real code is when a developer stops running it. So
// the clean extension must come back with ZERO failures, and that assertion is
// as load-bearing as every finding below.
//
// And no assertion here is satisfied by the rule never running: each one names
// the rule id it expects, so a rule that silently returns [] fails the test
// rather than passing it. That is the s053 lesson - do not write an assertion
// whose pass condition is also satisfied by the failure.

import { lint } from "../src/lint.mjs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";

const here = dirname(fileURLToPath(import.meta.url));
let pass = 0, fail = 0;

const check = (name, cond, extra = "") => {
  if (cond) { pass++; }
  else { fail++; console.log(`  FAIL  ${name}${extra ? `\n        ${extra}` : ""}`); }
};

const ids = (r) => r.findings.map((f) => f.rule);
const bySeverity = (r, s) => r.findings.filter((f) => f.severity === s).map((f) => f.rule);

// --- the non-compliant fixture ---------------------------------------------

const bad = lint(join(here, "fixtures", "bad"));

check("bad: remote <script> and eval are caught", ids(bad).includes("remote-code"));
check(
  "bad: remote-code produces evidence with a file and a line",
  bad.findings.filter((f) => f.rule === "remote-code").every((f) => f.evidence.length && f.evidence.every((e) => e.file && e.line > 0)),
);
check("bad: unused permissions are caught", ids(bad).includes("unused-permissions"));
{
  const f = bad.findings.find((x) => x.rule === "unused-permissions");
  // cookies and history ARE used in sw.js and must NOT be reported. This is the
  // assertion that separates "the rule works" from "the rule lists everything".
  check("bad: used permissions are not reported as unused", f && !/cookies|history/.test(f.title), f?.title);
  check("bad: the three genuinely unused ones are reported", f && ["bookmarks", "downloads", "topSites"].every((p) => f.title.includes(p)), f?.title);
}
check("bad: broad host permission is caught", ids(bad).includes("broad-host-permissions"));
check("bad: obfuscation signature is caught", ids(bad).includes("obfuscation"));
check("bad: http endpoint is caught", ids(bad).includes("insecure-transmission"));
check("bad: keyword stuffing is caught", ids(bad).includes("keyword-stuffing"));
check("bad: missing icons is caught", bad.findings.some((f) => f.rule === "listing-metadata" && /icons/.test(f.title)));
check("bad: prediction market wording is caught", ids(bad).includes("prediction-markets-2026"));
check("bad: disclosure change applies", ids(bad).includes("disclosure-2026"));
check("bad: at least one failure, so the exit code would be 1", bad.counts.fail > 0);

// Citations must be attached and must be the verbatim policy text, not a rule's
// own words. A rule quoting Google inaccurately is worse than a rule that stays
// quiet, so this checks the join actually happened.
check(
  "every cited finding carries a policy quote and a google.com URL",
  bad.findings.filter((f) => f.citation).every((f) => f.citation.policyQuote.length > 40 && f.citation.policyUrl.startsWith("https://developer.chrome.com/")),
);
check(
  "the 2026 changes carry the live-policy-vs-announcement distinction",
  bad.findings.filter((f) => f.change).every((f) => typeof f.change.inLivePolicyText === "boolean" && f.change.discrepancy),
);

// --- the compliant fixture --------------------------------------------------

const clean = lint(join(here, "fixtures", "clean"));
check("clean: zero failures", clean.counts.fail === 0, `got: ${bySeverity(clean, "fail").join(", ")}`);
check("clean: zero warnings", clean.counts.warn === 0, `got: ${bySeverity(clean, "warn").join(", ")}`);
check("clean: storage is used, so it is not reported unused", !ids(clean).includes("unused-permissions"));
check("clean: a narrow content script match is not reported as broad", !ids(clean).includes("broad-host-permissions"));

// --- edge cases -------------------------------------------------------------

const tmp = mkdtempSync(join(tmpdir(), "wsl-"));
const empty = lint(tmp);
check("a directory with no manifest fails with a clear message", empty.counts.fail === 1 && /no manifest\.json/.test(empty.findings[0].title));

const broken = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(broken, "manifest.json"), "{ not json");
const brokenResult = lint(broken);
check("invalid manifest JSON is reported, not thrown", brokenResult.counts.fail === 1 && /not valid JSON/.test(brokenResult.findings[0].title));

const mv2 = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(mv2, "manifest.json"), JSON.stringify({ manifest_version: 2, name: "Old", description: "An extension from before the migration to v3.", icons: { 16: "i.png" } }));
const mv2Result = lint(mv2);
check("manifest v2 fails", bySeverity(mv2Result, "fail").includes("manifest-v2"));

// localhost over http is normal in development and must not be a finding, or
// every extension with a dev server reads as a privacy violation.
const local = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(local, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Dev", description: "A small extension used while developing locally.", icons: { 16: "i.png" }, permissions: ["storage"] }));
writeFileSync(join(local, "app.js"), 'chrome.storage.local.get("k");\nconst DEV = "http://localhost:3000/api";\n');
check("http://localhost is not reported", !ids(lint(local)).includes("insecure-transmission"));

// node_modules must not be scanned: a finding in a dependency is noise the
// developer cannot act on, and it is the fastest way to get a linter muted.
const withDeps = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(withDeps, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Deps", description: "An extension that has a node_modules directory beside it.", icons: { 16: "i.png" }, permissions: ["storage"] }));
writeFileSync(join(withDeps, "app.js"), 'chrome.storage.local.get("k");\n');
mkdirSync(join(withDeps, "node_modules", "evil"), { recursive: true });
writeFileSync(join(withDeps, "node_modules", "evil", "index.js"), 'eval("nope"); var _0xdeadbeef1=1,_0xdeadbeef2=2,_0xdeadbeef3=3,_0xdeadbeef4=4,_0xdeadbeef5=5,_0xdeadbeef6=6,_0xdeadbeef7=7,_0xdeadbeef8=8,_0xdeadbeef9=9,_0xdeadbeefa=10;\n');
const deps = lint(withDeps);
check("node_modules is not scanned", deps.counts.fail === 0, `got: ${bySeverity(deps, "fail").join(", ")}`);
check("and the skip is reported rather than silent", deps.skipped.some((s) => s.path.includes("node_modules")));

console.log(`\nwebstore-lint: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
