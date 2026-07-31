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

import { lint, auditPermissions } from "../src/lint.mjs";
import { stripComments, stripCommentsChunk, initialCommentState, excerptAround, grep } from "../src/scan.mjs";
import { PERMISSION_API, NO_NAMESPACE_PERMISSIONS } from "../src/audit.mjs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
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

// ---------------------------------------------------------------------------
// TWO FALSE POSITIVES FOUND BY RUNNING THIS TOOL AGAINST REAL THIRD-PARTY
// EXTENSIONS (tools/lint_corpus.mjs) RATHER THAN AGAINST FIXTURES WE WROTE.
// Both had passed every test here for the tool's whole life, because the shapes
// that trigger them do not occur in our own fixtures.
//
// Each fix is paired with a control that must fire BOTH before and after it.
// That is the difference between a control set and a regression detector: the
// negative case alone would also pass if the rule stopped working entirely.

// (1) `$` is a valid JS identifier character, so `$eval(` is one identifier and
// not a call to eval. Fired `fail` on every AngularJS package.
const dollarEval = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(dollarEval, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Angular", description: "An extension built on an AngularJS scope evaluator.", icons: { 16: "i.png" }, permissions: ["storage"] }));
writeFileSync(join(dollarEval, "app.js"), 'chrome.storage.local.get("k");\nconst h = scope.$eval(attrs.customOnChange);\n');
check("$eval( is not reported as eval(", !ids(lint(dollarEval)).includes("remote-code"));

// THE CONTROLS: real string execution must still fail. If either of these ever
// goes quiet, the narrowing above swallowed the rule rather than a false hit.
const realEval = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(realEval, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Evaller", description: "An extension that executes a string as code at runtime.", icons: { 16: "i.png" }, permissions: ["storage"] }));
writeFileSync(join(realEval, "app.js"), 'chrome.storage.local.get("k");\neval(userSupplied);\n');
check("CONTROL: a bare eval( still fails", bySeverity(lint(realEval), "fail").includes("remote-code"));

const newFn = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(newFn, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Constructor", description: "An extension that builds a function from a string at runtime.", icons: { 16: "i.png" }, permissions: ["storage"] }));
writeFileSync(join(newFn, "app.js"), 'chrome.storage.local.get("k");\nreturn new Function("return " + obj.__value)();\n');
check("CONTROL: new Function( still fails", bySeverity(lint(newFn), "fail").includes("remote-code"));

// ---------------------------------------------------------------------------
// (1b) T-0414, FOUND ON SHIPPED RELEASE PACKAGES rather than source trees.
// `new Function("return this")` is webpack's globalThis shim and a method named
// `eval` is a definition, not a call. Between them they were the SOLE evidence
// behind 8 of 23 remote-code FAILs on real published extensions.
const mkExt = (name, desc, files) => {
  const d = mkdtempSync(join(tmpdir(), "wsl-"));
  writeFileSync(join(d, "manifest.json"), JSON.stringify({ manifest_version: 3, name, description: desc, icons: { 16: "i.png" }, permissions: ["storage"] }));
  for (const [f, body] of Object.entries(files)) writeFileSync(join(d, f), body);
  return d;
};
const rcFail = (dir) => lint(dir).findings.find((f) => f.rule === "remote-code" && f.severity === "fail" && /eval|Function/.test(f.title));

const shimOnly = mkExt("Bundled", "An extension bundled with webpack and nothing else.", {
  "app.js": 'chrome.storage.local.get("k");\nr.g=function(){if("object"==typeof globalThis)return globalThis;try{return this||new Function("return this")()}catch(e){}}();\n',
});
check("the webpack globalThis shim alone is not a remote-code FAIL", !rcFail(shimOnly));

// THE ONE THAT MATTERS. grep() takes one match per line and a bundle is ONE
// LINE, so before this fix the shim was the only site a developer ever saw and
// the real call after it was never reported. The assertion is on the reported
// MATCH TEXT, because "a fail is still produced" would also pass if the tool had
// simply gone on reporting the shim - the failure and the success look the same
// at the level of rule ids. Only the fix can make this say eval(.
const masked = mkExt("Masked", "An extension whose bundle carries a shim and a real call.", {
  "app.js": 'chrome.storage.local.get("k");\nvar r={};r.g=function(){try{return this||new Function("return this")()}catch(e){}}();var out=eval(fetchedFromServer);\n',
});
{
  const f = rcFail(masked);
  check("a real eval AFTER the shim on the same line is still a FAIL", Boolean(f), JSON.stringify(ids(lint(masked))));
  check("and the site reported is the eval, not the shim it sat behind",
    /^eval\s*\(/.test(f?.evidence?.[0]?.match?.replace(/^[^\w$]/, "") || ""), JSON.stringify(f?.evidence?.[0]?.match));
}

const evalMethod = mkExt("Compiler", "An extension embedding a CSS compiler whose AST nodes declare eval.", {
  "app.js": 'chrome.storage.local.get("k");\nclass Paren extends Node{genCSS(e,t){t.add("(")}eval(e){return new Paren(this.value.eval(e))}};\n',
});
check("a method DEFINITION named eval is not a remote-code FAIL", !rcFail(evalMethod));

// CONTROLS for both narrowings. Each must fire, and each is a shape the
// exclusion above deliberately does not cover - a prefix match or a loose
// method test would swallow these and the tool would go quiet on real code.
const shimLookalike = mkExt("Lookalike", "An extension building a function from something other than a literal.", {
  "app.js": 'chrome.storage.local.get("k");\nvar f=new Function("return fetch(" + url + ")");\n',
});
check("CONTROL: new Function with any OTHER string still fails", Boolean(rcFail(shimLookalike)));

const defAndCall = mkExt("Both", "An extension that both declares an eval method and calls global eval.", {
  "app.js": 'chrome.storage.local.get("k");\nclass N{eval(e){return this}};\nvar out=eval(userCode);\n',
});
check("CONTROL: an eval CALL beside an eval definition still fails", Boolean(rcFail(defAndCall)));

// ---------------------------------------------------------------------------
// (1c) T-0416. `eval()` with an EMPTY argument list executes nothing and returns
// undefined, so it is provably not string execution - the same kind of local,
// per-match proof as the two skips above. It is how scriptcat came to FAIL:
// the package bundles ESLint's own rule metadata, whose text is
// "Disallow the use of `eval()`".
//
// This is the ONLY part of T-0416 that got fixed, and the rest is refused on
// measurement rather than taste. The proposal was to blank plain string literals
// so that inert text stops firing. Probed over the 82 cached release packages
// that reclassified 28 sites, of which only FOUR were the inert text it aimed at:
// six were real violations a quote-tracking scan had misread, and eighteen were
// executable source deliberately embedded as a string. The control that settles
// it is inside ONE package - screenity ships the same bundled library twice,
// byte-identical but for minifier variable names, and a quote-tracking scan calls
// `new Function(x[P])(window)` code and `new Function(k[E])(window)` a string.
// Identical code, two answers. See the comment in rules.mjs.
const evalNoArgs = mkExt("Linter", "An extension bundling a javascript linter with rule metadata in it.", {
  "app.js": 'chrome.storage.local.get("k");\nconst meta={description:"Disallow the use of `eval()`",url:"https://eslint.org/docs/latest/rules/no-eval"};\n',
});
check("eval() with no arguments is not a remote-code FAIL", !rcFail(evalNoArgs));

// CONTROL, and it is the one that stops the skip widening into "eval in a
// string is fine": HackTools ships this exact payload as cheat-sheet UI text and
// it is LEFT FAILING, because nothing local separates it from a genuine call.
const evalInString = mkExt("Cheatsheet", "An extension listing cross site scripting payloads as reference text.", {
  "app.js": 'chrome.storage.local.get("k");\nconst payloads=[{title:"eval(\'ale\'+\'rt(0)\');"}];\n',
});
check("CONTROL: eval( with arguments inside a string still fails", Boolean(rcFail(evalInString)));

// ---------------------------------------------------------------------------
// (1d) "NO REMOTE CODE FOUND" IS A CLAIM ABOUT ALL THE CODE. scan.mjs does not
// read a file over 2 MB, and this rule used to go silent as though the package
// were clean. Measured on the 82 cached release packages: 23 skip a file for
// size, 13 of those produced no remote-code failure, and in three an unread file
// holds a site this rule would report - return-youtube-dislike ships
// `new Function('return (' + source + ');')()` in a 4.0 MB content script.
const bigUnread = mkExt("Bundled", "An extension whose service worker is a single large bundle.", {
  "app.js": 'chrome.storage.local.get("k");\n',
  // Over the 2 MB limit, and carrying a real violation the scan will never see.
  "background.js": `var pad="${"x".repeat(2 * 1024 * 1024)}";\nvar f=new Function('return ('+source+');')();\n`,
});
// v1.0.11 made the rule SAY it could not read the file. T-0417 makes it read
// it: grepLarge slides a window over the file instead of holding it, so the
// site below is reported at the same severity it would carry in a 4 KB file.
{
  const r = lint(bigUnread);
  const rc = r.findings.filter((f) => f.rule === "remote-code");
  const failed = rc.find((f) => f.severity === "fail" && /eval|Function/.test(f.title));
  // Assert on the SITE, not on "a fail exists": a fail with the wrong file and
  // line is what a broken offset would produce, and it reads identically.
  check("a violation past the 2 MB read limit is reported at fail", Boolean(failed),
    JSON.stringify(rc.map((f) => f.severity + ":" + f.title)));
  const site = failed?.evidence?.find((e) => e.file === "background.js");
  check("...naming the oversized file it was found in", Boolean(site),
    JSON.stringify(failed?.evidence));
  // The padding is one line, so the site is on line 2 of the file. Only a
  // correct newline count across the sliding window produces that number.
  check("...at the right line, counted across the window boundary", site?.line === 2, `line ${site?.line}`);
  check("...quoting the call as evidence", /new Function/.test(site?.text || ""), site?.text);
  // The honesty warning must now be GONE for this file. Saying "could not check"
  // about a file it did check sends a developer hunting by hand for a site the
  // tool already found.
  check("...and the file is no longer listed as unchecked",
    !rc.some((f) => f.severity === "warn" && /too large/i.test(f.title)),
    JSON.stringify(rc.map((f) => f.severity + ":" + f.title)));
}

// CONTROL: the streaming pass must not invent findings. Same oversized file,
// same size, no violation in it - and no fail. Without this the test above is
// satisfied by a rule that fails on every large file.
const bigClean = mkExt("BundledClean", "An extension whose service worker is a single large bundle with no eval in it.", {
  "app.js": 'chrome.storage.local.get("k");\n',
  "background.js": `var pad="${"x".repeat(2 * 1024 * 1024)}";\nvar f=JSON.parse(source);\n`,
});
check("CONTROL: an oversized file with no violation produces no remote-code fail",
  !lint(bigClean).findings.some((f) => f.rule === "remote-code" && f.severity === "fail"),
  JSON.stringify(lint(bigClean).findings.filter((f) => f.rule === "remote-code").map((f) => f.severity + ":" + f.title)));

// CONTROL: comments are blanked in the streaming pass exactly as in the whole-file
// one. Fannon/search-bookmarks was failed on a comment saying the code does NOT
// use eval; that must not come back just because the file is large.
const bigComment = mkExt("BundledComment", "An extension whose large bundle mentions eval only in a comment.", {
  "app.js": 'chrome.storage.local.get("k");\n',
  "background.js": `var pad="${"x".repeat(2 * 1024 * 1024)}";\n// a CSP-safe validator that does not require eval() or Function()\n`,
});
check("CONTROL: a comment inside an oversized file is not a violation",
  !lint(bigComment).findings.some((f) => f.rule === "remote-code" && f.severity === "fail"));

// CONTROL: a package with nothing skipped must NOT carry the disclosure, or it
// would appear on every clean report and mean nothing.
const allRead = mkExt("Small", "An extension whose files are all small enough to read.", {
  "app.js": 'chrome.storage.local.get("k");\n',
});
check("CONTROL: a fully-read package carries no unread-file warning",
  !lint(allRead).findings.some((f) => f.rule === "remote-code"));

// ---------------------------------------------------------------------------
// (1e) THE STREAMING COMMENT STRIPPER IS THE SAME CODE AS THE WHOLE-FILE ONE,
// and this is what holds it to that. stripComments() is a single call to the
// chunk stepper, so the risk is not two implementations drifting - it is the
// SEAM: a chunk boundary falling through the middle of a construct that needs
// lookahead. One of those was real and cost six of 400 live bundles - a `*/`
// whose asterisk was blanked in one chunk, leaving the next chunk hunting for a
// closer that no longer existed, so the block comment swallowed the rest of the
// file. The others are here because the same shape is available to them.
//
// The assertion is AGREEMENT between two runs that differ only in chunk size,
// which is a difference that must not matter. Agreement alone is satisfied by
// both sides doing nothing, so every case also asserts that the output really
// is shorter in visible characters than the input - i.e. something was blanked.
{
  const streamed = (text, size) => {
    let st = initialCommentState(), held = "", out = "";
    for (let p = 0; p < text.length; p += size) {
      const chunk = held + text.slice(p, p + size);
      const r = stripCommentsChunk(chunk, st, { atEof: p + size >= text.length });
      out += r.out; held = r.held; st = r.state;
    }
    return out + held;
  };
  const seam = [
    ["a block comment closing across the seam", `var a=1;/*${"c".repeat(40)}*/var b=2;/*x*/`],
    ["a line comment running up to the seam", `var a=1;//${"c".repeat(60)}\nvar b=2;//y`],
    ["an escaped quote straddling the seam", `var s="${"a".repeat(38)}\\"still in the string//not a comment";/*x*/var b=2;`],
    ["a template literal with an escaped backtick", "var s=`" + "a".repeat(38) + "\\`still in it//no`;/*x*/var b=2;"],
    ["a regex literal containing a slash in a class", `var r=/${"a".repeat(36)}[/]x/;/*x*/var b=2;`],
    ["a division that is not a regex", `var q=${"a".repeat(38)}/2;/*x*/var b=2;`],
  ];
  for (const [name, text] of seam) {
    const whole = stripComments(text);
    check(`stripComments blanks something in: ${name}`, whole !== text, JSON.stringify(whole));
    check(`stripComments preserves length in: ${name}`, whole.length === text.length);
    // EVERY chunk size from 1 up, not a chosen few. These literals are under 120
    // characters so exhaustive is cheap, and picking sizes by hand is how the
    // first version of this test missed a mutant entirely: the seam has to land
    // on one specific character to expose each bug, and guessing which one is
    // the same mistake as guessing where a bug is.
    const bad = [];
    for (let size = 1; size <= text.length; size++) if (streamed(text, size) !== whole) bad.push(size);
    check(`stripComments agrees whole-file and streamed at every chunk size: ${name}`, !bad.length,
      `disagrees at ${bad.slice(0, 8).join(",")}`);
  }
}

// (2) XML namespace URIs are identifiers, never endpoints. The http:// spelling
// is fixed by the spec, so this told people to change a string that would break
// their SVG. 6 of 7 insecure-transmission hits across the real corpus were this.
const svgNs = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(svgNs, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Drawing", description: "An extension that renders inline SVG into the page.", icons: { 16: "i.png" }, permissions: ["storage"] }));
writeFileSync(join(svgNs, "app.js"), 'chrome.storage.local.get("k");\nconst el = document.createElementNS("http://www.w3.org/2000/svg", "svg");\nconst m = \'<svg xmlns="http://www.w3.org/1999/xhtml">\';\n');
check("XML namespace URIs are not reported as insecure endpoints",
  !ids(lint(svgNs)).includes("insecure-transmission"));

// THE CONTROL: a genuinely insecure endpoint must still warn. Taken verbatim
// from the corpus - listen1 really does call this over plain http.
const realHttp = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(realHttp, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Player", description: "An extension that fetches track metadata from a remote api.", icons: { 16: "i.png" }, permissions: ["storage"] }));
writeFileSync(join(realHttp, "app.js"), 'chrome.storage.local.get("k");\nconst t = "http://api.bilibili.com/x/player/playurl";\n');
check("CONTROL: a real http:// endpoint still warns", ids(lint(realHttp)).includes("insecure-transmission"));

// AND THE MIXED CASE, which is the one that actually matters: a package holding
// both must still report the endpoint. A filter that drops the whole finding
// when any namespace is present would pass both checks above and still be wrong.
const mixed = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(mixed, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Both", description: "An extension that draws svg and also calls a plain http api.", icons: { 16: "i.png" }, permissions: ["storage"] }));
writeFileSync(join(mixed, "app.js"), 'chrome.storage.local.get("k");\ndocument.createElementNS("http://www.w3.org/2000/svg", "svg");\nfetch("http://api.example.com/track");\n');
const mixedResult = lint(mixed);
check("CONTROL: the endpoint is still reported when a namespace sits beside it",
  ids(mixedResult).includes("insecure-transmission"));
check("and the namespace is not among the evidence",
  !JSON.stringify(mixedResult.findings.find((f) => f.rule === "insecure-transmission")?.evidence || [])
    .includes("w3.org"));

// (3) The same case as (2), missed by it and caught by running the PUBLISHED
// tool afterwards: a DOCTYPE system identifier names a grammar and is fixed by
// the specification. The local corpus had already gone quiet on namespaces, so
// only the end-to-end run surfaced this one.
const dtd = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(dtd, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Doctype", description: "An extension shipping a page with an svg doctype in it.", icons: { 16: "i.png" }, permissions: ["storage"] }));
writeFileSync(join(dtd, "app.js"), 'chrome.storage.local.get("k");\n');
writeFileSync(join(dtd, "page.html"), '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">\n');
check("a DOCTYPE system identifier is not reported as an insecure endpoint",
  !ids(lint(dtd)).includes("insecure-transmission"));

// THE CONTROL for the narrowness of that exclusion: w3.org is not blanket
// allowed. A plain-http link to a w3.org document is still a plain-http link.
const w3doc = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(w3doc, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Linker", description: "An extension that links out to a specification document.", icons: { 16: "i.png" }, permissions: ["storage"] }));
writeFileSync(join(w3doc, "app.js"), 'chrome.storage.local.get("k");\nconst spec = "http://www.w3.org/TR/webstorage/";\n');
check("CONTROL: a plain-http w3.org document link is still reported",
  ids(lint(w3doc)).includes("insecure-transmission"));

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

// --- access to every site counts wherever it is DECLARED ---------------------
//
// A manifest can ask for every site from three different keys, and disclosure-2026
// used to read only host_permissions. So two extensions with identical access got
// different answers about the 1 August disclosure rule depending on spelling, and
// the shape that was told nothing - content_scripts with no host_permissions at
// all - is the common MV3 one. Found by running it, not by reading it.
//
// The three manifests below differ ONLY in which key carries "every site".

const everySite = (key) => {
  const dir = mkdtempSync(join(tmpdir(), "wsl-"));
  const base = { manifest_version: 3, name: "Reader", version: "1.0.0", description: "Highlights text on the pages you visit and saves your highlights.", icons: { 16: "i.png" } };
  const shapes = {
    host_permissions: { host_permissions: ["<all_urls>"] },
    content_scripts: { content_scripts: [{ matches: ["<all_urls>"], js: ["content.js"] }] },
    permissions: { permissions: ["https://*/*"] },
  };
  writeFileSync(join(dir, "manifest.json"), JSON.stringify({ ...base, ...shapes[key] }));
  writeFileSync(join(dir, "content.js"), "document.title;\n");
  return lint(dir);
};

const shapes = ["host_permissions", "content_scripts", "permissions"].map((k) => [k, everySite(k)]);

for (const [key, r] of shapes) {
  // Named rule id, so a rule that silently returns [] fails rather than passes.
  check(`every-site access via ${key} triggers the 1 August disclosure rule`, ids(r).includes("disclosure-2026"));
  check(`every-site access via ${key} triggers the broad-host rule`, ids(r).includes("broad-host-permissions"));
  // Evidence must name the pattern, because the fix is in whichever key they
  // actually wrote and an empty evidence list sends them looking in the wrong one.
  const f = r.findings.find((x) => x.rule === "disclosure-2026");
  check(
    `and the ${key} finding carries the host pattern as evidence`,
    f && f.evidence.some((e) => /<all_urls>|https:\/\/\*/.test(e.text)),
    f ? JSON.stringify(f.evidence.map((e) => e.text)) : "no finding",
  );
}

// The whole point is that they AGREE. Comparing the rule sets catches a future
// rule drifting the same way disclosure-2026 did.
check(
  "all three spellings of every-site access produce the same findings",
  new Set(shapes.map(([, r]) => ids(r).slice().sort().join(","))).size === 1,
  shapes.map(([k, r]) => `${k}: ${ids(r).sort().join("+")}`).join("  |  "),
);

// THE NOISE CONTROL, and it is why narrow matches are deliberately excluded: the
// clean fixture is a reading-time extension with a content script on ONE site.
// If that fired, the rule would fire on almost every extension in the store.
// Asserting the manifest parsed keeps "no finding" from being satisfied by a
// lint that never ran - the same trap the header warns about.
check("the clean fixture's manifest really was read", clean.manifest?.name === "Reading Time");
check("a NARROW content script is not treated as user data in scope", !ids(clean).includes("disclosure-2026"));

// --- where the line breaks fall must not change the answer -------------------
//
// remote-code is the highest-severity rule in the tool and the first trigger
// Google names for MV3. It searched line by line, so a long <script src="...">
// WRAPPED ACROSS LINES - which is what a formatter does to it - was invisible,
// and the extension came back clean. Same shape as the disclosure-2026 bug:
// two inputs differing in one way that should not matter, disagreeing.

const html = (body) => {
  const dir = mkdtempSync(join(tmpdir(), "wsl-"));
  writeFileSync(join(dir, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Fmt", version: "1.0.0", description: "An extension used to compare two spellings of the same page.", icons: { 16: "i.png" } }));
  writeFileSync(join(dir, "popup.html"), body);
  return lint(dir);
};

const oneLine = html('<html><body><script src="https://cdn.example.com/x.js"></script></body></html>\n');
const wrapped = html('<html><body>\n<script\n  src="https://cdn.example.com/x.js">\n</script>\n</body></html>\n');

check("a remote script on one line is caught", ids(oneLine).includes("remote-code"));
check("a remote script wrapped across lines is caught too", ids(wrapped).includes("remote-code"));
check(
  "both are the same severity, so formatting cannot downgrade a fail",
  bySeverity(oneLine, "fail").includes("remote-code") && bySeverity(wrapped, "fail").includes("remote-code"),
);
// The evidence must point at the line the tag OPENS on, not at the file.
{
  // Reached through optional chaining on purpose: when this regresses there is
  // no finding at all, and a test that THROWS there takes the rest of the suite
  // down with it instead of reporting one clean failure.
  const e = wrapped.findings.find((f) => f.rule === "remote-code")?.evidence?.[0];
  check("the wrapped match is attributed to the line the tag opens on", e && e.file === "popup.html" && e.line === 2, JSON.stringify(e));
}

// THE FALSE-POSITIVE CONTROL, and it is why the pattern was NOT widened to
// [\s\S]. A remote image is not remote code. A lazy any-character match would
// run from an inline <script> past its closing > and match the <img> src, which
// would turn every page with a CDN logo into a policy failure - and a fail that
// is wrong is worse here than a miss, because it is the one people mute.
const remoteImg = html('<html><body>\n<script>var a = 1;</script>\n<img src="https://cdn.example.com/logo.png">\n</body></html>\n');
check("the manifest was read, so a silent result means the rules ran", remoteImg.manifest?.name === "Fmt");
check("a remote IMAGE is not reported as remote code", !ids(remoteImg).includes("remote-code"));

// --- the permission ledger (src/audit.mjs) ----------------------------------
//
// THE LOAD-BEARING HALF HERE IS THE NEGATIVE CASE. A narrowing suggestion is
// advice to DELETE a permission, so a false one breaks a working extension.
// Every suggestion below is therefore tested twice: once where it must fire,
// and once on code where firing would be wrong.

const ledgerOf = (dir) => auditPermissions(dir).audit;
const permStatus = (a, name) => a.ledger.find((l) => l.permission === name)?.status;
const narrowedFrom = (a) => a.narrowings.map((n) => n.from);

// tabs -> activeTab, where every call site reads the tab the user acted on.
const gestureTabs = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(gestureTabs, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Gesture", description: "Acts on the tab you are looking at when you click the button.", icons: { 16: "i.png" }, permissions: ["tabs"] }));
writeFileSync(join(gestureTabs, "app.js"), 'chrome.action.onClicked.addListener(() => {\n  chrome.tabs.query({ active: true, currentWindow: true }, ([t]) => console.log(t.url));\n});\n');
const gt = ledgerOf(gestureTabs);
check("tabs is reported used, with a call site", permStatus(gt, "tabs") === "used" && gt.ledger.find((l) => l.permission === "tabs").sites.length > 0);
check("tabs -> activeTab is suggested when only the active tab is read", narrowedFrom(gt).includes("tabs"), `got: ${narrowedFrom(gt).join(", ")}`);
check("and the suggestion carries the condition that makes it wrong",
  gt.narrowings.filter((n) => n.from === "tabs").every((n) => n.wrongIf && n.evidence.length));

// The same permission, where narrowing WOULD BREAK IT: observing tabs the user
// has not touched. activeTab cannot do this, so the suggestion must not fire.
const observerTabs = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(observerTabs, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Observer", description: "Counts how many tabs you have open and warns you above fifty.", icons: { 16: "i.png" }, permissions: ["tabs"] }));
writeFileSync(join(observerTabs, "app.js"), 'chrome.tabs.onUpdated.addListener((id, info) => console.log(id, info.status));\n');
check("tabs -> activeTab is NOT suggested when tabs are observed in the background",
  !narrowedFrom(ledgerOf(observerTabs)).includes("tabs"), `got: ${narrowedFrom(ledgerOf(observerTabs)).join(", ")}`);

// WHERE THE LINE BREAKS FALL MUST NOT CHANGE THE ADVICE. The guard used to be a
// single regex tested against ONE LINE, so wrapping a query object across lines -
// what a formatter does - stopped it matching, and a background tab enumerator
// was told to drop tabs for activeTab. That advice breaks the extension. Both
// directions are asserted: the pair must AGREE, and the narrowable case must
// still fire, or the "fix" would just be muting the feature.
const tabsCase = (js) => {
  const d = mkdtempSync(join(tmpdir(), "wsl-"));
  writeFileSync(join(d, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Fmt", description: "Same extension, formatted two different ways, must get one answer.", icons: { 16: "i.png" }, permissions: ["tabs"] }));
  writeFileSync(join(d, "app.js"), js);
  return narrowedFrom(ledgerOf(d)).includes("tabs");
};

const ENUM_ONE = 'chrome.tabs.query({ windowType: "normal" }, (t) => setBadge(t.length));\n';
const ENUM_WRAP = 'chrome.tabs.query({\n  windowType: "normal"\n}, (t) => setBadge(t.length));\n';
check("enumerating tabs: no narrowing when the query is on one line", tabsCase(ENUM_ONE) === false);
check("enumerating tabs: no narrowing when the SAME query is wrapped across lines",
  tabsCase(ENUM_WRAP) === false, "a wrapped query object must not read as narrowable");
check("and the two formattings agree", tabsCase(ENUM_ONE) === tabsCase(ENUM_WRAP));

const ACT_ONE = 'chrome.action.onClicked.addListener(() => {\n  chrome.tabs.query({ active: true, currentWindow: true }, ([t]) => show(t.url));\n});\n';
const ACT_WRAP = 'chrome.action.onClicked.addListener(() => {\n  chrome.tabs.query({\n    active: true,\n    currentWindow: true\n  }, ([t]) => show(t.url));\n});\n';
check("active-tab-only: narrowing still fires on one line", tabsCase(ACT_ONE) === true);
check("active-tab-only: narrowing still fires when wrapped", tabsCase(ACT_WRAP) === true,
  "the fix must not silence the suggestion it exists to make");

// The same one-line assumption let an `active: true` anywhere on the line cancel
// an OBSERVER match. onActivated fires for tabs the user never touched, so the
// two questions have to be asked separately.
check("an observer is not excused by an active:true elsewhere on its line",
  tabsCase('chrome.tabs.onActivated.addListener(() => chrome.tabs.query({ active: true }, log));\n') === false);

// A query argument we cannot read is not evidence of narrowability. Honesty rule
// 2: a claim we cannot support is worse than no claim, and the cost of guessing
// here is a deleted permission.
check("a query whose argument is a variable is not treated as narrowable",
  tabsCase('const opts = buildQuery();\nchrome.tabs.query(opts, (t) => setBadge(t.length));\n') === false);
check("a query whose object is spread is not treated as narrowable",
  tabsCase('chrome.tabs.query({ ...opts, active: true }, (t) => setBadge(t.length));\n') === false);

// storage declared while only web storage is used: the permission does nothing.
const webStorage = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(webStorage, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "WebStore", description: "Remembers your last search using the browser's own storage.", icons: { 16: "i.png" }, permissions: ["storage"] }));
writeFileSync(join(webStorage, "app.js"), 'localStorage.setItem("last", "x");\n');
check("storage declared but only localStorage used is flagged as removable",
  narrowedFrom(ledgerOf(webStorage)).includes("storage"));

// And the same permission where it IS earned: chrome.storage is called.
check("storage is NOT flagged when chrome.storage is actually used",
  !narrowedFrom(ledgerOf(join(here, "fixtures", "clean"))).includes("storage"));

// A COMMENTED-OUT CALL IS NOT A CALL SITE. This is the Purple Potassium case
// itself: the feature was deleted, the comment and the permission were left. The
// tool used to grep raw lines and report the permission "used", missing the one
// finding it exists to make.
const permCase = (js, perm = "bookmarks") => {
  const d = mkdtempSync(join(tmpdir(), "wsl-"));
  writeFileSync(join(d, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Cmt", description: "An extension whose only mention of a permission is in a comment.", icons: { 16: "i.png" }, permissions: [perm] }));
  writeFileSync(join(d, "app.js"), js);
  return permStatus(ledgerOf(d), perm);
};
check("a real call is used", permCase("chrome.bookmarks.getTree((t) => render(t));\n") === "used");
check("a call left only in a line comment is UNUSED",
  permCase("// we used to call chrome.bookmarks.getTree here, dropped in v2\nfunction render() {}\n") === "unused");
check("a call left only in a block comment is UNUSED",
  permCase("/* chrome.bookmarks.getTree() */\nfunction render() {}\n") === "unused");
check("a call left only in a jsdoc block is UNUSED",
  permCase("/**\n * @see chrome.bookmarks.getTree\n */\nfunction render() {}\n") === "unused");

// The other direction, and it is the expensive one: blanking real code would
// invent an "unused" verdict, and that advice deletes a permission the extension
// needs. Each of these hides a comment marker somewhere a naive stripper trips.
for (const [what, js] of [
  ["a url in a string", 'const u = "https://a.com/x";\nchrome.bookmarks.getTree();\n'],
  ["a url in a template literal", 'const u = `https://a.com/x`;\nchrome.bookmarks.getTree();\n'],
  ["an apostrophe in a comment", "// don't delete this\nchrome.bookmarks.getTree();\n"],
  ["a regex containing a slash", 'if (/a\\/b/.test(s)) chrome.bookmarks.getTree();\n'],
  ["a regex matching a protocol", 's.replace(/https:\\/\\//, "");\nchrome.bookmarks.getTree();\n'],
  ["division that is not a regex", "const r = a / b / c;\nchrome.bookmarks.getTree();\n"],
  ["a comment marker inside a string", 'log("/* not a comment */");\nchrome.bookmarks.getTree();\n'],
  ["code on the same line as a closed block comment", "/* note */ chrome.bookmarks.getTree();\n"],
]) {
  check(`a real call survives ${what}`, permCase(js) === "used");
}

// A mention inside a STRING stays "used" on purpose. It is ambiguous, and the
// fail-safe direction for an ambiguous case is the one that does not tell a
// developer to delete a permission.
check("a mention inside a string is left as used, not accused",
  permCase('const DOCS = "chrome.bookmarks reference";\n') === "used");

// Comment bytes become spaces rather than disappearing, so every reported line
// number still points at the right line.
const shifted = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(shifted, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Line", description: "Checks that blanking comments does not move any reported line number.", icons: { 16: "i.png" }, permissions: ["bookmarks"] }));
writeFileSync(join(shifted, "app.js"), "// one\n/* two\nthree */\nchrome.bookmarks.getTree();\n");
check("blanking comments does not shift reported line numbers",
  ledgerOf(shifted).ledger.find((l) => l.permission === "bookmarks").sites[0].line === 4);

// SOME PERMISSIONS ARE EARNED BY THE MANIFEST WITH NO JAVASCRIPT AT ALL, and
// missing that produced a false "unused" on the two that matter most. The
// RECOMMENDED MV3 way to block requests is a static declarativeNetRequest
// ruleset, which touches no chrome.* namespace anywhere - so we were telling ad
// blockers to delete the permission that does their blocking. side_panel is the
// same shape. unused-permissions is a FAIL, so a false one here deletes a
// working feature.
const manifestCase = (extra, perm, js = 'console.log("no chrome api needed");\n', files = {}) => {
  const d = mkdtempSync(join(tmpdir(), "wsl-"));
  writeFileSync(join(d, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "NoJs", description: "Uses a permission through the manifest rather than through any code.", icons: { 16: "i.png" }, permissions: [perm], ...extra }));
  writeFileSync(join(d, "app.js"), js);
  for (const [name, body] of Object.entries(files)) writeFileSync(join(d, name), body);
  return {
    audit: permStatus(ledgerOf(d), perm),
    rule: lint(d).findings.some((f) => f.rule === "unused-permissions"),
  };
};

const dnr = manifestCase({ declarative_net_request: { rule_resources: [{ id: "ruleset_1", enabled: true, path: "rules.json" }] } },
  "declarativeNetRequest", undefined, { "rules.json": "[]" });
check("a static declarativeNetRequest ruleset counts as using the permission", dnr.audit === "used", dnr.audit);
check("...and the unused-permissions rule does not fail it", dnr.rule === false);

const sp = manifestCase({ side_panel: { default_path: "panel.html" } }, "sidePanel", undefined, { "panel.html": "<html></html>" });
check("a side_panel.default_path counts as using the permission", sp.audit === "used", sp.audit);
check("...and the unused-permissions rule does not fail it", sp.rule === false);

// THE POSITIVE CONTROL, and it is the load-bearing one: manifest evidence must be
// the ACTUAL configuration, not the permission excusing itself. Declared with no
// ruleset and no code is still unused.
const dnrBare = manifestCase({}, "declarativeNetRequest");
check("declarativeNetRequest with NO ruleset and no code is still unused", dnrBare.audit === "unused", dnrBare.audit);
const dnrEmpty = manifestCase({ declarative_net_request: { rule_resources: [] } }, "declarativeNetRequest");
check("...and an EMPTY rule_resources array does not excuse it", dnrEmpty.audit === "unused", dnrEmpty.audit);
const spBare = manifestCase({ side_panel: {} }, "sidePanel");
check("side_panel with no default_path does not excuse the permission", spBare.audit === "unused", spBare.audit);

// THE TWO HALVES OF THE TOOL MUST AGREE. audit.mjs produces the ledger and
// unused-permissions produces the verdict, and they used to answer the same
// question from different text: the rule read raw code, so a commented-out call
// silenced it while the ledger reported unused. Assert AGREEMENT, not a verdict.
const agree = (js, perm = "bookmarks", extra = {}) => {
  const r = manifestCase(extra, perm, js);
  return (r.audit === "unused") === (r.rule === true);
};
check("halves agree on a real call", agree("chrome.bookmarks.getTree();\n"));
check("halves agree on a call left only in a comment", agree("// chrome.bookmarks.getTree()\nfunction f() {}\n"));
check("halves agree on a call left only in a block comment", agree("/* chrome.bookmarks.getTree() */\n"));
check("halves agree on a static declarativeNetRequest ruleset",
  agree('console.log("x");\n', "declarativeNetRequest", { declarative_net_request: { rule_resources: [{ id: "r", enabled: true, path: "rules.json" }] } }));

// And the rule must not have become trigger-happy: it is a FAIL, so the same
// awkward-code controls apply to it as to the ledger.
for (const [what, js] of [
  ["a url in a string", 'const u = "https://a.com/x";\nchrome.bookmarks.getTree();\n'],
  ["an apostrophe in a comment", "// don't delete this\nchrome.bookmarks.getTree();\n"],
  ["a regex containing a slash", 'if (/a\\/b/.test(s)) chrome.bookmarks.getTree();\n'],
  ["a comment marker inside a string", 'log("/* not a comment */");\nchrome.bookmarks.getTree();\n'],
]) {
  check(`unused-permissions does not fail a real call behind ${what}`, manifestCase({}, "bookmarks", js).rule === false);
}

// The host narrowing reads the code for hosts too, so a documentation URL in a
// comment used to be offered as a host to allow-list. The suggested list is what
// a developer pastes into their manifest, so padding it with chromium.org is both
// wrong and the kind of noise that gets a linter muted.
const hostCmt = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(hostCmt, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Hosts", description: "Talks to one backend, and links to the docs in a comment.", icons: { 16: "i.png" }, host_permissions: ["<all_urls>"] }));
writeFileSync(join(hostCmt, "app.js"), '// Docs: https://developer.chrome.com/docs/extensions/mv3/intro\nfetch("https://api.realbackend.io/v1/sync");\n');
const hostTo = ledgerOf(hostCmt).narrowings.find((n) => /all_urls/.test(n.from)).to;
check("the host narrowing offers the host the code actually contacts", /api\.realbackend\.io/.test(hostTo), hostTo);
check("...and not a documentation url that only appears in a comment",
  !/developer\.chrome\.com/.test(hostTo), hostTo);

// A permission the tool has no pattern for must be UNKNOWN, never unused: a
// false "unused" tells someone to delete something their extension needs.
const exotic = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(exotic, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Exotic", description: "Uses a permission this linter carries no pattern for at all.", icons: { 16: "i.png" }, permissions: ["someFuturePermission"] }));
writeFileSync(join(exotic, "app.js"), 'console.log("hello");\n');
check("an unmodelled permission is UNKNOWN, not unused", permStatus(ledgerOf(exotic), "someFuturePermission") === "unknown");

// activeTab has no namespace, so a call-site count of zero is correct rather
// than a finding. Reporting the narrow answer as unused would invert the advice.
const active = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(active, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Active", description: "Reads the page you are on when you click the toolbar button.", icons: { 16: "i.png" }, permissions: ["activeTab"] }));
writeFileSync(join(active, "app.js"), 'chrome.action.onClicked.addListener(() => {});\n');
check("activeTab is never reported unused", permStatus(ledgerOf(active), "activeTab") === "used");

// THE PERMISSION TABLE HAD TWO COPIES AND THEY DRIFTED BY FOUR ENTRIES (T-0421),
// and the reason it went unnoticed for so long is the interesting part: the
// agreement checks above were only ever run on permissions BOTH halves modelled.
// A permission missing from the rule's copy is read as "unknown", the rule stays
// silent, and silence agrees with everything. So the drift was invisible to the
// test written to catch exactly this. There is one table now, and these assert
// the four that were missing in the direction that used to be unreachable.
check("PERMISSION_API is not redeclared in rules.mjs",
  !/^\s*(?:const|let|var|export const)\s+PERMISSION_API\s*=/m.test(readFileSync(join(here, "..", "src", "rules.mjs"), "utf8")));

// The structural invariant behind activeTab, stated so a FUTURE empty entry
// cannot reintroduce the bug: namespaceUsed answers false for an empty pattern
// list, and false means FAIL, so any permission with no namespace must be
// declared as having none rather than left to look like one we could not find.
for (const [name, apis] of Object.entries(PERMISSION_API)) {
  if (apis.length) continue;
  check(`${name} has no namespace, so it is declared in NO_NAMESPACE_PERMISSIONS`,
    NO_NAMESPACE_PERMISSIONS.has(name));
}

// activeTab is the one that must NOT flip: the rule now models it, and modelling
// it naively is what would fail every extension declaring the permission this
// linter's own narrowing advice tells people to move to.
check("...and the unused-permissions RULE does not fail an extension for activeTab",
  lint(active).findings.some((f) => f.rule === "unused-permissions") === false);

// The other three gain a verdict they could never reach. Each is asserted as
// AGREEMENT between the halves, in the direction the drift made unreachable: a
// permission with neither call sites nor manifest configuration is unused, and
// before this the rule said nothing at all.
check("halves agree that a bare declarativeNetRequest is unused", agree('console.log("x");\n', "declarativeNetRequest"));
check("halves agree that a bare sidePanel is unused", agree('console.log("x");\n', "sidePanel"));
check("halves agree that a bare offscreen is unused", agree('console.log("x");\n', "offscreen"));
// ...and the false-positive control alongside each, so none of the three passes
// by the rule having become trigger-happy instead of merely present.
check("halves agree that offscreen WITH a call site is used", agree("chrome.offscreen.createDocument({});\n", "offscreen"));
check("halves agree that sidePanel WITH a call site is used", agree("chrome.sidePanel.setOptions({});\n", "sidePanel"));
check("halves agree that declarativeNetRequest WITH a call site is used",
  agree("chrome.declarativeNetRequest.updateDynamicRules({});\n", "declarativeNetRequest"));

// Minified code defeats call-site evidence. The audit must SAY so rather than
// report a confident zero - an absence found in a bundle is not an absence.
const bundled = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(bundled, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Bundled", description: "An extension shipped as a single minified bundle file.", icons: { 16: "i.png" }, permissions: ["bookmarks"] }));
writeFileSync(join(bundled, "bundle.js"), "var a=1;".repeat(400) + "\n");
const bundle = ledgerOf(bundled);
check("minified code is detected", bundle.confidence.minified.length > 0);
check("and the caveat says the unused verdict is not safe to act on",
  /incomplete/i.test(bundle.confidence.caveat), bundle.confidence.caveat);

// The bad fixture: unused permissions must appear as unused WITH the reason.
const badLedger = ledgerOf(join(here, "fixtures", "bad"));
check("bad fixture: bookmarks is reported unused", permStatus(badLedger, "bookmarks") === "unused");
check("bad fixture: cookies is reported used, with evidence",
  permStatus(badLedger, "cookies") === "used" && badLedger.ledger.find((l) => l.permission === "cookies").sites.every((s) => s.file && s.line > 0));
check("bad fixture: <all_urls> is narrowed against the hosts the code names",
  badLedger.narrowings.some((n) => /all_urls/.test(n.from) && n.to.includes("https://")));
check("bad fixture: disclosure categories are derived from USED permissions only",
  badLedger.disclosures.every((d) => permStatus(badLedger, d.permission) === "used"));

// webRequest: suggest declarativeNetRequest only when it is actually used.
// Declared-and-never-called is already "delete it", and printing both is the
// doubled-up output that gets a linter muted.
const wrUsed = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(wrUsed, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Blocker", description: "Blocks requests to a list of hosts you configure yourself.", icons: { 16: "i.png" }, permissions: ["webRequest"] }));
writeFileSync(join(wrUsed, "app.js"), 'chrome.webRequest.onBeforeRequest.addListener(() => ({ cancel: true }), { urls: ["<all_urls>"] }, ["blocking"]);\n');
check("webRequest -> declarativeNetRequest is suggested when webRequest is used",
  narrowedFrom(ledgerOf(wrUsed)).includes("webRequest"));

const wrUnused = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(wrUnused, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "Stale", description: "Declares a request permission it no longer calls anywhere.", icons: { 16: "i.png" }, permissions: ["webRequest"] }));
writeFileSync(join(wrUnused, "app.js"), 'console.log("nothing here");\n');
const stale = ledgerOf(wrUnused);
check("webRequest declared but unused says delete it, not migrate it",
  permStatus(stale, "webRequest") === "unused" && !narrowedFrom(stale).includes("webRequest"),
  `status=${permStatus(stale, "webRequest")} narrowings=${narrowedFrom(stale).join(", ")}`);

// --- the privacy policy URL check ------------------------------------------
// The case this exists for is a REAL rejection: a developer's policy url 404'd
// because the GitHub repo behind it was private, and Chrome DevRel diagnosed it
// in one reply. Every case here is driven by an injected fetch, so the suite stays
// offline and deterministic; the live behaviour is exercised separately below.

const res = (status, body, url) => ({
  ok: status >= 200 && status < 300,
  status,
  url,
  text: async () => body,
});
// Deliberately the length a REAL policy page runs to. The first version of this
// fixture was about 380 characters of text and tripped the "does not read like a
// privacy policy" warning, which was the check being right and the fixture being
// unrealistic: a genuine policy is never three sentences.
const POLICY_PAGE =
  "<h1>Privacy Policy</h1><p>This extension collects the following personal " +
  "information and data: the url of the page you are currently on, which is " +
  "stored in a cookie in your own browser. We do not share it with any third " +
  "party, we do not sell it, and we do not use it for advertising of any kind. " +
  "We process it locally on your device and retain it for thirty days, after " +
  "which it is deleted automatically. You can clear it at any time from the " +
  "extension options page, and you can contact us to have any information we " +
  "hold about you deleted.</p><p>This notice describes what we collect, why we " +
  "collect it, how long we keep it, who we share it with, and how you can ask " +
  "us to delete it. It applies to the browser extension only and not to any " +
  "other product. If we change what we collect we will update this page and " +
  "note the date of the change at the top.</p>";

const pol = async (url, fetchImpl) => (await import("../src/privacy.mjs")).checkPolicyUrl(url, { fetchImpl });
const sev = (fs, s) => fs.filter((f) => f.severity === s);

// A 404 must FAIL, and the detail must name the private-repo cause, because that
// is the whole diagnostic value over "your url is broken".
const gone = await pol("https://example.com/privacy", async () => res(404, "Not Found", "https://example.com/privacy"));
check("privacy url: a 404 fails", sev(gone, "fail").length === 1 && /answers 404/.test(gone[0].title));
check("privacy url: the 404 detail names the private-repo cause",
  /private/i.test(gone[0].detail) && /PUBLIC/.test(gone[0].detail));
check("privacy url: the 404 cites the disclosure category", gone[0].category === "udp-disclosure-policy");

// AND THE PAIRED CASE, or every assertion above is satisfied by a check that
// fails on everything: a real policy page must produce NO failure and NO warning.
const good = await pol("https://example.com/privacy", async () => res(200, POLICY_PAGE, "https://example.com/privacy"));
check("privacy url: a reachable policy page produces no failure",
  sev(good, "fail").length === 0, JSON.stringify(good.map((f) => f.title)));
check("privacy url: a reachable policy page produces no warning",
  sev(good, "warn").length === 0, JSON.stringify(good.map((f) => f.title)));
check("privacy url: a reachable policy page is reported as reachable",
  good.some((f) => f.severity === "info" && /reachable/.test(f.title)));

// 200 with a landing page rather than a policy: warn, never fail. The tool
// cannot read a policy and must not pretend the distinction is certain.
const shell = await pol("https://example.com/", async () => res(200, "<h1>Welcome</h1>", "https://example.com/"));
check("privacy url: 200 with no policy text warns rather than fails",
  sev(shell, "fail").length === 0 && sev(shell, "warn").some((f) => /does not read like/.test(f.title)));
check("privacy url: the shallow check admits it can be wrong about JavaScript",
  sev(shell, "warn").some((f) => /JavaScript/.test(f.detail)));

// COULD NOT LOOK IS NOT NOT-THERE. A network error is a warning, not a failure.
const dns = await pol("https://nope.invalid/privacy", async () => { throw new Error("getaddrinfo ENOTFOUND"); });
check("privacy url: a network error warns and does not fail",
  sev(dns, "fail").length === 0 && sev(dns, "warn").length === 1);
check("privacy url: the network error says it is not evidence about the url",
  /not the same as the address being broken/.test(dns[0].detail));

// A url only the developer can open is a rejection waiting to happen, and no
// request is made to it. The thrown fetch proves the request never happened: if
// the host check were missing, this case would report a network error instead.
const boom = async () => { throw new Error("this fetch must never run"); };
for (const host of ["http://localhost:8080/p", "https://127.0.0.1/p", "https://10.0.0.5/p", "https://policy.internal/p"]) {
  const r = await pol(host, boom);
  check(`privacy url: ${host} fails without making a request`,
    sev(r, "fail").length === 1 && /nobody outside your network/.test(r[0].title),
    JSON.stringify(r.map((f) => f.title)));
}

const notUrl = await pol("privacy.html", boom);
check("privacy url: a bare filename fails as not a url", sev(notUrl, "fail").length === 1 && /not a URL/.test(notUrl[0].title));

const ftp = await pol("ftp://example.com/p", boom);
check("privacy url: a non-http scheme fails", sev(ftp, "fail").length === 1 && /rather than https/.test(ftp[0].title));

const insecure = await pol("http://example.com/privacy", async () => res(200, POLICY_PAGE, "http://example.com/privacy"));
check("privacy url: plain http warns but does not fail",
  sev(insecure, "fail").length === 0 && sev(insecure, "warn").some((f) => /plain http/.test(f.title)));

const moved = await pol("https://example.com/privacy", async () => res(200, POLICY_PAGE, "https://www.example.com/privacy-policy"));
check("privacy url: a redirect is reported as info, not a problem",
  sev(moved, "fail").length === 0 && moved.some((f) => f.severity === "info" && /redirects/.test(f.title)));

// --- s077: five defects in the rules that had never been audited -------------
//
// EVERY ONE OF THESE IS AN AGREEMENT ASSERTION. Two packages differ in ONE way
// that must not change the verdict, and the test demands the SAME answer from
// both. Agreement cannot be satisfied by the tool crashing on both inputs or by
// a rule silently returning [], which a "does it fire" test can be. Each pair is
// also pinned to the specific finding, so a rule that goes quiet everywhere
// fails here rather than passing twice.

const pkg = (files) => {
  const dir = mkdtempSync(join(tmpdir(), "wsl-"));
  for (const [rel, body] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, typeof body === "string" ? body : JSON.stringify(body));
  }
  return dir;
};

// 1. LOCALISATION. A localised extension does not put its description in
// manifest.json - it writes __MSG_extDescription__ and the sentence lives in
// _locales/<default_locale>/messages.json. Reading the placeholder literally
// gave the SAME extension opposite answers, and the localised side got it wrong
// both ways: an invented "22 characters" warning, and silence about a
// description that reads "prediction market ... sportsbook betting". The silent
// half is the dangerous one - it dropped a finding about a policy enforced from
// 1 August 2026.
const GAMBLING_DESC = "A prediction market and sportsbook betting companion showing live gambling odds for every parlay.";
const inlineDesc = pkg({
  "manifest.json": { manifest_version: 3, name: "Odds", version: "1.0.0", description: GAMBLING_DESC, icons: { 16: "i.png" } },
});
const localisedDesc = pkg({
  "manifest.json": { manifest_version: 3, name: "__MSG_extName__", version: "1.0.0", default_locale: "en", description: "__MSG_extDescription__", icons: { 16: "i.png" } },
  "_locales/en/messages.json": { extName: { message: "Odds" }, extDescription: { message: GAMBLING_DESC } },
});
{
  const a = ids(lint(inlineDesc)).sort();
  const b = ids(lint(localisedDesc)).sort();
  check("i18n: localising a description does not change the verdict", JSON.stringify(a) === JSON.stringify(b), `${a} vs ${b}`);
  check("i18n: and the verdict they agree on is the real one", a.includes("prediction-markets-2026"), String(a));
  check("i18n: the localised package is not accused of a short description",
    !lint(localisedDesc).findings.some((f) => /characters/.test(f.title)));
}
// Message names are case-insensitive in Chrome, so the lookup must be too.
check("i18n: message names are matched case-insensitively",
  !ids(lint(pkg({
    "manifest.json": { manifest_version: 3, name: "X", version: "1.0.0", default_locale: "en", description: "__MSG_extDescription__", icons: { 16: "i.png" } },
    "_locales/en/messages.json": { ExtDescription: { message: "A perfectly ordinary description of what this extension does." } },
  }))).includes("listing-metadata"));

// THE CONTROL THAT KEEPS THE ABOVE HONEST: resolution must never INVENT text. A
// placeholder with no message behind it is a package Chrome refuses to load, and
// it must be reported as exactly that rather than measured as a short string.
for (const [name, files] of Object.entries({
  "no default_locale": { "manifest.json": { manifest_version: 3, name: "X", version: "1.0.0", description: "__MSG_extDescription__", icons: { 16: "i.png" } } },
  "no messages.json": { "manifest.json": { manifest_version: 3, name: "X", version: "1.0.0", default_locale: "en", description: "__MSG_extDescription__", icons: { 16: "i.png" } } },
  "no such message": {
    "manifest.json": { manifest_version: 3, name: "X", version: "1.0.0", default_locale: "en", description: "__MSG_extDescription__", icons: { 16: "i.png" } },
    "_locales/en/messages.json": { somethingElse: { message: "unrelated" } },
  },
})) {
  const r = lint(pkg(files));
  check(`i18n: an unresolvable placeholder (${name}) fails and says why`,
    bySeverity(r, "fail").includes("listing-metadata") && r.findings.some((f) => /does not resolve/.test(f.title)),
    JSON.stringify(r.findings.map((f) => f.title)));
  check(`i18n: (${name}) is not misdiagnosed as a short description`,
    !r.findings.some((f) => /characters/.test(f.title)));
}

// 1b. A UTF-8 BOM IS NOT A SYNTAX ERROR (s100, found by the 160-repo corpus).
// `readFileSync(f, "utf8")` leaves U+FEFF at the head of the string and
// `JSON.parse` throws on it; Chromium's JSON reader consumes it and loads the
// extension. We reported MarvellousSuspender - published, 374 good message keys -
// at FAIL for "a localised manifest field does not resolve", and SmartProxy at
// warn for the same byte.
//
// The pass condition here is deliberately NOT "no listing-metadata finding",
// which a scan that died on its way to the rule would also satisfy. It is that
// the sentence living ONLY inside the BOM'd file comes back out in the verdict:
// GAMBLING_DESC is what triggers prediction-markets-2026, so that rule firing is
// proof the bytes were read, and nothing but successful parsing produces it.
const BOM = "﻿";
const localeBody = JSON.stringify({ extName: { message: "Odds" }, extDescription: { message: GAMBLING_DESC } });
const bomLocale = pkg({
  "manifest.json": { manifest_version: 3, name: "__MSG_extName__", version: "1.0.0", default_locale: "en", description: "__MSG_extDescription__", icons: { 16: "i.png" } },
  "_locales/en/messages.json": BOM + localeBody,
});
{
  const withBom = ids(lint(bomLocale)).sort();
  check("bom: a BOM on messages.json does not change the verdict",
    JSON.stringify(withBom) === JSON.stringify(ids(lint(localisedDesc)).sort()),
    `${withBom} vs ${ids(lint(localisedDesc)).sort()}`);
  check("bom: and the description inside the BOM'd file was actually read",
    withBom.includes("prediction-markets-2026"), String(withBom));
  check("bom: the package is not failed for unresolvable localisation",
    !lint(bomLocale).findings.some((f) => /does not resolve/.test(f.title)));
}
// THE CONTROL, and it is the whole reason this is a BOM strip rather than a
// softened parse error: a locale file that is genuinely malformed must STILL
// fail and still say why. A fix that made JSON errors survivable would pass
// every assertion above and quietly stop reporting broken packages.
{
  const r = lint(pkg({
    "manifest.json": { manifest_version: 3, name: "X", version: "1.0.0", default_locale: "en", description: "__MSG_extDescription__", icons: { 16: "i.png" } },
    "_locales/en/messages.json": BOM + '{"extDescription": {"message": "truncated"',
  }));
  check("bom: a BOM in front of REAL broken JSON still fails and says why",
    bySeverity(r, "fail").includes("listing-metadata") && r.findings.some((f) => /does not resolve/.test(f.title)),
    JSON.stringify(r.findings.map((f) => f.title)));
}
// The manifest reader takes the same strip. No manifest.json in the 160-repo
// corpus carries a BOM, so this half is a latent trap rather than a measured
// one - but it is the worse site: an unparseable manifest aborts the scan, so
// the whole extension reads as unreadable rather than as one bad field.
{
  const r = lint(pkg({
    "manifest.json": BOM + JSON.stringify({ manifest_version: 3, name: "Odds", version: "1.0.0", description: GAMBLING_DESC, icons: { 16: "i.png" } }),
  }));
  check("bom: a BOM on manifest.json is read, not reported as invalid JSON",
    !r.findings.some((f) => /not valid JSON/.test(f.title)) && ids(r).includes("prediction-markets-2026"),
    JSON.stringify(r.findings.map((f) => f.title)));
}

// 1c. REMOTE-CODE AIMED AT THE PACKAGE CHROME ACTUALLY REVIEWS (s100, corpus of
// 94 packages). Two separate wrong FAILs, both measured on real extensions:
// test files counted as shipped code, and a COMMENT counted as code.
const MANIFEST = { manifest_version: 3, name: "X", version: "1.0.0", description: "A perfectly ordinary description of one purpose.", icons: { 16: "i.png" } };
const rc = (r) => r.findings.filter((f) => f.rule === "remote-code");
const evalFinding = (r) => rc(r).find((f) => /eval\(\) or new Function/.test(f.title));

// Nagi-ovo/voyager's whole FAIL was one line in a __tests__ directory.
{
  const r = lint(pkg({ "manifest.json": MANIFEST, "__tests__/scroll.test.js": "const fn = new Function(code);\n" }));
  const f = evalFinding(r);
  check("remote-code: a test-only site is reported, not ignored", Boolean(f), JSON.stringify(ids(r)));
  check("remote-code: and a test-only site is a warning, not a failure",
    f?.severity === "warn" && /only in test files/.test(f.title), `${f?.severity} ${f?.title}`);
  check("remote-code: the test-only warning still points at the line",
    f?.evidence?.length === 1 && /scroll\.test\.js/.test(f.evidence[0].file) && f.evidence[0].line === 1);
}
// THE CONTROL THAT MAKES THAT A NARROWING AND NOT A MUTE: the same call in
// shipped code is still a FAIL. Without this pair, "warn" could be the answer
// everywhere and every assertion above would still pass.
{
  const r = lint(pkg({ "manifest.json": MANIFEST, "background.js": "const fn = new Function(code);\n" }));
  const f = evalFinding(r);
  check("remote-code: the identical call in shipped code still FAILS",
    f?.severity === "fail" && !/only in test files/.test(f.title), `${f?.severity} ${f?.title}`);
}
// Mixed: scriptcat buried 2 real sites under 13 test ones. It must stay a FAIL,
// and the site that matters must be the first one they read.
{
  const r = lint(pkg({
    "manifest.json": MANIFEST,
    "content.js": "const fn = new Function(code);\n",
    "src/__tests__/a.test.js": "new Function('x');\n",
    "test/b.spec.ts": "new Function('y');\n",
  }));
  const f = evalFinding(r);
  check("remote-code: shipped + test sites stay a FAIL", f?.severity === "fail", String(f?.severity));
  check("remote-code: and the shipped site is listed FIRST",
    f?.evidence?.[0]?.file === "content.js", JSON.stringify(f?.evidence?.map((e) => e.file)));
  check("remote-code: the test sites are kept, not dropped",
    f?.evidence?.length === 3 && /further 2 site\(s\) are in test files/.test(f.detail || ""),
    `${f?.evidence?.length} evidence`);
}
// A COMMENT CANNOT EXECUTE. Fannon/search-bookmarks was failed on a line reading
// "a CSP-safe recursive validator that doesn't require eval() or Function()".
{
  const r = lint(pkg({
    "manifest.json": MANIFEST,
    "validate.js": "// This is a CSP-safe validator that doesn't require eval() or Function().\nexport const ok = 1;\n",
  }));
  check("remote-code: a comment mentioning eval() is not a finding", !evalFinding(r), JSON.stringify(rc(r).map((f) => f.title)));
}
// AND THE CONTROL FOR T-0411, which is why only comments are blanked and never
// strings: automa assembles code inside a template literal and injects it. A fix
// that blanked string contents would pass the comment test above and go blind to
// the real violation.
{
  const r = lint(pkg({
    "manifest.json": MANIFEST,
    "inject.js": "const payload = `eval(${userInput})`;\nchrome.scripting.executeScript({ func: new Function(payload) });\n",
  }));
  const f = evalFinding(r);
  check("remote-code: code built inside a string literal is still seen", f?.severity === "fail", String(f?.severity));
}
// Evidence must quote the developer's real line, not the comment-blanked copy.
{
  const r = lint(pkg({
    "manifest.json": MANIFEST,
    "run.js": "const fn = new Function(code); // build the handler\n",
  }));
  const f = evalFinding(r);
  check("remote-code: evidence quotes the ORIGINAL line, not the blanked one",
    /\/\/ build the handler/.test(f?.evidence?.[0]?.text || ""), JSON.stringify(f?.evidence?.[0]?.text));
}

// 2. NEW TAB PAGE. The rule detects newtab manipulation from code and used to
// accept ANY of three override keys as the declaration that excuses it. Two of
// them govern different surfaces, so declaring an unrelated homepage override
// silenced a FAIL - the exact manoeuvre the policy exists to catch.
const NTP_CODE = 'chrome.tabs.onCreated.addListener((t) => {\n  if (t.pendingUrl === "chrome://newtab/") chrome.tabs.update(t.id, { url: "https://ours.example/" });\n});\n';
const ntpBase = { manifest_version: 3, name: "Start", version: "1.0.0", description: "Opens your chosen start page when you open a new tab.", icons: { 16: "i.png" }, permissions: ["tabs"] };
const ntpBare = pkg({ "manifest.json": ntpBase, "sw.js": NTP_CODE });
const ntpHomepage = pkg({ "manifest.json": { ...ntpBase, chrome_settings_overrides: { homepage: "https://ours.example/home" } }, "sw.js": NTP_CODE });
const ntpSearch = pkg({ "manifest.json": { ...ntpBase, chrome_settings_overrides: { search_provider: { name: "s", search_url: "https://ours.example/?q={searchTerms}", encoding: "UTF-8", is_default: true, keyword: "s", favicon_url: "https://ours.example/f.ico" } } }, "sw.js": NTP_CODE });
for (const [name, dir] of [["a homepage override", ntpHomepage], ["a search provider", ntpSearch]]) {
  check(`ntp: declaring ${name} does not excuse hijacking the new tab page`,
    ids(lint(dir)).includes("ntp-override"), JSON.stringify(ids(lint(dir))));
}
check("ntp: the undeclared case still fails", bySeverity(lint(ntpBare), "fail").includes("ntp-override"));
// THE FALSE-POSITIVE CONTROL, and the reason the narrowing above is a fix rather
// than a regression: an extension that declares the OFFICIAL override is doing
// the correct thing and must hear nothing at all.
check("ntp: the official chrome_url_overrides.newtab is still accepted",
  !ids(lint(pkg({ "manifest.json": { ...ntpBase, chrome_url_overrides: { newtab: "newtab.html" } }, "sw.js": NTP_CODE }))).includes("ntp-override"));

// VISITING THE NEW TAB PAGE IS NOT OVERRIDING IT. Taken verbatim from
// xifangczy/cat-catch, which this rule failed at severity FAIL for the ordinary
// "keep the window open when closing the last tab" idiom.
//
// The pair is the point and neither half means anything alone: the same two
// files differ only in whether the newtab url is a DESTINATION or a thing being
// compared against, which is the distinction the rule is supposed to encode. A
// narrowing that also silenced the hijack would pass the first check and fail
// the second, so the second is what makes this a fix rather than a mute.
const NTP_VISIT = 'function closeTab(tabId = 0) {\n  chrome.tabs.query({}, async function (tabs) {\n    if (tabs.length === 1) {\n      await chrome.tabs.create({ url: "chrome://newtab" });\n      tabId ? chrome.tabs.remove(tabId) : window.close();\n    }\n  });\n}\n';
check("ntp: opening the new tab page to keep a window alive is not a finding",
  !ids(lint(pkg({ "manifest.json": ntpBase, "sw.js": NTP_VISIT }))).includes("ntp-override"),
  JSON.stringify(ids(lint(pkg({ "manifest.json": ntpBase, "sw.js": NTP_VISIT })))));
check("ntp: window.open of the new tab page is not a finding either",
  !ids(lint(pkg({ "manifest.json": ntpBase, "sw.js": 'window.open("chrome://newtab");\n' }))).includes("ntp-override"));
check("ntp: THE CONTROL - the hijack in the very same file is still caught",
  bySeverity(lint(pkg({ "manifest.json": ntpBase, "sw.js": NTP_VISIT + NTP_CODE })), "fail").includes("ntp-override"));
// Blanking is offset-preserving precisely so this case survives: a create() and
// a redirect sharing ONE line must not hide each other.
check("ntp: a redirect sharing a line with a benign create is still caught",
  bySeverity(lint(pkg({ "manifest.json": ntpBase, "sw.js": 'if (t.url === "chrome://newtab") { chrome.tabs.create({ url: "chrome://newtab" }); chrome.tabs.update(t.id, { url: "https://ours.example/" }); }\n' })), "fail").includes("ntp-override"));

// 2a-bis. RECOGNISING THE NEW TAB PAGE IN ORDER TO LEAVE IT ALONE. Chrome
// forbids content scripts on chrome:// pages, so a careful extension guards
// against them - which means the old rule fired hardest on the extensions being
// most careful. All three are verbatim from the corpus.
for (const [who, code] of [
  ["obsidian-clipper's isBlankPage", "export function isBlankPage(url) {\n  return url === 'about:blank' || url === 'chrome://newtab/' || url === 'edge://newtab/';\n}\n"],
  ["extension-js's first-run check", "const isInitialPage =\n  url.startsWith('about:home') ||\n  url.startsWith('about:newtab') ||\n  url === 'about:blank';\n"],
  ["scriptcat's test that the page is REFUSED", 'expect(() => assertDomUrlAllowed("about:newtab")).toThrow("not allowed");\n'],
]) {
  check(`ntp: ${who} is not a finding`,
    !ids(lint(pkg({ "manifest.json": ntpBase, "sw.js": code }))).includes("ntp-override"),
    JSON.stringify(ids(lint(pkg({ "manifest.json": ntpBase, "sw.js": code })))));
}
// AND THE CONTROL THAT KEEPS THAT FROM BEING A MUTE: the same predicate, plus a
// redirect that uses it. This is the shape the policy is actually about.
check("ntp: THE CONTROL - a guard that feeds a redirect is still caught",
  bySeverity(lint(pkg({ "manifest.json": ntpBase, "sw.js": "chrome.tabs.onUpdated.addListener((id, i, tab) => {\n  if (tab.url === 'chrome://newtab/') chrome.tabs.update(id, { url: 'https://ours.example/' });\n});\n" })), "fail").includes("ntp-override"));
// Proximity, not co-occurrence: a predicate in one function must not pair with
// an unrelated navigation far down the file.
check("ntp: a guard and a distant unrelated tabs.update do not pair up",
  !ids(lint(pkg({ "manifest.json": ntpBase, "sw.js": "const isBlank = (u) => u === 'chrome://newtab/';\n" + "// filler\n".repeat(60) + "chrome.tabs.update(someId, { url: dest });\n" }))).includes("ntp-override"));

// 2b-bis. THE MANIFEST NAMES FILES THAT ARE NOT HERE. Authenticator was failed
// for five permissions "never used" while we linted a folder of seven JSON
// files and no code at all; its manifest names dist/background.js.
const goneManifest = { manifest_version: 3, name: "Authenticator", version: "1.0.0", description: "Two factor authentication codes, stored locally on your device.", icons: { 16: "i.png" }, permissions: ["storage", "identity", "alarms"], background: { service_worker: "dist/background.js" } };
const absent = lint(pkg({ "manifest.json": goneManifest }));
check("missing files: the absent service worker is reported",
  ids(absent).includes("missing-declared-files"), JSON.stringify(ids(absent)));
check("missing files: it is a warn, not a fail",
  !bySeverity(absent, "fail").includes("missing-declared-files"));
check("missing files: permissions are NOT failed as unused when the code is absent",
  !bySeverity(absent, "fail").includes("unused-permissions"),
  JSON.stringify(absent.findings.map((f) => `${f.severity}:${f.rule}`)));
check("missing files: and it says the code is not here to be read",
  absent.findings.some((f) => f.rule === "unused-permissions" && /not in this directory/.test(f.detail || "")));
// THE CONTROL. The same manifest with the file actually present must still fail
// the permissions, or the guard has deleted the check rather than aimed it.
const withCode = lint(pkg({ "manifest.json": { ...goneManifest, background: { service_worker: "bg.js" } }, "bg.js": "console.log('nothing uses the permissions');\n" }));
check("missing files: THE CONTROL - with the file present, unused permissions still fail",
  bySeverity(withCode, "fail").includes("unused-permissions"),
  JSON.stringify(withCode.findings.map((f) => `${f.severity}:${f.rule}`)));
check("missing files: THE CONTROL - and a complete package is not accused of missing any",
  !ids(withCode).includes("missing-declared-files"));
// A file the SCANNER skipped is present, not absent - an instrument failure must
// never render as a finding.
check("missing files: a declared file too big to read counts as present",
  !ids(lint(pkg({ "manifest.json": { ...goneManifest, background: { service_worker: "big.js" } }, "big.js": "x".repeat(2 * 1024 * 1024 + 10) }))).includes("missing-declared-files"));
// Wildcards are patterns, not paths.
check("missing files: a wildcard resource is not reported missing",
  !ids(lint(pkg({ "manifest.json": { ...goneManifest, background: { service_worker: "bg.js" }, web_accessible_resources: [{ resources: ["assets/*"], matches: ["<all_urls>"] }] }, "bg.js": "chrome.storage.local.get();chrome.identity.getProfileUserInfo();chrome.alarms.create();\n" }))).includes("missing-declared-files"));

// 2b. FRAGMENT MANIFESTS. A file with no name and no version is an input to a
// build step, not a package, and saying "you have no description" about one is a
// true sentence and a wrong diagnosis. Both shapes are real: darkreader's
// manifest-chrome-mv3.json carries only the MV3 deltas, automa's
// manifest.chrome.json has a name but no version.
const fragBase = { manifest_version: 3, action: { default_popup: "p.html" }, background: { service_worker: "sw.js" } };
for (const [name, m] of [
  ["no name and no version", fragBase],
  ["a name but no version", { ...fragBase, name: "Automa" }],
]) {
  const r = lint(pkg({ "manifest.json": m, "sw.js": "chrome.storage.local.get();\n", "p.html": "<html></html>" }));
  check(`fragment: ${name} is reported as a build fragment`,
    ids(r).includes("incomplete-manifest"), JSON.stringify(ids(r)));
  check(`fragment: ${name} is NOT misdiagnosed as a missing description`,
    !r.findings.some((f) => /no description/.test(f.title)),
    JSON.stringify(r.findings.map((f) => f.title)));
  check(`fragment: ${name} is a warn, because telling the two apart needs the build`,
    !bySeverity(r, "fail").includes("incomplete-manifest"));
}
// THE FALSE-POSITIVE CONTROL. A complete manifest that genuinely has no
// description must still be failed for it - otherwise the guard above has not
// narrowed the diagnosis, it has deleted the check.
const noDesc = lint(pkg({ "manifest.json": { ...fragBase, name: "Real", version: "1.0.0", icons: { 16: "i.png" } }, "sw.js": "chrome.storage.local.get();\n", "p.html": "<html></html>" }));
check("fragment: THE CONTROL - a complete manifest with no description still fails",
  bySeverity(noDesc, "fail").includes("listing-metadata") && noDesc.findings.some((f) => /no description/.test(f.title)),
  JSON.stringify(noDesc.findings.map((f) => `${f.severity}:${f.title}`)));
check("fragment: a complete manifest is not called a fragment",
  !ids(noDesc).includes("incomplete-manifest"));

// 2c. AN ABSENCE IS NOT EVIDENCE WHEN THE PACKAGE HAS NOT BEEN BUILT. voyager
// was failed for a __MSG_extName__ that "does not resolve" on a tree whose
// messages.json sits in src/locales/ and is copied to _locales/ by the build.
const i18nSrc = { manifest_version: 3, name: "__MSG_extName__", version: "1.0.0", default_locale: "en", description: "A perfectly ordinary description of one purpose.", icons: { 16: "i.png" } };
const unbuilt = lint(pkg({ "manifest.json": i18nSrc, "sw.js": 'import { x } from "webext-storage";\nx();\n' }));
check("unbuilt i18n: the unresolved placeholder is reported as a warn, not a fail",
  ids(unbuilt).includes("listing-metadata") && !bySeverity(unbuilt, "fail").includes("listing-metadata"),
  JSON.stringify(unbuilt.findings.map((f) => `${f.severity}:${f.title}`)));
check("unbuilt i18n: it still says the placeholder does not resolve",
  unbuilt.findings.some((f) => /does not resolve/.test(f.title)));
// THE CONTROL, and it is the same manifest: with no bare imports this is a
// package that ships as checked in, and the unresolved placeholder really would
// be rejected before review. The two must NOT agree.
const built = lint(pkg({ "manifest.json": i18nSrc, "sw.js": 'chrome.storage.local.get();\n' }));
check("unbuilt i18n: THE CONTROL - the same manifest in a real package still fails",
  bySeverity(built, "fail").includes("listing-metadata"),
  JSON.stringify(built.findings.map((f) => `${f.severity}:${f.title}`)));

// AND THE SHAPE THE REAL EXTENSION ACTUALLY HAS, which the fixture above does
// not: voyager's DESCRIPTION is a placeholder too, and that returns early from
// the rule several lines before the downgrade used to sit. The check above went
// green while the reported case stayed at FAIL, so the two fixtures differ in
// the one thing that decides which exit is taken.
const i18nBothSrc = { ...i18nSrc, description: "__MSG_extDescription__" };
const unbuiltBoth = lint(pkg({ "manifest.json": i18nBothSrc, "sw.js": 'import { x } from "webext-storage";\nx();\n' }));
check("unbuilt i18n: a placeholder DESCRIPTION takes the early exit and is still downgraded",
  ids(unbuiltBoth).includes("listing-metadata") && !bySeverity(unbuiltBoth, "fail").includes("listing-metadata"),
  JSON.stringify(unbuiltBoth.findings.map((f) => `${f.severity}:${f.title}`)));
const builtBoth = lint(pkg({ "manifest.json": i18nBothSrc, "sw.js": 'chrome.storage.local.get();\n' }));
check("unbuilt i18n: THE CONTROL on that same early exit - a real package still fails",
  bySeverity(builtBoth, "fail").includes("listing-metadata"),
  JSON.stringify(builtBoth.findings.map((f) => `${f.severity}:${f.title}`)));

// 3. OPTIONAL PERMISSIONS. disclosure-2026 and unused-permissions both read
// permissions AND optional_permissions; limited-use-2026 read only the first, so
// one extension was told its history access was in scope for disclosure and not
// in scope for limited use. Same data either way; the difference is when it is
// asked for.
const histBase = { manifest_version: 3, name: "Hist", version: "1.0.0", description: "Summarises the pages you read most often over the last week.", icons: { 16: "i.png" } };
const histRequired = pkg({ "manifest.json": { ...histBase, permissions: ["history"] }, "sw.js": 'chrome.history.search({ text: "" }, () => {});\n' });
const histOptional = pkg({ "manifest.json": { ...histBase, optional_permissions: ["history"] }, "sw.js": 'chrome.history.search({ text: "" }, () => {});\n' });
{
  const a = ids(lint(histRequired)).sort();
  const b = ids(lint(histOptional)).sort();
  check("optional permissions: required and optional history get the same rules", JSON.stringify(a) === JSON.stringify(b), `${a} vs ${b}`);
  check("optional permissions: and both include the limited-use rule", a.includes("limited-use-2026"), String(a));
  // ?. rather than a bare access: against the pre-fix source this rule produces
  // NOTHING, and a throw here would abort the run and take every test after it
  // with it - which is how a control set silently stops controlling anything.
  check("optional permissions: the finding says which one is optional",
    /history \(optional\)/.test(lint(histOptional).findings.find((f) => f.rule === "limited-use-2026")?.title || ""));
}

// 4. KEYWORD STUFFING ON ORDINARY ENGLISH. The word pattern demands three
// letters, which "the" clears, so plain prose using it five times was reported
// as repeating terms. This file's own header says the clean fixture is the
// load-bearing half; a warning that fires on ordinary English is that failure
// arriving through a different door.
check("keyword stuffing: ordinary prose is not reported",
  !ids(lint(pkg({ "manifest.json": { manifest_version: 3, name: "Reader", version: "1.0.0", icons: { 16: "i.png" }, description: "Shows the reading time for the article you are on, and the reading time for the comments, so that you know how long the whole page will take before you start." } }))).includes("keyword-stuffing"));
// The control: real stuffing must still be caught. The bad fixture repeats
// "coupons" and "deals", and the assertion at the top of this file covers it -
// this one pins that the stopword list did not swallow the mechanism entirely.
check("keyword stuffing: a genuinely stuffed description is still caught",
  ids(lint(pkg({ "manifest.json": { manifest_version: 3, name: "Deals", version: "1.0.0", icons: { 16: "i.png" }, description: "coupons, coupons, promo, coupons, deals, deals, vouchers, deals, discounts, coupons" } }))).includes("keyword-stuffing"));

// 5. COMMENTED-OUT CODE. A deleted endpoint left in a comment is not an endpoint
// the package contacts, and a miner in a comment mines nothing. Both rules read
// raw text, which is the same defect unused-permissions had fixed in s076 - the
// lesson did not transfer by being written down next to the tool.
const httpLive = pkg({ "manifest.json": { manifest_version: 3, name: "S", version: "1.0.0", description: "Sends a summary of the page you are reading to your own server.", icons: { 16: "i.png" } }, "sw.js": 'const API = "http://api.example.com/collect";\nfetch(API);\n' });
const httpDead = pkg({ "manifest.json": { manifest_version: 3, name: "S", version: "1.0.0", description: "Sends a summary of the page you are reading to your own server.", icons: { 16: "i.png" } }, "sw.js": '// const API = "http://api.example.com/collect";\n// fetch(API);\n' });
check("comments: a live http endpoint is reported", ids(lint(httpLive)).includes("insecure-transmission"));
check("comments: the same endpoint commented out is not", !ids(lint(httpDead)).includes("insecure-transmission"));
const mineLive = pkg({ "manifest.json": { manifest_version: 3, name: "M", version: "1.0.0", description: "Runs a small background task while you browse the web pages.", icons: { 16: "i.png" } }, "sw.js": 'import CoinHive from "./ch.js";\nnew CoinHive.Anonymous("k").start();\n' });
const mineDead = pkg({ "manifest.json": { manifest_version: 3, name: "M", version: "1.0.0", description: "Runs a small background task while you browse the web pages.", icons: { 16: "i.png" } }, "sw.js": '// we removed the CoinHive experiment in 2019\n' });
check("comments: a live miner still fails", bySeverity(lint(mineLive), "fail").includes("crypto-mining"));
check("comments: a miner mentioned only in a comment is not an accusation", !ids(lint(mineDead)).includes("crypto-mining"));

// --- s077: the CLI, which had never been audited ----------------------------
//
// THIS SECTION SPAWNS THE BINARY, because argument parsing and exit codes cannot
// be reached from lint(). The exit code is what a CI gate reads, so a wrong one
// is the tool lying to a machine that cannot argue back.
//
// A NOTE ON HOW THESE ARE MEASURED. The first version of this check read the
// exit code through a pipe and got the exit code of `grep` every time, which
// reported 0 for runs that had exited 1. spawnSync gives the process's own
// status with nothing in between.

const BIN = join(here, "..", "bin", "webstore-lint.mjs");
const run = (...argv) => {
  const r = spawnSync(process.execPath, [BIN, ...argv], { encoding: "utf8" });
  return { code: r.status, out: r.stdout + r.stderr };
};

const cleanDir = join(here, "fixtures", "clean");
const badDir = join(here, "fixtures", "bad");

// The controls come FIRST here, because every assertion below narrows what the
// CLI accepts, and a narrowing that breaks ordinary use is a worse bug than the
// one it fixes.
check("cli: a clean extension exits 0", run(cleanDir).code === 0);
check("cli: a failing extension exits 1", run(badDir).code === 1);
check("cli: --json still exits 1 on a failure", run(badDir, "--json").code === 1);
check("cli: --json emits parseable json", (() => { try { JSON.parse(run(cleanDir, "--json").out); return true; } catch { return false; } })());
check("cli: --quiet is accepted", run(cleanDir, "--quiet").code === 0);
check("cli: --permissions is accepted", run(cleanDir, "--permissions").code === 0);
check("cli: --policy is accepted", run("--policy").code === 0);
check("cli: --help exits 0", run("--help").code === 0);

// s100: --json WAS TRUNCATED TO ONE PIPE BUFFER, and the check above could not
// see it because the clean fixture's report is under a kilobyte.
//
// `process.stdout` is async on a pipe and sync on a TTY, so
// `console.log(big); process.exit()` printed in full interactively and lost
// everything past 64 KB the moment anything consumed it. On automa's shipped
// release package: 1,502,987 bytes to a file, 65,536 through a pipe. Our own
// GitHub Action spawnSyncs this binary, so it was broken for every extension
// big enough to be worth linting - it refused to call an unparseable run clean,
// which is why this surfaced as a hard failure rather than a false green.
//
// THE SIZE AND THE TRANSPORT ARE BOTH PART OF THE FIXTURE, and the first
// version of this test got the size wrong and passed against a binary it was
// written to catch. Measured on the broken build:
//
//   400 sites  (137 KB)   spawnSync: PARSES      shell pipe: 65,536b, broken
//   2000 sites (343 KB)   spawnSync: 146,176b    shell pipe: 65,536b, broken
//
// spawnSync drains continuously, so it only loses the race above ~146 KB - the
// exact figure the corpus run reported. A shell pipe caps at one 64 KB buffer at
// every size. So the report must be comfortably over BOTH thresholds, and both
// transports are asserted: a CI runner may be either.
{
  const sites = 2000;
  const lines = Array.from({ length: sites }, (_, i) => `const handler${i} = new Function("return " + payload${i});`);
  const big = pkg({ "manifest.json": MANIFEST, "background.js": lines.join("\n") + "\n" });
  const evidenceCount = (s) => {
    try { return JSON.parse(s).findings.find((f) => f.rule === "remote-code")?.evidence?.length; }
    catch { return null; }
  };

  const r = spawnSync(process.execPath, [BIN, big, "--json"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  check("cli: a large --json report is not cut off at one pipe buffer",
    r.stdout.length > 200_000, `${r.stdout.length} bytes`);
  check("cli: and it is complete, parseable JSON through spawnSync", Boolean(evidenceCount(r.stdout)));
  // Only a report that arrived whole can carry every site we planted. A count is
  // the assertion because a truncated report still starts with valid-looking JSON.
  check("cli: every planted site survives the write to spawnSync",
    evidenceCount(r.stdout) === sites, `${evidenceCount(r.stdout)} of ${sites}`);
  check("cli: the exit code still says failure", r.status === 1, String(r.status));

  // The deterministic one: a real shell pipe, which is what `| jq` and every
  // redirect in a workflow file actually is.
  const piped = spawnSync("sh", ["-c", `${JSON.stringify(process.execPath)} ${JSON.stringify(BIN)} ${JSON.stringify(big)} --json | cat`],
    { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  check("cli: the report survives a real shell pipe intact",
    evidenceCount(piped.stdout) === sites, `${piped.stdout.length} bytes, ${evidenceCount(piped.stdout)} of ${sites}`);
}
check("cli: no arguments is a usage error", run().code === 2);

// An unknown flag was silently dropped, so `--permission` - one letter from the
// flagship ledger flag - ran the ordinary lint and exited 0. The user reads
// "0 failing" as an answer to the question they asked, and it is an answer to a
// different one.
{
  const r = run(cleanDir, "--permission");
  check("cli: a typo'd flag is refused rather than ignored", r.code === 2, `exit ${r.code}`);
  check("cli: ...and the message names the flag it did not understand", /--permission\b/.test(r.out));
  check("cli: ...and lists the flags it does understand", /--permissions/.test(r.out) && /--privacy-policy/.test(r.out));
}
// THE CONTROL: the correctly spelled flag must still work, or this is a
// regression wearing a fix's clothes. Covered by the --permissions check above,
// and pinned here against the exact string the refusal path prints.
check("cli: the real --permissions flag is not caught by the unknown-flag check",
  !/unknown flag/.test(run(cleanDir, "--permissions").out));

// --privacy-policy with nothing after it ran the lint, skipped the only network
// check in the tool, and exited 0. The user asked for their policy page to be
// fetched and was told nothing was wrong.
{
  const r = run(cleanDir, "--privacy-policy");
  check("cli: --privacy-policy with no url is refused", r.code === 2, `exit ${r.code}`);
  check("cli: ...and says the check was not run", /NOT run/.test(r.out));
}
// The control: a url that IS supplied must still be consumed as the flag's
// value and not mistaken for the directory. That trap is why VALUED exists.
check("cli: a supplied url is not linted as a directory",
  !/no manifest\.json/.test(run(cleanDir, "--privacy-policy", "https://example.com/privacy").out));

// "no manifest.json in this directory" was printed for a path that is not a
// directory and for one that does not exist, which sends a developer looking for
// a file inside a folder that was never there.
{
  const missing = run(join(here, "fixtures", "no-such-directory"));
  check("cli: a path that does not exist says so", /there is nothing at/.test(missing.out), missing.out.split("\n").find((l) => /FAIL/.test(l)));
  check("cli: ...and still exits 1", missing.code === 1);
  const atManifest = run(join(cleanDir, "manifest.json"));
  check("cli: being pointed at manifest.json says to point at the directory",
    /is the manifest itself/.test(atManifest.out), atManifest.out.split("\n").find((l) => /FAIL/.test(l)));
  const atFile = run(join(cleanDir, "content.js"));
  check("cli: being pointed at some other file says it is a file",
    /is a file, not an unpacked extension directory/.test(atFile.out));
  // THE CONTROL: a real directory that genuinely lacks a manifest must keep the
  // original message, which is the accurate one for that case.
  const emptyDir = mkdtempSync(join(tmpdir(), "wsl-"));
  check("cli: a real directory with no manifest keeps the original message",
    /no manifest\.json in this directory/.test(run(emptyDir).out));
}

// UNUSED-PERMISSIONS MUST NOT SAY "NEVER" ABOUT CODE IT COULD NOT READ (s098).
// Found on immersive-translate's shipped dist/chrome, where the four files that
// use storage, contextMenus and webRequest are 2.6-3.2 MB each and every one was
// over scan.mjs's read limit. We failed the package for permissions its unread
// code uses on every run, and the output looked entirely reasonable.
//
// The controls are the point of this block: the LAST case must keep firing at
// `fail`, or the fix has simply switched the rule off and every assertion above
// would pass just as happily on a rule that returns nothing.
{
  const perm = (extra) => ({
    manifest_version: 3, name: "Perms", description: "An extension used to test permission detection.",
    icons: { 16: "i.png" }, permissions: ["storage"], ...extra,
  });
  const mk = (files, manifest = perm()) => {
    const d = mkdtempSync(join(tmpdir(), "wsl-"));
    writeFileSync(join(d, "manifest.json"), JSON.stringify(manifest));
    for (const [n, t] of Object.entries(files)) writeFileSync(join(d, n), t);
    return lint(d).findings.find((f) => f.rule === "unused-permissions");
  };

  // 1. The bug itself: a minifier aliases the namespace. `Ne.storage` is a use.
  check("unused-permissions: an aliased namespace counts as used",
    !mk({ "app.js": 'var Ne=chrome;Ne.storage.local.get("k");' }),
    "reported unused despite Ne.storage");
  check("unused-permissions: a computed property access counts as used",
    !mk({ "app.js": 'const api=chrome;api["storage"].local.get("k");' }));
  check("unused-permissions: a destructured namespace counts as used",
    !mk({ "app.js": 'const { storage } = chrome;\nstorage.local.get("k");' }));
  check("unused-permissions: optional chaining counts as used",
    !mk({ "app.js": 'globalThis.chrome?.storage?.local.get("k");' }),
    "reported unused despite chrome?.storage");

  // 2. A file over the 2 MB limit is now STREAMED rather than left unread, so a
  //    permission used inside one is simply used. This fixture used to produce
  //    the "we did not read everything" warning; the tool now reads it.
  const big = mk({ "huge.js": `/*${"x".repeat(2 * 1024 * 1024)}*/\nchrome.storage.local.get("k");` });
  check("unused-permissions: a permission used inside an oversized file counts as used",
    !big, big ? `${big.severity}: ${big.title}` : "");

  // 2b. THE ASYMMETRY, AND THE MOST IMPORTANT ASSERTION IN THIS BLOCK. Having
  //     READ a bundle is not having SEEN the name in it: a minifier rewrites
  //     chrome into a one-letter local. So an oversized file that is minified
  //     must keep the finding at WARN even though every byte of it was read.
  //     Measured on the 82 cached release packages, dropping this would have
  //     turned 17 permissions in 7 packages into "declared but never used",
  //     among them contextMenus and idle on Bitwarden, which uses both.
  const bigMin = mk({ "huge.js": `var pad="${"x".repeat(2 * 1024 * 1024)}";var a=1;` });
  check("unused-permissions: an oversized MINIFIED file keeps the finding at warn",
    bigMin?.severity === "warn", bigMin ? `${bigMin.severity}: ${bigMin.title}` : "no finding at all");
  check("unused-permissions: ...and says why - a minifier renames the namespace",
    /minif|bundled/i.test(bigMin?.detail || ""), bigMin?.detail?.slice(0, 140));

  // 2c. CONTROL PAIR: the demotion above must come from the SHAPE of the file and
  //     not from its size, or every large package is permanently un-failable and
  //     the rule quietly stops working on exactly the packages that ship. Same
  //     size, same absence of the permission, ordinary line lengths.
  const bigPlain = mk({ "huge.js": `${"var a=1;\n".repeat(240000)}` });
  check("unused-permissions: CONTROL, an oversized file with ordinary lines does not demote",
    bigPlain?.severity === "fail", bigPlain ? `${bigPlain.severity}: ${bigPlain.title}` : "no finding at all");

  // 3. Minified but fully read: still cannot tell renamed from absent.
  const min = mk({ "b.js": `${"a".repeat(2500)}=1;` });
  check("unused-permissions: a minified package demotes fail to warn",
    min?.severity === "warn", min ? `${min.severity}: ${min.title}` : "no finding at all");

  // 4. THE CONTROL THAT MUST STILL FAIL. Small, unminified, fully read, and the
  //    permission genuinely appears nowhere - the commonest true positive, a
  //    feature deleted with its permission left behind.
  const gone = mk({ "app.js": 'chrome.storage.local.get("k"); // the bookmarks feature was removed' },
    perm({ permissions: ["storage", "bookmarks"] }));
  check("unused-permissions: a genuinely absent permission is still a fail",
    gone?.severity === "fail" && /bookmarks/.test(gone.title),
    gone ? `${gone.severity}: ${gone.title}` : "no finding at all");
  check("unused-permissions: ...and does not drag in the used one",
    !/storage/.test(gone?.title || ""), gone?.title);

  // 5. A SOURCE TREE. The permission's call site is inside a dependency that is
  //    not on disk, which is why refined-github was failed for scripting and
  //    alarms. The bare import is the tell.
  const src = mk({ "app.js": 'import debounce from "debounce-fn";\nchrome.storage.local.get("k");' },
    perm({ permissions: ["storage", "alarms"] }));
  check("unused-permissions: a bare import demotes fail to warn",
    src?.severity === "warn", src ? `${src.severity}: ${src.title}` : "no finding at all");
  check("unused-permissions: ...and says the directory is pre-build source",
    /pre-build source/.test(src?.detail || ""), src?.detail?.slice(0, 140));
}

// THE SOURCE-TREE RULE ITSELF. It must fire on what a bundler reads and stay
// silent on what it produces, or it is just noise on every clean package.
{
  const mkdir = (files) => {
    const d = mkdtempSync(join(tmpdir(), "wsl-"));
    writeFileSync(join(d, "manifest.json"), JSON.stringify({
      manifest_version: 3, name: "Src", description: "An extension used to test source detection.",
      icons: { 16: "i.png" }, permissions: ["storage"],
    }));
    for (const [n, t] of Object.entries(files)) writeFileSync(join(d, n), t);
    return lint(d).findings.find((f) => f.rule === "unbuilt-source");
  };
  const f = mkdir({ "app.js": 'import x from "clsx";\nchrome.storage.local.get("k");' });
  check("unbuilt-source: a bare module import is caught", !!f, "no finding");
  check("unbuilt-source: ...as a warning, not a failure", f?.severity === "warn", f?.severity);
  check("unbuilt-source: ...names the specifier that cannot resolve", /clsx/.test(f?.title + f?.detail));
  check("unbuilt-source: ...and cites no policy, because it is not a policy finding",
    !f?.citation, JSON.stringify(f?.citation)?.slice(0, 60));

  // THE CONTROLS. Each of these is a form a real BUILT package uses, and firing
  // on any of them would put a warning on every clean extension - which this
  // file's own header says is worth less than no warning at all.
  check("unbuilt-source: a relative import is not source",
    !mkdir({ "app.js": 'import x from "./util.js";\nchrome.storage.local.get("k");' }));
  check("unbuilt-source: an absolute path is not source",
    !mkdir({ "app.js": 'import x from "/lib/util.js";\nchrome.storage.local.get("k");' }));
  check("unbuilt-source: a URL specifier is not this finding",
    !mkdir({ "app.js": 'const m = await import("https://cdn.example.com/x.js");' }));
  check("unbuilt-source: a package with no imports at all is silent",
    !mkdir({ "app.js": 'chrome.storage.local.get("k");' }));

  // THE TWO THAT SHIPPED. Both are verbatim from immersive-translate's built
  // dist/chrome, which v1.0.4 flagged as source. The first matched the word
  // `from` inside a string literal and reported a module named ", ". Kept as
  // literals rather than paraphrased, because the paraphrase is what passes.
  check("unbuilt-source: CONTROL, the word from inside a string is not an import",
    !mkdir({ "app.js": 'return ["from", "to"].forEach((a) => { chrome.storage.local.get(a); });' }),
    "matched from inside a string literal");
  check("unbuilt-source: CONTROL, a minified bundle is not source",
    !mkdir({ "b.js": '(()=>{var t={919:(t,e)=>{"use strict";e.byteLength=function(t){return t.concat("from","x")}}};})();' }));
  // ...and the positive alongside them, so this block cannot pass by the rule
  // having been switched off.
  check("unbuilt-source: CONTROL PAIR, a real bare import still fires",
    !!mkdir({ "app.js": 'import x from "clsx";' }));
  check("unbuilt-source: a multi-line import list is still caught",
    !!mkdir({ "app.js": 'import {\n  debounce,\n} from "debounce-fn";' }));
  check("unbuilt-source: a side-effect import is caught",
    !!mkdir({ "app.js": 'import "webext-base-css";' }));
}


// --------------------------------------------------------------------------
// EVIDENCE MUST CONTAIN THE MATCH. Found on a real corpus repo (s106): a
// malicious postcss.config.mjs ends with the legitimate `export default
// config;`, then 507 spaces, then an 8.6 KB loader that resolves a C2 host from
// an Ethereum transaction and evals what it downloads. remote-code fired at FAIL
// and the evidence we printed was "export default config;" - innocent code, so
// the most serious finding the tool can produce read as an obvious false alarm.
{
  const padded = "export default config;" + " ".repeat(507) + 'const x=1;eval(fetched+payload);';
  const idx = padded.indexOf("eval(");
  const ev = excerptAround(padded, idx, "eval(".length);
  check("evidence follows a match hidden behind padding", ev.includes("eval("), ev);
  check("and it is marked as an excerpt rather than pretending to be the line start",
    ev.startsWith("..."), ev);
  check("CONTROL: the innocent prefix alone is NOT what gets reported",
    ev.trim() !== "export default config;", ev);

  // The control that makes the change safe: ordinary lines must be untouched,
  // or this silently rewrites the evidence on every other finding in the tool.
  const normal = "  const s = eval(userInput);";
  check("CONTROL: an ordinary line is byte-identical to the old first-160 rule",
    excerptAround(normal, normal.indexOf("eval("), 5) === normal.trim().slice(0, 160),
    excerptAround(normal, normal.indexOf("eval("), 5));
  const longButEarly = "  const s = eval(x); // " + "y".repeat(400);
  check("CONTROL: a long line whose match is early still reports from the start",
    excerptAround(longButEarly, longButEarly.indexOf("eval("), 5) === longButEarly.trim().slice(0, 160));

  // End to end through grep(), because excerptAround being right is not evidence
  // that the scanner actually calls it.
  const hits = grep([{ path: "postcss.config.mjs", lines: [padded] }], /eval\s*\(/);
  check("grep() itself reports evidence containing the match",
    hits.length === 1 && hits[0].text.includes("eval("), JSON.stringify(hits[0] && hits[0].text));
}

// ---------------------------------------------------------------------------
// A REMOTE <script> IN A PAGE NO EXTENSION SURFACE CAN OPEN IS A WEBSITE, NOT A
// VIOLATION (s107). Found by auditing the low-star band the s106 sampling fix
// added: Rat-S/ai-chat-exporter was FAILed on three sites and all three were its
// GitHub Pages site - a CDN tag in `docs/404.html` and a Tally widget in two
// feedback pages. The manifest references nothing under `docs/`.
//
// THE UNIT IS THE DIRECTORY AND THE CONTROLS BELOW ARE WHY. A page opened with
// chrome.tabs.create is never named in the manifest, so a per-file test would
// have deleted real violations; a directory the manifest references nothing in
// at all is a different thing entirely.
{
  const mkTree = (manifest, files) => {
    const d = mkdtempSync(join(tmpdir(), "wsl-"));
    writeFileSync(join(d, "manifest.json"), JSON.stringify({ manifest_version: 3, icons: { 16: "i.png" }, permissions: ["storage"], ...manifest }));
    for (const [f, body] of Object.entries(files)) {
      const full = join(d, f);
      mkdirSync(dirname(full), { recursive: true });
      writeFileSync(full, body);
    }
    return d;
  };
  const REMOTE = '<html><head><script src="https://cdn.tailwindcss.com"></script></head><body></body></html>\n';
  const POPUP = { manifest_version: 3, name: "Sited", description: "An extension whose repository also holds its marketing website.", action: { default_popup: "popup/popup.html" } };
  const rc = (dir, sev) => lint(dir).findings.find((f) => f.rule === "remote-code" && f.severity === sev && /<script>/.test(f.title));
  const cites = (f, path) => !!f && f.evidence.some((e) => e.file === path);

  const site = mkTree(POPUP, {
    "popup/popup.html": "<html><body></body></html>\n",
    "app.js": 'chrome.storage.local.get("k");\n',
    "docs/404.html": REMOTE,
  });
  check("a remote <script> in a directory the manifest never references is not a FAIL", !rc(site, "fail"));
  check("...it is reported as a warn instead", !!rc(site, "warn"));
  check("...and the site is still named, not deleted", cites(rc(site, "warn"), "docs/404.html"));

  // CONTROL 1: the manifest-referenced page itself. Must FAIL both before and
  // after this change, or the partition swallowed the rule.
  const inPopup = mkTree(POPUP, {
    "popup/popup.html": REMOTE,
    "app.js": 'chrome.storage.local.get("k");\n',
  });
  check("CONTROL: a remote <script> in the declared popup still FAILs", !!rc(inPopup, "fail"));

  // CONTROL 2: the page chrome.tabs.create opens. Not in the manifest, but it
  // sits in a directory that is - so it is part of the package.
  const sibling = mkTree(POPUP, {
    "popup/popup.html": "<html><body></body></html>\n",
    "popup/help.html": REMOTE,
    "app.js": 'chrome.storage.local.get("k");\n',
  });
  check("CONTROL: an undeclared page beside a declared one still FAILs", !!rc(sibling, "fail"));

  // CONTROL 3: everything at the root. The root is always live, so a flat
  // extension gets no free pass from this.
  const flat = mkTree({ manifest_version: 3, name: "Flat", description: "An extension that keeps every one of its pages at the package root.", action: { default_popup: "popup.html" } }, {
    "popup.html": "<html><body></body></html>\n",
    "extra.html": REMOTE,
    "app.js": 'chrome.storage.local.get("k");\n',
  });
  check("CONTROL: a page at the package root still FAILs", !!rc(flat, "fail"));

  // CONTROL 4: THE BUILD THAT FLATTENS. google/archat declares
  // `options_ui.page: "options.html"` and keeps the file at
  // `options/options.html`, where rollup flattens it on build. A
  // directory-only test demoted a real Google Tag Manager <script> in it. This
  // is the regression that control exists for, and only a source-tree A/B could
  // have found it - a built zip has no `options/` left to flatten.
  const flattened = mkTree({ manifest_version: 3, name: "Built", description: "An extension whose build flattens its options page to the package root.", options_ui: { page: "options.html" } }, {
    "options/options.html": REMOTE,
    "app.js": 'chrome.storage.local.get("k");\n',
  });
  check("CONTROL: a page the build flattens to a declared name still FAILs", !!rc(flattened, "fail"));

  // CONTROL 5: THE PARTITION IS NOT A DELETION. With a real violation present,
  // the website site must still be reported rather than dropped on the floor.
  const both = mkTree(POPUP, {
    "popup/popup.html": REMOTE,
    "app.js": 'chrome.storage.local.get("k");\n',
    "docs/404.html": REMOTE,
  });
  check("CONTROL: a real violation alongside a website hit still FAILs", cites(rc(both, "fail"), "popup/popup.html"));
  check("CONTROL: ...and the website hit is still reported, not dropped", cites(rc(both, "warn"), "docs/404.html"));
}

console.log(`\nwebstore-lint: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
