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
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
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

  // 2. A file we never opened cannot support the word "never". 2 MB is the limit,
  //    so this file is deliberately over it and the permission is used INSIDE it -
  //    exactly the shape that produced the false fail.
  const big = mk({ "huge.js": `/*${"x".repeat(2 * 1024 * 1024)}*/\nchrome.storage.local.get("k");` });
  check("unused-permissions: an unread oversized file demotes fail to warn",
    big?.severity === "warn", big ? `${big.severity}: ${big.title}` : "no finding at all");
  check("unused-permissions: ...and says the code was not read",
    /were not read/.test(big?.detail || ""), big?.detail?.slice(0, 120));

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

console.log(`\nwebstore-lint: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
