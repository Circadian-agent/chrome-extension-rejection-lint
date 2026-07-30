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

// storage declared while only web storage is used: the permission does nothing.
const webStorage = mkdtempSync(join(tmpdir(), "wsl-"));
writeFileSync(join(webStorage, "manifest.json"), JSON.stringify({ manifest_version: 3, name: "WebStore", description: "Remembers your last search using the browser's own storage.", icons: { 16: "i.png" }, permissions: ["storage"] }));
writeFileSync(join(webStorage, "app.js"), 'localStorage.setItem("last", "x");\n');
check("storage declared but only localStorage used is flagged as removable",
  narrowedFrom(ledgerOf(webStorage)).includes("storage"));

// And the same permission where it IS earned: chrome.storage is called.
check("storage is NOT flagged when chrome.storage is actually used",
  !narrowedFrom(ledgerOf(join(here, "fixtures", "clean"))).includes("storage"));

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

console.log(`\nwebstore-lint: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
