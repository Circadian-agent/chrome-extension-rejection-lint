#!/usr/bin/env node
// webstore-lint - check an unpacked Chrome extension against the Chrome Web
// Store program policies before you submit it.
//
//   npx github:Circadian-agent/chrome-extension-rejection-lint ./my-extension
//   npx github:Circadian-agent/chrome-extension-rejection-lint ./my-extension --json
//   npx github:Circadian-agent/chrome-extension-rejection-lint ./my-extension --quiet
//
// THE COMMAND NAMES GitHub BECAUSE THE npm NAME IS NOT PUBLISHED. npm requires a
// human registrant. Do not print the bare `npx webstore-lint` anywhere a reader
// sees it until that lands: it 404s, and this help text is read by people who
// have already got the tool working, so a wrong line here teaches them a command
// that fails the next time they reach for it.
//
// EXIT CODES: 0 clean or warnings only, 1 at least one failure, 2 bad usage.
// Warnings do not fail the run on purpose. Half of them are conditions this
// tool cannot resolve without seeing your store listing, and a CI gate that
// cannot be satisfied locally gets switched off.

import { lint, auditPermissions, POLICY, pageUrlFor } from "../src/lint.mjs";
import { checkPolicyUrl } from "../src/privacy.mjs";

const args = process.argv.slice(2);
const flags = new Set(args.filter((a) => a.startsWith("--")));

// Flags that TAKE A VALUE. The value must be removed before the directory is
// picked out of what is left, or `--privacy-policy https://x ./ext` lints the URL
// as a directory and reports that manifest.json is missing - a confusing failure
// that blames the wrong argument.
const VALUED = new Set(["--privacy-policy"]);
const KNOWN = new Set(["--help", "--json", "--quiet", "--policy", "--permissions", ...VALUED]);

// A FLAG WE DO NOT RECOGNISE IS AN ERROR, NOT SILENCE. Unknown flags used to be
// dropped on the floor, so `--permission` - a one-letter slip away from the
// flagship `--permissions` ledger - ran the ordinary lint instead and exited 0.
// The user reads "0 failing" and believes they were told something about the
// report they asked for. This is scan.mjs's own rule about silent skips applied
// to the argument list: a tool that says "clean" about a question it never
// answered is worse than one that refuses.
const unknown = [...flags].filter((f) => !KNOWN.has(f));
if (unknown.length) {
  console.error(`unknown flag${unknown.length > 1 ? "s" : ""}: ${unknown.join(", ")}`);
  console.error(`known flags: ${[...KNOWN].sort().join(", ")}`);
  process.exit(2);
}

const valueOf = (flag) => {
  const i = args.indexOf(flag);
  if (i < 0) return null;
  const v = args[i + 1];
  return v && !v.startsWith("--") ? v : null;
};

// Same reasoning, one level down: `--privacy-policy` with no url behind it USED
// TO RUN THE LINT AND EXIT 0, having quietly skipped the only network check in
// the tool. The user explicitly asked for their policy page to be fetched and
// was told nothing had gone wrong.
for (const f of VALUED) {
  if (flags.has(f) && !valueOf(f)) {
    console.error(`${f} needs a url after it, and the check was NOT run.`);
    console.error(`  webstore-lint ./my-extension ${f} https://example.com/privacy`);
    process.exit(2);
  }
}
const consumed = new Set();
for (const f of VALUED) {
  const i = args.indexOf(f);
  if (i >= 0 && args[i + 1] && !args[i + 1].startsWith("--")) consumed.add(i + 1);
}
const target = args.find((a, i) => !a.startsWith("--") && !consumed.has(i));
const policyUrl = valueOf("--privacy-policy");

if (flags.has("--help") || (!target && !flags.has("--policy"))) {
  console.log(`webstore-lint - Chrome Web Store policy check, before you submit

  webstore-lint <extension-directory> [--json] [--quiet]
  webstore-lint <extension-directory> --permissions
                                        the permission ledger: what in your code
                                        requires each permission, and where a
                                        narrower one would have done
  webstore-lint <extension-directory> --privacy-policy <url>
                                        additionally check that your listing's
                                        privacy policy URL actually answers. This
                                        is the ONLY flag that touches the network,
                                        and only when you pass a url
  webstore-lint --policy                list the policy data this build carries

Not on npm yet, so the one-liner is:
  npx github:Circadian-agent/chrome-extension-rejection-lint <extension-directory>

Policy data pulled ${POLICY.datasetPulledAt}. Enforcement of the ${POLICY.enforcedFrom} updates:
${POLICY.enforcementQuote}

This tool reads your package. Without --privacy-policy it makes no network
request at all, and it cannot see your store listing or your screenshots. It is
not affiliated with Google. A clean run is not a promise of approval.`);
  process.exit(flags.has("--help") ? 0 : 2);
}

if (flags.has("--policy")) {
  console.log(`${Object.keys(POLICY.categories).length} verified rejection categories, from ${POLICY.generatedFrom}\n`);
  for (const [id, c] of Object.entries(POLICY.categories)) {
    console.log(`  ${c.notificationIds.join(", ").padEnd(38)} ${c.title}`);
  }
  console.log(`\n${POLICY.changes2026.length} changes effective ${POLICY.enforcedFrom}:`);
  for (const c of POLICY.changes2026) {
    console.log(`  ${c.inLivePolicyText ? "in live policy text" : "ANNOUNCED ONLY, not in any policy page"}  ${c.name}`);
  }
  process.exit(0);
}

const wrapEarly = (s, indent = "    ", width = 92) => {
  const words = String(s).split(/\s+/);
  const lines = [];
  let cur = indent;
  for (const w of words) {
    if (cur.trim() && cur.length + w.length + 1 > width) { lines.push(cur); cur = indent; }
    cur += (cur.trim() ? " " : "") + w;
  }
  if (cur.trim()) lines.push(cur);
  return lines.join("\n");
};

// --permissions: the ledger. This is the evidence a Chrome Web Store permission
// justification has to rest on, and the comparative question ("could a narrower
// permission have done this") that Purple Potassium is actually decided on.
if (flags.has("--permissions")) {
  const { audit: a, root, manifestError } = auditPermissions(target);
  if (manifestError) { console.error(manifestError); process.exit(1); }

  if (flags.has("--json")) { console.log(JSON.stringify(a, null, 2)); process.exit(0); }

  const cite = POLICY.categories["excessive-permissions"];
  console.log(`\nwebstore-lint permission ledger  ${root}`);
  console.log(`manifest v${a.manifestVersion}, ${a.confidence.filesRead} JavaScript file(s) read as source\n`);

  if (!a.ledger.length) console.log("  The manifest declares no named permissions.\n");

  for (const l of a.ledger) {
    const tag = l.status === "used" ? "used   " : l.status === "unused" ? "UNUSED " : "unknown";
    console.log(`  ${tag} ${l.permission}${l.siteCount ? `  (${l.siteCount} call site${l.siteCount === 1 ? "" : "s"})` : ""}${l.where === "optional_permissions" ? "  [optional]" : ""}`);
    if (l.disclosure) console.log(`          discloses: ${l.disclosure}`);
    if (l.note) console.log(wrapEarly(l.note, "          "));
    for (const s of l.sites.slice(0, 6)) console.log(`          ${s.file}:${s.line}  ${s.text}`);
    if (l.siteCount > 6) console.log(`          ... and ${l.siteCount - 6} more`);
    console.log("");
  }

  if (a.narrowings.length) {
    console.log(`\nCould a narrower permission have done the job? Google's words:`);
    console.log(wrapEarly(`"${cite.policyQuote}"`, "    "));
    console.log(`    ${cite.policyUrl}\n`);
    for (const n of a.narrowings) {
      console.log(`  ${n.from}  ->  ${n.to}`);
      console.log(wrapEarly(n.why, "      "));
      for (const e of n.evidence.slice(0, 6)) console.log(`      ${e.file}${e.line ? ":" + e.line : ""}  ${e.text}`);
      if (n.evidence.length > 6) console.log(`      ... and ${n.evidence.length - 6} more`);
      console.log(wrapEarly(`This suggestion is WRONG if ${n.wrongIf}`, "      "));
      console.log("");
    }
  }

  if (a.disclosures.length) {
    console.log(`\nPrivacy practices tab, from what the code actually touches:`);
    for (const d of a.disclosures) console.log(`  ${d.permission.padEnd(16)} ${d.category}`);
    console.log("");
  }

  console.log(wrapEarly(a.confidence.caveat, "  "));
  for (const m of a.confidence.minified) console.log(`  minified, so call sites are unreliable: ${m.file} (longest line ${m.longestLine} chars)`);
  for (const s of a.confidence.skipped) console.log(`  not read: ${s.path} (${s.why})`);
  console.log("");
  process.exit(0);
}

const result = lint(target);

// The one network check, merged into the same findings list so it renders and
// exits through the same path as everything else. Only reached when a url was
// given, and skipped entirely when the manifest could not be read - there is no
// point telling somebody their policy url is fine when we could not find their
// extension.
if (policyUrl && !result.manifestError) {
  const extra = await checkPolicyUrl(policyUrl);
  for (const f of extra) {
    // These findings are built here rather than in lint(), so they need the same
    // two derived fields attached by the same rule. A finding that reaches the
    // renderer without citationUrl silently loses its explainer link, and the
    // only reader who would notice is the one whose privacy policy failed.
    const citation = f.category ? POLICY.categories[f.category] || null : null;
    result.findings.push({
      ...f,
      citation,
      citationUrl: pageUrlFor(citation),
      change: null,
    });
    result.counts[f.severity]++;
  }
  const order = { fail: 0, warn: 1, info: 2 };
  result.findings.sort((a, b) => order[a.severity] - order[b.severity]);
} else if (policyUrl && result.manifestError) {
  console.error(
    "--privacy-policy was skipped: the extension directory could not be read, so " +
      "the finding below is the one that matters first.",
  );
}

// PROCESS.EXIT() TRUNCATES A PIPE, AND THIS COST US THE WHOLE CI STORY.
// `process.stdout` is asynchronous when fd 1 is a pipe and synchronous when it
// is a TTY, so `console.log(big); process.exit()` prints in full interactively
// and is cut to one 64 KB pipe buffer everywhere else. Measured on automa's
// shipped release package: 1,502,987 bytes to a file, 65,536 through a pipe -
// the same command, differing only in what fd 1 is, with 96% of the report
// discarded and the exit code still 1.
//
// Anything that consumes --json reads a pipe by definition. That includes our
// own GitHub Action, which spawnSyncs this file: it refuses to report a run it
// cannot parse, so it failed loudly rather than passing a broken extension -
// but it failed on every package big enough to matter, which is every real one.
// Interactive use is exactly the case that cannot show this.
//
// So: hand the data over, WAIT for the callback that says it reached the OS,
// and only then exit. `process.exitCode` alone is not enough here because the
// human branch below must not also run.
if (flags.has("--json")) {
  await new Promise((resolve) => {
    process.stdout.write(
      JSON.stringify(result, (k, v) => (k === "files" || k === "lines" ? undefined : v), 2) + "\n",
      resolve,
    );
  });
  process.exit(result.counts.fail ? 1 : 0);
}

const MARK = { fail: "FAIL", warn: "WARN", info: "INFO" };
const wrap = (s, indent = "    ", width = 92) => {
  const words = String(s).split(/\s+/);
  const lines = [];
  let cur = indent;
  for (const w of words) {
    if (cur.trim() && cur.length + w.length + 1 > width) { lines.push(cur); cur = indent; }
    cur += (cur.trim() ? " " : "") + w;
  }
  if (cur.trim()) lines.push(cur);
  return lines.join("\n");
};

console.log(`\nwebstore-lint  ${result.root}`);
console.log(`policy data pulled ${POLICY.datasetPulledAt}, ${POLICY.enforcedFrom} updates included\n`);

if (!result.findings.length) {
  console.log("No findings.\n");
} else {
  for (const f of result.findings) {
    console.log(`${MARK[f.severity]}  ${f.title}`);
    console.log(`      rule ${f.rule}${f.citation ? `  |  ${f.citation.notificationIds.join(", ")}  |  ${f.citation.title}` : ""}`);
    // ONE LINE, ALWAYS PRINTED, INCLUDING UNDER --quiet. This output is the
    // artifact that travels: a developer pastes it into an issue, a forum
    // thread or a question, and until now nothing in it said what produced it
    // or where to read more. The codename is the exact phrase a rejected
    // developer searches for, and this is the page answering it.
    if (f.citationUrl) console.log(`      explained: ${f.citationUrl}`);
    if (f.detail) console.log(wrap(f.detail, "      "));
    for (const e of (f.evidence || []).slice(0, 8)) {
      // Not all evidence is a line in a file. The privacy policy check's evidence
      // is a url and an HTTP status, and printing "url:undefined" for it reads
      // like a bug in the tool.
      console.log(`        ${e.file}${e.line ? ":" + e.line : ""}  ${e.text || e.match || ""}`);
    }
    if ((f.evidence || []).length > 8) console.log(`        ... and ${f.evidence.length - 8} more`);
    if (!flags.has("--quiet") && f.citation) {
      console.log(`\n      What Google's policy says, verbatim:`);
      console.log(wrap(`"${f.citation.policyQuote}"`, "        "));
      console.log(`        ${f.citation.policyUrl}`);
      if (f.citation.fixes?.length) {
        console.log(`      Google's stated fix:`);
        for (const fix of f.citation.fixes) console.log(wrap(`- ${fix}`, "        "));
      }
    }
    if (!flags.has("--quiet") && f.change) {
      console.log(`\n      Changed ${POLICY.enforcedFrom}. ${f.change.inLivePolicyText ? "Live policy text now reads:" : "NOT IN ANY LIVE POLICY PAGE. The announcement reads:"}`);
      console.log(wrap(`"${f.change.inLivePolicyText ? f.change.livePolicyQuote : f.change.blogQuote}"`, "        "));
      console.log(wrap(`Watch out: ${f.change.discrepancy}`, "        "));
      if (f.change.carveOut) console.log(wrap(`Carve-out the announcement omitted: ${f.change.carveOut}`, "        "));
    }
    console.log("");
  }
}

for (const s of result.skipped) console.log(`      not read: ${s.path} (${s.why})`);
if (result.skipped.length) console.log("");

const { fail, warn, info } = result.counts;
console.log(`${fail} failing, ${warn} needing your judgement, ${info} informational`);
console.log(
  "This reads your package only. Your store listing, privacy policy page and screenshots are " +
  "where several of these are actually satisfied, and no local tool can see them.",
);
console.log("webstore-lint is free and open source: https://github.com/Circadian-agent/chrome-extension-rejection-lint\n");
// Same trap, same reason: the human report is also large on a real extension
// and it is also piped (`webstore-lint . | less`, or into a file in CI). Setting
// the code instead of calling exit() lets Node drain stdout and then leave with
// it. Nothing runs after this line, so there is nothing to guard against.
process.exitCode = fail ? 1 : 0;
