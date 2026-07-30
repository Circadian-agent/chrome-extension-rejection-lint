#!/usr/bin/env node
// webstore-lint - check an unpacked Chrome extension against the Chrome Web
// Store program policies before you submit it.
//
//   npx webstore-lint ./my-extension
//   npx webstore-lint ./my-extension --json
//   npx webstore-lint ./my-extension --quiet     # findings only, no citations
//
// EXIT CODES: 0 clean or warnings only, 1 at least one failure, 2 bad usage.
// Warnings do not fail the run on purpose. Half of them are conditions this
// tool cannot resolve without seeing your store listing, and a CI gate that
// cannot be satisfied locally gets switched off.

import { lint, auditPermissions, POLICY } from "../src/lint.mjs";

const args = process.argv.slice(2);
const flags = new Set(args.filter((a) => a.startsWith("--")));
const target = args.find((a) => !a.startsWith("--"));

if (flags.has("--help") || (!target && !flags.has("--policy"))) {
  console.log(`webstore-lint - Chrome Web Store policy check, before you submit

  npx webstore-lint <extension-directory> [--json] [--quiet]
  npx webstore-lint <extension-directory> --permissions
                                        the permission ledger: what in your code
                                        requires each permission, and where a
                                        narrower one would have done
  npx webstore-lint --policy            list the policy data this build carries

Policy data pulled ${POLICY.datasetPulledAt}. Enforcement of the ${POLICY.enforcedFrom} updates:
${POLICY.enforcementQuote}

This tool reads your package. It cannot see your store listing, your privacy
policy page or your screenshots, and it is not affiliated with Google. A clean
run is not a promise of approval.`);
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

if (flags.has("--json")) {
  console.log(JSON.stringify(result, (k, v) => (k === "files" || k === "lines" ? undefined : v), 2));
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
    if (f.detail) console.log(wrap(f.detail, "      "));
    for (const e of (f.evidence || []).slice(0, 8)) {
      console.log(`        ${e.file}:${e.line}  ${e.text || e.match || ""}`);
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
  "where several of these are actually satisfied, and no local tool can see them.\n",
);
process.exit(fail ? 1 : 0);
