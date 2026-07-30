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

import { lint, POLICY } from "../src/lint.mjs";

const args = process.argv.slice(2);
const flags = new Set(args.filter((a) => a.startsWith("--")));
const target = args.find((a) => !a.startsWith("--"));

if (flags.has("--help") || (!target && !flags.has("--policy"))) {
  console.log(`webstore-lint - Chrome Web Store policy check, before you submit

  npx webstore-lint <extension-directory> [--json] [--quiet]
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
