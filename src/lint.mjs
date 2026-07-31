// Run the rules and attach the policy citation to every finding.
//
// The citation is attached HERE rather than inside each rule, so a rule cannot
// invent a quote even by accident: a rule names a category id, and the words
// come from data/policy.json, which is generated from the verified dataset.

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { scan } from "./scan.mjs";
import { RULES } from "./rules.mjs";
import { audit } from "./audit.mjs";

const here = dirname(fileURLToPath(import.meta.url));
export const POLICY = JSON.parse(readFileSync(join(here, "..", "data", "policy.json"), "utf8"));

const EXPLAINER_BASE = "https://circadian-agent.com/research/chrome-rejections/";

const kebab = (s) =>
  String(s).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

// THE SLUG RULE IS NOT UNIFORM AND MUST NOT BE GUESSED FROM THE CODENAME.
//
// A category carrying ONE notification id lives at that id: Blue Argon is at
// /blue-argon. A category carrying SEVERAL lives at its TITLE instead: Blue
// Copper, Blue Lithium, Blue Magnesium and Blue Zinc are all at
// /prohibited-products, because publishing four pages with identical bodies is
// the thing search engines actually penalise.
//
// So kebab(notificationId) is right for 23 of the 36 ids and WRONG for the
// other 13. A dead link in a linter's output is worse than no link at all: the
// tool is then visibly wrong in front of somebody who is already having a bad
// day, which is how a tool gets muted. test/explainer.test.mjs pins every one
// of the 27 urls, and a live check confirmed all 27 resolve.
//
// This mirrors slugFor() in services/storefront/lib/chrome-rejections.ts. The
// two read the same category data so they cannot disagree about which
// categories exist, only about this rule - which is exactly what the suite
// checks, by asserting the two implementations AGREE on all 27.
export function pageUrlFor(category) {
  if (!category?.notificationIds?.length) return null;
  const slug =
    category.notificationIds.length === 1
      ? kebab(category.notificationIds[0])
      : kebab(category.title);
  return slug ? EXPLAINER_BASE + slug : null;
}

export function lint(root) {
  const ctx = scan(root);

  if (ctx.manifestError) {
    return {
      ...ctx,
      findings: [{
        rule: "manifest",
        severity: "fail",
        title: ctx.manifestError,
        // The generic sentence is still the fallback, because it is right for a
        // path that does not exist or is a file. When scan() recognised a
        // framework build it has something far more useful to say, and saying
        // both would bury it. Severity is unchanged: nothing was checked, and a
        // green check would be a lie whichever message we print.
        detail: ctx.manifestHint
          || "Point webstore-lint at the directory holding manifest.json, or at the unzipped package.",
        evidence: [],
        citation: null,
        citationUrl: null,
      }],
      counts: { fail: 1, warn: 0, info: 0 },
    };
  }

  const findings = [];
  for (const rule of RULES) {
    let produced;
    try {
      produced = rule.run(ctx) || [];
    } catch (e) {
      // One broken rule must not take the run down and, more importantly, must
      // not be mistaken for a clean result. It is reported as a finding about
      // the tool itself.
      findings.push({
        rule: rule.id,
        severity: "warn",
        title: `The rule ${rule.id} crashed and checked nothing: ${e.message}`,
        detail: "This is a bug in webstore-lint, not in your extension. Please report it with the manifest that triggered it.",
        evidence: [],
        citation: null,
        citationUrl: null,
      });
      continue;
    }
    for (const f of produced) {
      const citation = rule.category ? POLICY.categories[rule.category] || null : null;
      findings.push({
        rule: rule.id,
        ...f,
        citation,
        // Attached HERE, next to the citation it is derived from, so every
        // surface gets it from one place: the text renderer, --json, and the
        // GitHub Action, which reads --json and would otherwise have to
        // re-implement the slug rule and drift from it.
        citationUrl: pageUrlFor(citation),
        change: rule.change ? POLICY.changes2026.find((c) => c.name === rule.change) || null : null,
      });
    }
  }

  const order = { fail: 0, warn: 1, info: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  const counts = { fail: 0, warn: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;

  return { ...ctx, findings, counts };
}

// The permission ledger is a separate entry point because it answers a different
// question from the rules: not "is this a violation" but "what in your code
// requires this, and would a narrower permission have done". See src/audit.mjs.
export function auditPermissions(root) {
  const ctx = scan(root);
  if (ctx.manifestError) return { ...ctx, audit: null };
  return { ...ctx, audit: audit(ctx) };
}
