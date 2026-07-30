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

const here = dirname(fileURLToPath(import.meta.url));
export const POLICY = JSON.parse(readFileSync(join(here, "..", "data", "policy.json"), "utf8"));

export function lint(root) {
  const ctx = scan(root);

  if (ctx.manifestError) {
    return {
      ...ctx,
      findings: [{
        rule: "manifest",
        severity: "fail",
        title: ctx.manifestError,
        detail: "Point webstore-lint at the directory holding manifest.json, or at the unzipped package.",
        evidence: [],
        citation: null,
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
      });
      continue;
    }
    for (const f of produced) {
      findings.push({
        rule: rule.id,
        ...f,
        citation: rule.category ? POLICY.categories[rule.category] || null : null,
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
