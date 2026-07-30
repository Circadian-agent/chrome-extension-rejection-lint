// Tests for the explainer link the linter puts on every cited finding.
//
// THE ONE THAT MATTERS MOST is that the linter must never emit a url to a page
// that does not exist. This tool prints these links to strangers whose extension
// has just been rejected, and a 404 in that moment is the tool being visibly
// wrong in front of somebody already having a bad day. That is how a tool gets
// muted, which costs more than the link was ever worth.
//
// THE SLUG RULE IS THE TRAP, and guessing it is the bug this file exists to
// prevent. 23 of the 36 codenames live at their own name (Blue Argon ->
// /blue-argon) but the other 13 share a page named after their CATEGORY (Blue
// Copper, Blue Lithium, Blue Magnesium and Blue Zinc are all at
// /prohibited-products). kebab(notificationId) therefore looks right, passes a
// spot check on whichever codename you happen to try first, and mints 13 dead
// links. There is an explicit negative control for exactly that below.
//
// WHY THE 27 URLS ARE PINNED RATHER THAN COMPUTED. Computing the expected value
// with the same rule the code uses proves only that the function is
// deterministic - the two would agree even if both were wrong. The pinned list
// was verified against the live site: all 27 returned 200 AND contained their
// own notification id, checked alongside a bogus slug that returned 404, so the
// probe could tell a real page from a challenge page or a soft 404.
//
// So this list is a record of what was OBSERVED to exist, and the drift guard
// below is the point of it: if data/policy.json ever gains a category, changes a
// title, or moves a codename, this suite goes red. That is correct and it is not
// noise. A new category needs a page published on the site BEFORE the linter is
// allowed to link to it, and nothing else in the repo would notice the gap.

import { lint, pageUrlFor, POLICY } from "../src/lint.mjs";
import { annotation, summary } from "../action/report.mjs";
import { spawnSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
let pass = 0, fail = 0;
const check = (name, cond, extra = "") => {
  if (cond) { pass++; }
  else { fail++; console.log(`  FAIL  ${name}${extra ? `\n        ${extra}` : ""}`); }
};

const BAD = join(here, "fixtures", "bad");
const CLI = join(here, "..", "bin", "webstore-lint.mjs");
const BASE = "https://circadian-agent.com/research/chrome-rejections/";

// Verified live 2026-07-30: 27/27 returned 200 and contained their own
// notification id. Negative control "definitely-not-a-real-code-zzz" returned
// 404, so a 200 here means a real page rather than a challenge response.
// All 27, keyed by the category id in data/policy.json. The keys are read from
// the data rather than guessed: a first draft of this file invented plausible
// ids ("online-gambling" for what is really "gambling") and eight of them did
// not exist, which the drift guard caught on its first run.
const PINNED = {
  "additional-requirements-for-manifest-v3": "blue-argon",
  "does-not-work": "yellow-magnesium",
  "excessive-permissions": "purple-potassium",
  "no-metadata": "yellow-zinc",
  "deceptive-behavior": "deceptive-behavior",
  "udp-disclosure-policy": "purple-lithium",
  "illegal-activities": "grey-zinc",
  "gambling": "grey-copper",
  "pornography": "grey-lithium",
  "hate": "grey-magnesium",
  "not-family-safe": "grey-nickel",
  "violence": "grey-potassium",
  "single-use": "single-purpose",
  "udp-prominent-disclosure": "purple-nickel",
  "udp-secure": "purple-copper",
  "udp-other-requirements": "purple-magnesium",
  "cryptocurrency-mining": "grey-silicon",
  "prohibited-products": "prohibited-products",
  "keyword-stuffing": "yellow-argon",
  "redirection": "yellow-lithium",
  "spam": "yellow-nickel",
  "circumvents-api-ntp": "circumvents-the-overrides-api",
  "uws-distribution": "red-zinc",
  "obfuscation": "red-titanium",
  "minimum_functionality": "yellow-potassium",
  "affiliate_ads": "grey-titanium",
  "enforcement_circumvention": "blue-titanium",
};

// ---------------------------------------------------------------- slug rule

{
  // Every category resolves to a url, and every url is inside our own site.
  // "Returns a string" is not enough: a bug that returned the base url for
  // everything would satisfy that and point all 36 codenames at one page.
  const cats = Object.values(POLICY.categories);
  check("policy carries 27 categories", cats.length === 27, `got ${cats.length}`);

  const urls = cats.map(pageUrlFor);
  check("every category resolves to a url", urls.every((u) => typeof u === "string" && u.startsWith(BASE)));

  const slugs = urls.map((u) => u.slice(BASE.length));
  check("no category resolves to an empty slug", slugs.every((s) => s.length > 0));
  check(
    "all 27 slugs are distinct",
    new Set(slugs).size === 27,
    `${new Set(slugs).size} distinct`,
  );
  check(
    "no slug carries a character that would need escaping in a url",
    slugs.every((s) => /^[a-z0-9-]+$/.test(s)),
    slugs.filter((s) => !/^[a-z0-9-]+$/.test(s)).join(", "),
  );
}

{
  // THE DRIFT GUARD. Named categories are pinned to the slug observed live.
  const misses = [];
  for (const [id, expected] of Object.entries(PINNED)) {
    const c = POLICY.categories[id];
    if (!c) { misses.push(`${id}: category no longer exists`); continue; }
    const got = pageUrlFor(c);
    if (got !== BASE + expected) misses.push(`${id}: expected ${expected}, got ${got}`);
  }
  check("every pinned category still resolves to its verified live url", misses.length === 0, misses.join("\n        "));

  // Without this, the loop above only proves the categories we already knew
  // about are unchanged. A NEW category added to policy.json is the dangerous
  // case - it has no page on the site yet, so the linter would start printing a
  // url that 404s - and iterating PINNED could never notice it.
  const unpinned = Object.keys(POLICY.categories).filter((k) => !(k in PINNED));
  check(
    "no category exists that has not been verified live",
    unpinned.length === 0,
    unpinned.length
      ? `${unpinned.join(", ")} - publish the page, confirm it returns 200, then pin it here`
      : "",
  );
}

{
  // THE NEGATIVE CONTROL, and it is the whole reason this file exists.
  // A category carrying several codenames must NOT resolve to its first
  // codename. This is the assertion that fails if somebody "simplifies"
  // pageUrlFor to kebab(notificationIds[0]).
  const shared = Object.values(POLICY.categories).filter((c) => c.notificationIds.length > 1);
  check("the policy really does contain multi-codename categories", shared.length > 0, "control is vacuous without one");

  const wrong = [];
  for (const c of shared) {
    const naive = BASE + c.notificationIds[0].toLowerCase().replace(/[^a-z0-9]+/g, "-");
    const got = pageUrlFor(c);
    if (got === naive) wrong.push(`${c.title} resolved to the naive ${naive}`);
  }
  check(
    "a shared category never resolves to kebab(first codename)",
    wrong.length === 0,
    wrong.join("\n        "),
  );

  // And the positive half of the same rule: a lone codename DOES use its name.
  const solo = Object.values(POLICY.categories).filter((c) => c.notificationIds.length === 1);
  const soloOk = solo.every(
    (c) => pageUrlFor(c) === BASE + c.notificationIds[0].toLowerCase().replace(/[^a-z0-9]+/g, "-"),
  );
  check("a lone codename resolves to its own name", soloOk);

  // Count the split, so a data change that moved codenames between the two
  // branches cannot pass silently.
  check("13 codenames sit on a shared page", shared.reduce((n, c) => n + c.notificationIds.length, 0) === 13);
  check("23 codenames sit on their own page", solo.length === 23, `${solo.length}`);
}

{
  // Null safety. A finding with no citation must produce no link rather than a
  // url ending in "undefined", which would 404 and look like a broken page.
  check("no category yields null", pageUrlFor(null) === null);
  check("empty notificationIds yields null", pageUrlFor({ title: "x", notificationIds: [] }) === null);
  check("missing notificationIds yields null", pageUrlFor({ title: "x" }) === null);
}

// ------------------------------------------------------- findings carry it

{
  const result = lint(BAD);
  const cited = result.findings.filter((f) => f.citation);

  // The control: without this, the two checks below pass on an empty list, which
  // is exactly what a linter that produced nothing would give.
  check("the bad fixture produces cited findings", cited.length > 0, `${cited.length}`);

  check(
    "every cited finding carries citationUrl",
    cited.every((f) => typeof f.citationUrl === "string" && f.citationUrl.startsWith(BASE)),
    cited.filter((f) => !f.citationUrl).map((f) => f.rule).join(", "),
  );
  check(
    "citationUrl always matches the finding's own citation",
    cited.every((f) => f.citationUrl === pageUrlFor(f.citation)),
  );
  check(
    "an uncited finding carries citationUrl null, not undefined",
    result.findings.filter((f) => !f.citation).every((f) => f.citationUrl === null),
  );
}

{
  // The manifest-unreadable path builds its finding on a different branch and
  // would be the easy one to forget.
  const broken = lint(join(here, "fixtures", "does-not-exist-at-all"));
  check("the unreadable-manifest finding still has the field", broken.findings[0].citationUrl === null);
}

// ------------------------------------------------------------- the surfaces

{
  const r = spawnSync(process.execPath, [CLI, BAD], { encoding: "utf8" });
  const out = r.stdout;
  check("the CLI prints at least one explainer line", out.includes("explained: " + BASE));
  check("the CLI links Blue Argon to its own page", out.includes(BASE + "blue-argon"));
  check("the CLI still prints Google's policy url", out.includes("developer.chrome.com"));
  check("the CLI footer names the repo", out.includes("github.com/Circadian-agent/webstore-lint"));

  // --quiet drops the verbatim policy quote but must KEEP the link: quiet is
  // for less text, and one url is the least text that still tells a reader
  // where the answer is.
  const q = spawnSync(process.execPath, [CLI, BAD, "--quiet"], { encoding: "utf8" });
  check("--quiet still prints the explainer link", q.stdout.includes("explained: " + BASE));
  check("--quiet really is quieter", q.stdout.length < out.length, `${q.stdout.length} vs ${out.length}`);
}

{
  const r = spawnSync(process.execPath, [CLI, BAD, "--json"], { encoding: "utf8" });
  const parsed = JSON.parse(r.stdout);
  const cited = parsed.findings.filter((f) => f.citation);
  check("--json survives the new field", cited.length > 0);
  check(
    "--json carries citationUrl on every cited finding",
    cited.every((f) => typeof f.citationUrl === "string"),
  );
}

{
  // The Action reads --json, so it gets the field for free. These check it is
  // actually rendered rather than merely present in the object.
  const f = lint(BAD).findings.find((x) => x.citation);
  const a = annotation(f, f.evidence?.[0] || null);
  // encData escapes only percent, CR and LF, so the url survives verbatim in
  // the body. If that encoding ever widens, this check is what notices.
  check("the annotation body carries the explainer url", a.includes(f.citationUrl), a.slice(0, 300));
  check("the annotation still carries Google's url", a.includes("developer.chrome.com"));

  const md = summary(lint(BAD), { datasetPulledAt: POLICY.datasetPulledAt, enforcedFrom: POLICY.enforcedFrom });
  check("the job summary links the explainer", md.includes("[explained](" + BASE));
  check("the job summary still links Google", md.includes("developer.chrome.com"));
}

// ------------------------------------------------------------- house style

{
  // Outward copy: no em dashes and no non-ASCII. Checked on the rendered
  // output rather than the source, because that is what a reader sees.
  const out = spawnSync(process.execPath, [CLI, BAD], { encoding: "utf8" }).stdout;
  const bad = [...out].filter((ch) => ch.charCodeAt(0) > 126);
  check("the CLI output is pure ASCII", bad.length === 0, `found: ${[...new Set(bad)].join(" ")}`);
  check("the CLI output contains no em dash", !out.includes("—"));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
