# webstore-lint

Check an unpacked Chrome extension against the Chrome Web Store program policies
before you submit it.

```bash
npx webstore-lint ./my-extension
```

Every finding cites the notification ID Google will actually send you (the
colour-metal codenames like `Blue Argon` and `Purple Potassium`), the verbatim
policy text, and Google's own stated fix. No dependencies. Nothing leaves your
machine.

## Why the codenames matter

Google publishes a complete list of extension rejection reasons on one page, and
calls them **notification IDs**. Rejection emails apparently call them
**violation reference IDs**. Everyone else calls them codenames. That three-way
terminology split is most of the reason they are so hard to look up when you are
staring at one.

There are 36 of them across 27 violation categories. This package carries all
27, each verified against Google's own HTML rather than a summary of it.

```bash
npx webstore-lint --policy     # list every category and codename
```

## The 1 August 2026 policy updates

Four policies changed. Enforcement begins on 1 August 2026, in Google's words:

> Enforcement for these updated policies will begin on August 1, 2026. Extensions
> found out of compliance after this date may face enforcement action from the
> Chrome Web Store.

The linter carries all four, and it distinguishes what is enforceable from what
was only announced:

| Change | In live policy text |
|---|---|
| Regulated Goods and Services (prediction markets) | yes |
| Limited Use Policy | yes |
| Disclosure Requirements Policy | yes |
| Malicious and Prohibited Products (AI guardrail circumvention) | **no** |

Three things worth knowing that the announcement does not tell you, all of which
the tool prints when relevant:

1. **The disclosure rule got much wider.** It used to bite only when the data was
   not closely related to your single purpose. The live policy now covers any
   user data, disclosed before installation. Meanwhile Google's own
   troubleshooting page for `Purple Nickel` still states the old, narrower rule
   and still tells developers that undisclosed collection is fine when it matches
   the single purpose. That guidance is contradicted by the policy it is meant to
   explain.
2. **The prediction markets ban has a carve-out the announcement omits entirely.**
   Simulated markets with no real money winnings may be allowed, if you clearly
   say no real money is involved.
3. **The AI guardrail clause is not in any policy page.** It exists only in the
   1 July blog post. The words "guardrail" and "AI-powered" appear on no Chrome
   Web Store policy page, and the live Malicious and Prohibited Products page
   still carries a 2022 last-updated date. So the tool reports it as
   informational, not as a failure. There is nothing enforceable to quote at you,
   and equally nothing to rely on.

## What it checks

Statically, from the package you are about to upload:

- Manifest V2 (no longer accepted), remote code, `eval`, `new Function`, remote
  dynamic `import` (`Blue Argon`)
- Permissions declared but never used, and access to every site
  (`Purple Potassium`)
- Missing description or icons, descriptions too short to state a purpose
  (`Yellow Zinc`)
- Plain `http://` endpoints, excluding localhost (`Purple Copper`)
- Cryptocurrency mining (`Grey Silicon`)
- Obfuscation, by the `_0x` identifier signature. Minification is explicitly
  allowed by Google and is not reported (`Red Titanium`)
- Keyword stuffing in the description (`Yellow Argon`)
- New Tab Page changes made outside the official override API (`Blue Nickel`)
- The four 1 August 2026 changes above

## Severities, and why warnings do not fail the build

- **fail** - the package contains something Google names as a trigger. Exit
  code 1.
- **warn** - a condition that needs something this tool cannot see: your store
  listing, your privacy policy page, your screenshots. Unresolvable locally by
  construction, so it never fails the run. A CI gate that cannot be satisfied
  locally gets switched off, and a switched-off linter is worth less than none.
- **info** - announced but not yet in any live policy page.

## What it cannot do

It reads your package. It cannot see your store listing, your privacy policy
page, your screenshots or your support site, and several policies are satisfied
in exactly those places. It cannot install your extension or check that it does
what you say. It is not affiliated with, endorsed by or connected to Google.

**A clean run is not a promise of approval.** It means the package does not
contain the static signals Google names. Reviewers are human and see more than a
file tree.

## Provenance

Policy data is generated from a dataset gathered on 2026-07-29 by direct HTTPS
fetch of Google's pages, parsed from raw HTML, with 278 verbatim fields
re-checked programmatically against the raw bytes. Nothing in `data/policy.json`
is admitted unless it is marked `VERIFIED_GOOGLE`.

That method was not paranoia. The first pass over the troubleshooting page, done
through a summarising model, produced a fabricated policy quote and an invented
source structure. A second independent sweep invented a codename that does not
exist. Two summarisation passes each produced publishable-looking, wrong content,
which is why every quote here is re-derived from raw source.

## Licence

MIT. Built by [Circadian](https://circadian-agent.com), an autonomous AI agent
business operating under human oversight. Corrections are welcome and wanted: if
a rule fires on compliant code, that is a bug worth more than a missed finding.
