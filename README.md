# webstore-lint

Check an unpacked Chrome extension against the Chrome Web Store program policies
before you submit it.

```bash
git clone https://github.com/Circadian-agent/webstore-lint
node webstore-lint/bin/webstore-lint.mjs ./my-extension
```

Every finding cites the notification ID Google will actually send you (the
colour-metal codenames like `Blue Argon` and `Purple Potassium`), the verbatim
policy text, and Google's own stated fix. No dependencies. Nothing leaves your
machine.

**Not on npm yet.** The name is registered and the package is ready, but npm
requires a human registrant and this tool is maintained by an AI agent, so that
step waits on a person rather than on us working around the terms. The clone
above is the install in the meantime, and there is nothing to fetch: the package
has no dependencies. Once it is published, `npx webstore-lint ./my-extension`
will be the one-liner.

## Why the codenames matter

Google publishes a complete list of extension rejection reasons on one page, and
calls them **notification IDs**. Rejection emails apparently call them
**violation reference IDs**. Everyone else calls them codenames. That three-way
terminology split is most of the reason they are so hard to look up when you are
staring at one.

There are 36 of them across 27 violation categories. This package carries all
27, each verified against Google's own HTML rather than a summary of it.

```bash
node bin/webstore-lint.mjs --policy     # list every category and codename
```

<!-- CODENAMES:START -->

All 36 codenames across 27 categories, generated from
[the open dataset](https://circadian-agent.com/data/chrome-rejection-ids.json)
(CC BY 4.0). Every quote behind these was fetched from developer.chrome.com and
re-checked against the raw HTML.

| Codename | Category | What it actually means |
|---|---|---|
| [Blue Argon](https://circadian-agent.com/research/chrome-rejections/blue-argon) | Additional requirements for Manifest V3 | Your Manifest V3 extension is loading or executing code that is not inside the package you submitted. |
| [Blue Copper](https://circadian-agent.com/research/chrome-rejections/prohibited-products) | Prohibited products | The extension gets round paywalls or logins, or enables downloading content the user has no right to. |
| [Blue Lithium](https://circadian-agent.com/research/chrome-rejections/prohibited-products) | Prohibited products | The extension gets round paywalls or logins, or enables downloading content the user has no right to. |
| [Blue Magnesium](https://circadian-agent.com/research/chrome-rejections/prohibited-products) | Prohibited products | The extension gets round paywalls or logins, or enables downloading content the user has no right to. |
| [Blue Nickel](https://circadian-agent.com/research/chrome-rejections/circumvents-the-overrides-api) | Circumvents the overrides API | You changed the New Tab Page or omnibox search by some route other than the official Overrides API. |
| [Blue Potassium](https://circadian-agent.com/research/chrome-rejections/circumvents-the-overrides-api) | Circumvents the overrides API | You changed the New Tab Page or omnibox search by some route other than the official Overrides API. |
| [Blue Titanium](https://circadian-agent.com/research/chrome-rejections/blue-titanium) | Enforcement circumvention | You tried to dodge a review or an enforcement action. This is the one that ends accounts. |
| [Blue Zinc](https://circadian-agent.com/research/chrome-rejections/prohibited-products) | Prohibited products | The extension gets round paywalls or logins, or enables downloading content the user has no right to. |
| [Grey Copper](https://circadian-agent.com/research/chrome-rejections/grey-copper) | Online gambling | The extension provides, facilitates, or directs users to real money gambling or prediction markets. |
| [Grey Lithium](https://circadian-agent.com/research/chrome-rejections/grey-lithium) | Pornographic content | The extension contains, serves, or exists mainly to enhance sexually explicit material. |
| [Grey Magnesium](https://circadian-agent.com/research/chrome-rejections/grey-magnesium) | Hate content | The extension carries or points to hate speech, or lacks moderation for user-generated content that does. |
| [Grey Nickel](https://circadian-agent.com/research/chrome-rejections/grey-nickel) | Not family safe | Your extension has adult-ish content but you never ticked the Mature box. |
| [Grey Potassium](https://circadian-agent.com/research/chrome-rejections/grey-potassium) | Violent content | The extension carries or points to gratuitously violent, threatening, harassing or bullying content. |
| [Grey Silicon](https://circadian-agent.com/research/chrome-rejections/grey-silicon) | Cryptocurrency mining | The extension mines cryptocurrency, or gives users the ability to. |
| [Grey Titanium](https://circadian-agent.com/research/chrome-rejections/grey-titanium) | Affiliate Ads | You inject affiliate links, codes or cookies without disclosing it and without the user doing something that would lead them to expect it. |
| [Grey Zinc](https://circadian-agent.com/research/chrome-rejections/grey-zinc) | Illegal activities | The extension engages in or promotes unlawful activity. |
| [Purple Copper](https://circadian-agent.com/research/chrome-rejections/purple-copper) | User data policy - secure transmission | You send user data over an insecure channel, or leak it in URLs and headers. |
| [Purple Lithium](https://circadian-agent.com/research/chrome-rejections/purple-lithium) | User data policy - disclosure policy | You collect user data but your privacy policy is missing, unreachable, in the wrong field, or does not actually describe data handling. |
| [Purple Magnesium](https://circadian-agent.com/research/chrome-rejections/purple-magnesium) | User data policy - other requirements | You collect browsing activity you do not need for a visible feature, or you expose sensitive data publicly. |
| [Purple Nickel](https://circadian-agent.com/research/chrome-rejections/purple-nickel) | User data policy - prominent disclosure | You collect user data without prominently telling the user first and getting their consent. |
| [Purple Potassium](https://circadian-agent.com/research/chrome-rejections/purple-potassium) | Excessive permissions | You asked for a permission you do not use, or a broader one than the job needs. |
| [Red Argon](https://circadian-agent.com/research/chrome-rejections/single-purpose) | Single purpose | Your extension does two or more unrelated things and needs to be split into separate extensions. |
| [Red Copper](https://circadian-agent.com/research/chrome-rejections/single-purpose) | Single purpose | Your extension does two or more unrelated things and needs to be split into separate extensions. |
| [Red Lithium](https://circadian-agent.com/research/chrome-rejections/single-purpose) | Single purpose | Your extension does two or more unrelated things and needs to be split into separate extensions. |
| [Red Magnesium](https://circadian-agent.com/research/chrome-rejections/single-purpose) | Single purpose | Your extension does two or more unrelated things and needs to be split into separate extensions. |
| [Red Nickel](https://circadian-agent.com/research/chrome-rejections/deceptive-behavior) | Deceptive behavior | What the extension does and what its listing says do not match, or it passes itself off as someone else's product. |
| [Red Potassium](https://circadian-agent.com/research/chrome-rejections/deceptive-behavior) | Deceptive behavior | What the extension does and what its listing says do not match, or it passes itself off as someone else's product. |
| [Red Silicon](https://circadian-agent.com/research/chrome-rejections/deceptive-behavior) | Deceptive behavior | What the extension does and what its listing says do not match, or it passes itself off as someone else's product. |
| [Red Titanium](https://circadian-agent.com/research/chrome-rejections/red-titanium) | Obfuscation | Your submitted code is obfuscated. Minification is fine, obfuscation is not. |
| [Red Zinc](https://circadian-agent.com/research/chrome-rejections/red-zinc) | Deceptive installation | How you got users to install the extension was misleading, regardless of what the extension itself does. |
| [Yellow Argon](https://circadian-agent.com/research/chrome-rejections/yellow-argon) | Keyword stuffing | Your description is padded with keywords, site lists or locations to game search ranking. |
| [Yellow Lithium](https://circadian-agent.com/research/chrome-rejections/yellow-lithium) | Redirection | The extension is a shortcut. All it does is open a website or another product. |
| [Yellow Magnesium](https://circadian-agent.com/research/chrome-rejections/yellow-magnesium) | Functionality not working | The reviewer could not get your extension to do what your listing says it does, or your package is broken. |
| [Yellow Nickel](https://circadian-agent.com/research/chrome-rejections/yellow-nickel) | Spam | Duplicate extensions, manipulated ratings or installs, notification abuse, or messages sent as the user. |
| [Yellow Potassium](https://circadian-agent.com/research/chrome-rejections/yellow-potassium) | Minimum Functionality | The extension is too thin to be worth listing, or it just links out to a service that does the actual work. |
| [Yellow Zinc](https://circadian-agent.com/research/chrome-rejections/yellow-zinc) | Missing or insufficient metadata | Your listing is missing an icon, title, screenshots or description, or what is there does not explain the extension. |

<!-- CODENAMES:END -->

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

## The permission ledger

```bash
node bin/webstore-lint.mjs ./my-extension --permissions
```

The Chrome Web Store dashboard makes you write a justification for every
permission you request, and `Purple Potassium` is what comes back when those are
thin. A justification is only as good as the evidence under it, so this mode
answers the question the linter cannot: **what in your code actually requires
this permission, and would a narrower one have done?**

That second half is the comparative question Google's policy actually asks:

> If more than one permission could be used to implement a feature, you must
> request those with the least access to data or functionality.

So it prints, per permission, the exact call sites that require it, and where a
narrower option exists it names it with the evidence:

- `tabs` reaching only for the tab the user just acted on, where `activeTab`
  grants that on a gesture with no install warning and no host permission
- `storage` declared while the code only ever calls `localStorage`, which needs
  no permission at all
- `webRequest` where `declarativeNetRequest` covers it without the extension
  seeing the traffic
- `<all_urls>` against the hosts your code actually names, which is usually a
  short list and removes the "Read and change all your data on all websites"
  warning

It also derives your Privacy practices answers from what the code touches rather
than from memory.

**Every suggestion carries the condition that would make it wrong.** These are
recommendations to delete a permission, so a false one breaks a working
extension. If you observe tabs the user has not touched, `activeTab` cannot do
it, and the tool says so instead of suggesting it. Three honesty rules hold
throughout: a permission with no pattern in the tool is reported `unknown` and
never `unused`; minified bundles defeat call-site evidence and are declared as
such rather than reported as a confident zero; and unread or skipped files are
named, because an absence is only as broad as where you looked.

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
