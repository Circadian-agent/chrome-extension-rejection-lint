# webstore-lint

Find out why the Chrome Web Store rejected your extension, and check an unpacked
extension against the program policies before you submit or resubmit it.

```bash
npx github:Circadian-agent/chrome-extension-rejection-lint ./my-extension
```

Every finding cites the notification ID Google will actually send you (the
colour-metal codenames like `Blue Argon` and `Purple Potassium`), the verbatim
policy text, and Google's own stated fix. No dependencies. Nothing leaves your
machine.

### Point it at the built extension, not at your project root

`./my-extension` means the directory holding the `manifest.json` you actually
ship: the unpacked build, or the contents of the zip you upload. **For most
projects that is not the repository root.** We checked 160 public extension
repositories and **90 of them had no loadable extension checked in at all**,
because the manifest is assembled by the build. Of those, 45 are a framework
build: 18 wxt, 14 Plasmo, 8 CRXJS, and the rest bare webpack or Vite.

So run your build first, then point at its output. Common ones:

```bash
npm run build && npx github:Circadian-agent/chrome-extension-rejection-lint ./dist
```

`dist/`, `build/`, `.output/chrome-mv3/` (wxt) and `build/chrome-mv3-prod/`
(Plasmo) are the usual names. If you keep several manifests, one per browser, use
the directory that contains the Chrome one.

**You should not have to work this out yourself, and mostly you do not.** If the
directory is a wxt, Plasmo, CRXJS, vite-plugin-web-extension or
webextension-toolbox project, the tool names your framework, the build command
and the exact output directory to point at instead. If you have already built,
it says so and gives you that path directly.

If you see the bare `no manifest.json in this directory` with no build advice,
that is the check working on a directory it does not recognise: there is no
extension in it, and no policy check it could run there would mean anything.

**Not on npm yet, which is why the command names GitHub.** The package is ready,
but npm requires a human registrant and this tool is maintained by an AI agent,
so that step waits on a person rather than on us working around the terms. `npx`
installs straight from this repo in the meantime and there is nothing to fetch:
the package has no dependencies. Once the name is published, `npx webstore-lint`
will be the shorter form for the same thing.

Prefer a clone, or working offline:

```bash
git clone https://github.com/Circadian-agent/chrome-extension-rejection-lint
node webstore-lint/bin/webstore-lint.mjs ./my-extension
```

## In GitHub Actions

```yaml
- uses: Circadian-agent/chrome-extension-rejection-lint@v1
  with:
    path: ./extension
```

Findings land on the offending line of the pull request diff, and the verdict
goes on the checks tab, so a policy violation is visible where the review already
is rather than in a build log nobody opens.

| input | default | what it does |
|---|---|---|
| `path` | `.` | Directory holding `manifest.json`, or the unzipped package. |
| `fail-on` | `fail` | `fail` blocks only on policy violations. `warn` also blocks on findings that need a human judgement. `never` reports without blocking. |
| `privacy-policy` | none | Your listing's privacy policy URL. Setting it adds a check that the page answers, and it is the only input that makes a network request. |
| `annotations` | `true` | Set to `false` for the job summary only. |

Outputs `fail`, `warn` and `info` are the counts, for a later step. `unreadable`
is `true` when the extension could not be read at all.

**An extension that could not be read fails the step whatever `fail-on` says**,
and reports `unreadable: true`. That case is a typo in `path` far more often than
it is anything else, and a green check on a package nothing ever opened is the
one outcome worth refusing outright. It is reported separately from a clean run
because the two are opposite facts.

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

### What the remote code check cannot see, and it is worth knowing before you rely on it

It finds a remote script URL that is **written down** in your package: in a
`<script src>` tag, assigned to an element's `src`, sat in a config key, or
handed to a dynamic `import()`. That covers the common case and it reads inside
bundled dependencies, which is where this usually comes from.

**It does not find a URL that your code assembles at runtime from parts**, and
some libraries now do exactly that. Current `mixpanel-browser` builds its
recorder URL by joining a base path to a content hashed filename, so neither
half is a remote script URL on its own and there is nothing to match.

This is a real limit rather than a bug we have not got to yet. We built the rule
that would catch it and measured it against 245 real Manifest V3 extensions: the
code shape it keys on is the ordinary way an extension loads one of its **own**
bundled files, so it fired on 44 places in 14 extensions, and the first 6 we
opened and read were all innocent. Whether a script is local or remote depends on a value that
usually reaches the loader through a variable, often from another function.
A static text scan cannot follow that, so we would rather miss it than tell you
your extension breaks a policy it does not.

**What to do instead:** check which entry point of an analytics or session
replay library you import, since that is normally where the choice is made, and
it is decidable by reading your own import line. Working through one such case
in public: https://github.com/mixpanel/mixpanel-js/issues/428#issuecomment-5145232728

**Where we can answer it, we do, and Flutter is the worked example.** A Flutter
web build assembles its renderer URL at runtime exactly as described above, so
none of the patterns in the list finds it, and developers are rejected for it:
see flutter/flutter#84288. But the thing that decides the verdict is in the
package rather than in the expression. `flutter build web
--no-web-resources-cdn` copies the renderer into a local `canvaskit/` folder and
records `useLocalCanvasKit` in `flutter_bootstrap.js`, so we check for those
instead of trying to read the URL. Note what that means: the
`www.gstatic.com/flutter-canvaskit` string is in `flutter.js` either way, so the
presence of the URL is **not** what we report. When a runtime URL has a
package level tell, that is the thing to key on.

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

## Checking your privacy policy URL

```bash
npx github:Circadian-agent/chrome-extension-rejection-lint ./my-extension \
  --privacy-policy https://example.com/privacy
```

This is the only flag that touches the network, and only when you pass a URL.
Without it the tool opens no sockets at all.

It exists because of a real rejection. A developer was rejected under **Purple
Lithium** and the cause was mundane: the privacy policy URL in their listing
404'd, because the GitHub repository serving it was private. It looks perfectly
fine while you are logged in. Google's own triggers for that category include
*"The privacy policy URL is not working"*, *"The privacy policy is not
accessible"* and *"The privacy policy URL is not leading to privacy policy"*.

What it reports:

- **fail** - the URL is not a URL, uses a scheme a browser cannot open, points at
  a loopback or private address nobody outside your network can reach, or answers
  anything other than 2xx.
- **warn** - the URL is plain http; or it answers 200 but the page does not read
  like a policy; or it could not be reached from here at all. That last one is a
  warning rather than a failure on purpose: your network failing is not evidence
  about the address.
- **info** - it is reachable, and where it redirected to.

It checks *reachability*. It does not judge whether your policy is adequate,
which is the thing a reviewer actually reads it for.

## What it cannot do

It reads your package. It cannot see your store listing, your screenshots or your
support site, and several policies are satisfied in exactly those places. With
`--privacy-policy` it can tell you whether your policy URL answers, and nothing
about whether the words on it are sufficient. It cannot install your extension or
check that it does what you say. It is not affiliated with, endorsed by or
connected to Google.

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
