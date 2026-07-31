// The rules.
//
// EVERY RULE CITES A CATEGORY IN data/policy.json, and that file is generated
// from a dataset whose quotes were re-checked against Google's raw HTML. A rule
// may describe what it found; it may not paraphrase what Google requires.
//
// THREE SEVERITIES, and the boundary between them is the honest part:
//
//   fail  - a static signal Google names as a trigger. Not a prediction of
//           rejection; reviewers are human and this tool cannot install your
//           extension. It means the package contains the thing the policy names.
//   warn  - the package shows a condition that REQUIRES something this tool
//           cannot see (a store listing, a privacy policy page, a screenshot).
//           Unresolvable locally by construction, so it is never a fail.
//   info  - announced but not yet in any live policy page, or advisory.
//
// A linter that reports everything as an error gets muted, and a muted linter
// is worth less than none. When in doubt a rule warns and says what a human
// must check.

import { grep, grepAcross, isCode, isMarkup, codeView } from "./scan.mjs";
import { MANIFEST_EVIDENCE, namespaceUsed, looksMinified, bareImports } from "./audit.mjs";

// Permissions whose presence means USER data is in play. Used by the disclosure
// and privacy-policy rules. Kept explicit rather than inferred: a list you can
// read and argue with beats a heuristic nobody can audit.
//
// "storage" IS DELIBERATELY ABSENT and the omission is the important part.
// chrome.storage holds the extension's own state, not the user's data, and
// almost every extension declares it - so including it made the disclosure rule
// fire on a fixture that is compliant by construction. A warning that appears on
// every extension carries no information and teaches people to skip the output.
// The clean-fixture test is what caught it. Same reasoning excludes alarms,
// notifications, contextMenus and scripting.
export const DATA_PERMISSIONS = [
  "cookies", "history", "topSites", "browsingData", "bookmarks", "downloads",
  "geolocation", "clipboardRead", "tabs", "webRequest", "webNavigation",
  "identity", "identity.email", "management", "privacy",
  "declarativeNetRequestFeedback", "pageCapture", "desktopCapture", "audioCapture",
  "videoCapture", "contentSettings", "debugger", "proxy",
];

// chrome.* namespaces a permission unlocks, for the unused-permission check.
// A permission whose namespace never appears is the exact trigger Google names
// for Purple Potassium.
const PERMISSION_API = {
  cookies: ["chrome.cookies", "browser.cookies"],
  history: ["chrome.history", "browser.history"],
  topSites: ["chrome.topSites", "browser.topSites"],
  bookmarks: ["chrome.bookmarks", "browser.bookmarks"],
  downloads: ["chrome.downloads", "browser.downloads"],
  browsingData: ["chrome.browsingData", "browser.browsingData"],
  management: ["chrome.management", "browser.management"],
  tabs: ["chrome.tabs", "browser.tabs"],
  webRequest: ["chrome.webRequest", "browser.webRequest"],
  webNavigation: ["chrome.webNavigation", "browser.webNavigation"],
  identity: ["chrome.identity", "browser.identity"],
  storage: ["chrome.storage", "browser.storage"],
  notifications: ["chrome.notifications", "browser.notifications"],
  contextMenus: ["chrome.contextMenus", "browser.contextMenus"],
  alarms: ["chrome.alarms", "browser.alarms"],
  scripting: ["chrome.scripting", "browser.scripting"],
  debugger: ["chrome.debugger", "browser.debugger"],
  proxy: ["chrome.proxy", "browser.proxy"],
  privacy: ["chrome.privacy", "browser.privacy"],
  contentSettings: ["chrome.contentSettings", "browser.contentSettings"],
  pageCapture: ["chrome.pageCapture", "browser.pageCapture"],
  desktopCapture: ["chrome.desktopCapture", "browser.desktopCapture"],
  idle: ["chrome.idle", "browser.idle"],
  power: ["chrome.power", "browser.power"],
  tts: ["chrome.tts", "browser.tts"],
};

const BROAD_HOSTS = ["<all_urls>", "*://*/*", "http://*/*", "https://*/*"];

// Words that carry no ranking value, excluded from the keyword-stuffing count.
//
// WITHOUT THIS THE RULE FIRED ON ORDINARY ENGLISH. The word pattern demands three
// letters or more, which "the", "and", "for" and "you" all clear, so a plain
// two-sentence description saying "the" five times was reported as repeating
// terms. Google's trigger is padding a listing with search terms; "the" is not a
// search term anybody stuffs. This file's own header says a warning that appears
// on every extension carries no information, and that is what this had become.
// The bad fixture stuffs "coupons" and "deals", which are exactly the words this
// list does not contain, so the rule still catches what it is for.
const STOPWORDS = new Set([
  "the", "and", "for", "you", "your", "with", "that", "this", "from", "are",
  "can", "not", "but", "all", "any", "was", "were", "has", "have", "had",
  "will", "when", "what", "which", "who", "how", "why", "its", "our", "their",
  "them", "they", "than", "then", "into", "onto", "over", "out", "off", "one",
  "get", "gets", "use", "uses", "using", "just", "also", "more", "most", "only",
]);

// Every place a manifest can ask for access to a page, in one function because
// two rules used to collect them separately and DRIFTED. broad-host-permissions
// read all three keys; disclosure-2026 read only host_permissions, so two
// extensions with identical access to every site got different answers about the
// 1 August disclosure rule depending on which key they declared it in - and the
// content_scripts shape, which is the common one, was the one told nothing.
//
// The three keys are not interchangeable spellings. content_scripts[].matches is
// where an MV3 extension that only reads pages declares itself and it needs no
// host_permissions at all; hosts listed in `permissions` is the MV2 spelling,
// and MV2 extensions are the ones already in trouble.
//
// Callers filter to BROAD_HOSTS. Narrow matches are deliberately NOT treated as
// user data in scope: the clean fixture is a reading-time extension with a
// content script on one site, and a warning that fires on that fires on almost
// everything. Same reasoning as the "storage" omission from DATA_PERMISSIONS.
export function declaredHosts(manifest) {
  if (!manifest) return [];
  return [
    ...(manifest.host_permissions || []),
    ...(manifest.permissions || []).filter((p) => typeof p === "string" && (p.includes("://") || p === "<all_urls>")),
    ...(manifest.content_scripts || []).flatMap((c) => c.matches || []),
  ];
}

const finding = (o) => ({ evidence: [], ...o });

// ---------------------------------------------------------------------------

export const RULES = [

  // FIRST, BECAUSE IT CHANGES HOW YOU READ EVERY OTHER FINDING. If this fires,
  // the directory is not the thing Chrome would review, and every rule that
  // reasons from the ABSENCE of something is unreliable against it.
  //
  // This is a warn by the letter of the contract above: the condition requires
  // something this tool cannot see, namely the build output. Measured on real
  // repositories rather than imagined - 14 of 25 public MV3 projects hold no
  // loadable extension at the path a reader would try first, and the one that
  // reached this rule (refined-github) was failed for two permissions whose
  // call sites are inside dependencies that are not in the repository.
  {
    id: "unbuilt-source",
    // NO CATEGORY, DELIBERATELY. Every other rule names a policy category, which
    // attaches Google's own words and a link to the matching rejection page.
    // This finding is about whether this tool is looking at the right directory,
    // not about anything Google requires, and citing a policy at it would be the
    // paraphrase this file's header forbids.
    run({ manifest, files }) {
      if (!manifest) return [];
      const bare = bareImports(codeView(files).filter(isCode));
      if (!bare.length) return [];
      const specs = [...new Set(bare.map((b) => b.spec))].slice(0, 5);
      return [finding({
        severity: "warn",
        title: `This looks like source, not a packaged extension: ${bare.length >= 25 ? "25+" : bare.length} bare module import(s)`,
        detail:
          `Files here import module names Chrome cannot resolve (${specs.join(", ")}). A loaded extension can only ` +
          "import a relative path, so this directory is what a bundler reads rather than what it produces, and it " +
          "would not run if you submitted it. Point this tool at your BUILD OUTPUT instead - commonly dist/ or " +
          "build/, .output/chrome-mv3 under wxt, build/chrome-mv3-prod under Plasmo. Until you do, treat every " +
          "finding below with care and the absence of a finding with more: the code that would have triggered it " +
          "may be in a dependency that is not in this directory.",
        evidence: bare.slice(0, 5).map((b) => ({ file: b.file, line: b.line, match: b.spec, text: b.text })),
      })];
    },
  },

  {
    id: "manifest-v2",
    category: "additional-requirements-for-manifest-v3",
    run({ manifest }) {
      if (!manifest || manifest.manifest_version === 3) return [];
      return [finding({
        severity: "fail",
        title: `manifest_version is ${manifest.manifest_version ?? "missing"}, and the Chrome Web Store accepts Manifest V3 only`,
        detail:
          "Manifest V2 submissions are no longer accepted. This is not a policy judgement call, it is a " +
          "hard gate before any reviewer sees the extension.",
        evidence: [{ file: "manifest.json", line: 1, text: `"manifest_version": ${manifest.manifest_version ?? "absent"}` }],
      })];
    },
  },

  {
    id: "remote-code",
    category: "additional-requirements-for-manifest-v3",
    run({ files }) {
      const out = [];
      // [^>] already crosses newlines - a JS character class ignores line
      // structure - so the pattern was never the problem and must NOT be widened
      // to [\s\S]: that would run past the closing > of this tag and match a
      // remote src on some later <img>. The bug was that grep() fed it one line
      // at a time, so it was never shown a newline to cross.
      const remoteScript = grepAcross(files, /<script[^>]+src\s*=\s*["'](https?:)?\/\/[^"']+/i, isMarkup);
      if (remoteScript.length) {
        out.push(finding({
          severity: "fail",
          title: "A <script> tag loads code from outside the extension package",
          detail: "Google names this as the first trigger for this category. The referenced file must be vendored into the package.",
          evidence: remoteScript,
        }));
      }
      // eval and the Function constructor. `new Function()` is the one people
      // forget: it is eval wearing a different name and the policy names both.
      //
      // `$` BELONGS IN THE EXCLUSION because it is a valid JavaScript identifier
      // character, so `$eval` is ONE identifier and not a call to eval - exactly
      // as `myeval` is. Without it this fired `fail` on every AngularJS package
      // using `scope.$eval(...)`, which is an Angular expression evaluator and
      // not the JS engine's eval at all. Found by running this rule against real
      // third-party extensions (listen1/listen1_chrome_extension) rather than
      // against our own fixtures, which had no `$`-prefixed identifiers in them.
      //
      // This NARROWS the rule, so the risk it carries is a miss rather than a
      // wrong fail. That is the safe direction here only because `$eval` is not
      // a JS API: there is no real string-execution path this now walks past.
      const evals = grep(files, /(^|[^.\w$])eval\s*\(|new\s+Function\s*\(/, isCode);
      if (evals.length) {
        out.push(finding({
          severity: "fail",
          title: "eval() or new Function() executes a string as code",
          detail:
            "Google's trigger is executing a string fetched from a remote source. This tool cannot prove where " +
            "your string comes from, so review each site: if the string is a literal in your own package it is " +
            "defensible, and if any part of it arrives over the network it is the violation.",
          evidence: evals,
        }));
      }
      const dynImport = grepAcross(files, /import\s*\(\s*["'`](https?:)?\/\//, isCode);
      if (dynImport.length) {
        out.push(finding({
          severity: "fail",
          title: "A dynamic import() pulls a module from a remote URL",
          evidence: dynImport,
        }));
      }
      return out;
    },
  },

  {
    id: "unused-permissions",
    category: "excessive-permissions",
    run({ manifest, files, skipped = [] }) {
      if (!manifest) return [];
      const declared = [...(manifest.permissions || []), ...(manifest.optional_permissions || [])];
      // Comments blanked first. A permission whose only trace is "// we used to
      // call chrome.bookmarks.getTree here" is the COMMONEST real form of an
      // unused permission - the feature was deleted and the note left behind -
      // and reading raw text made this rule blind to exactly that case while
      // audit.mjs reported it. Shared with audit.mjs so the two cannot disagree.
      const view = codeView(files).filter(isCode);
      const code = view.map((f) => f.text).join("\n");
      const unused = declared.filter((p) => {
        const apis = PERMISSION_API[p];
        if (!apis) return false; // unknown permission: say nothing rather than guess
        // Not a literal `chrome.storage` test: a minifier aliases the namespace
        // and the literal test then reads as "never used". See namespaceUsed.
        if (namespaceUsed(code, apis)) return false;
        // Some permissions are earned by the manifest with no JavaScript at all
        // (a declarativeNetRequest static ruleset, a side_panel path). This rule
        // is a FAIL, so a false one here deletes a working feature.
        return !MANIFEST_EVIDENCE[p]?.(manifest);
      });
      if (!unused.length) return [];
      // "NEVER USED" IS A CLAIM ABOUT ALL THE CODE, so it may only be made when
      // all the code was read and read in a form where a name survives. Two
      // things break that, and both were found on one real package - the shipped
      // `dist/chrome` of immersive-translate (s098):
      //
      //   1. FILES WE DID NOT OPEN. scan.mjs skips anything over 2 MB and lists
      //      what it skipped, honestly. But this rule went on asserting "never"
      //      anyway, and on that package the skipped set was popup.js,
      //      content_main.js, side-panel.js and options.js - 2.6 to 3.2 MB each,
      //      which is to say the entire application. We read the leftovers and
      //      failed it for permissions the unread files use on every run.
      //   2. MINIFICATION, even where everything WAS read: a minifier rewrites
      //      `chrome` to a one-letter local, so absence of a name is not absence
      //      of a call. namespaceUsed catches the common aliases; it cannot
      //      catch a computed `chrome[a]`.
      //
      // Either way the honest report is the same finding at the severity the
      // evidence carries - something for the developer to check against their
      // source, not a defect we claim to have found. Silence would be wrong too:
      // a permission left behind by a deleted feature is still the commonest
      // true positive, and it looks exactly like this.
      const unread = skipped.filter((s) => /\.(js|mjs|cjs|ts|jsx|tsx|html?)$/i.test(s.path || ""));
      const minified = looksMinified(view);
      const bare = bareImports(view);
      if (unread.length || minified.length || bare.length) {
        const why = unread.length
          ? `${unread.length} code file(s) in this package were not read (${unread[0].path}: ${unread[0].why}), so this scan did not see all of your code`
          : bare.length
            ? `this directory is pre-build source rather than a packaged extension (${bare[0].file}:${bare[0].line} imports "${bare[0].spec}"), so the code that uses these may be inside a dependency that is not here`
            : `this package is bundled or minified (${minified[0].file} runs to ${minified[0].longestLine} characters on one line), and a minifier rewrites chrome.* into short local names`;
        return [finding({
          severity: "warn",
          title: `Cannot confirm these permissions are used: ${unused.join(", ")}`,
          detail:
            "Google's stated trigger is asking for a permission you do not use. This is a warning and not a " +
            `failure because ${why}. That makes "unused" and "unseen" indistinguishable here, and deleting a ` +
            "permission your extension turns out to need breaks the feature it exists for. Check each of these " +
            "against your SOURCE. If a feature really did go away and the permission stayed, remove it, or move " +
            "it to optional_permissions and request it at the moment the feature runs.",
          evidence: unused.map((p) => ({ file: "manifest.json", line: 1, text: `"${p}"` })),
        })];
      }
      return [finding({
        severity: "fail",
        title: `Declared but never used: ${unused.join(", ")}`,
        detail:
          "Google's stated trigger is asking for a permission you do not use. Each of these is declared in the " +
          "manifest and its chrome.* namespace appears nowhere in the packaged JavaScript. Remove it, or move it " +
          "to optional_permissions and request it at the moment the feature runs.",
        evidence: unused.map((p) => ({ file: "manifest.json", line: 1, text: `"${p}"` })),
      })];
    },
  },

  {
    id: "broad-host-permissions",
    category: "excessive-permissions",
    run({ manifest }) {
      if (!manifest) return [];
      const broad = [...new Set(declaredHosts(manifest).filter((h) => BROAD_HOSTS.includes(h)))];
      if (!broad.length) return [];
      return [finding({
        severity: "warn",
        title: `Access to every site: ${broad.join(", ")}`,
        detail:
          "This is the broader-than-the-job-needs half of the same policy. It is a warning rather than a failure " +
          "because some extensions genuinely need every site. If yours does not, narrow the match patterns. If it " +
          "does, expect to justify it in the listing, and note that this also pulls you into the user data policies.",
        evidence: broad.map((h) => ({ file: "manifest.json", line: 1, text: h })),
      })];
    },
  },

  {
    id: "listing-metadata",
    category: "no-metadata",
    run({ manifest, i18nUnresolved = [] }) {
      if (!manifest) return [];
      const out = [];
      // A __MSG_ placeholder that resolves to nothing is not a short description,
      // it is a package that does not load - Chrome rejects it before a reviewer
      // reads a word of it, the same shape as manifest-v2 above. Reported first
      // and separately, because "the description is 22 characters" is a wrong
      // diagnosis of it and sends the developer to edit the wrong file.
      if (i18nUnresolved.length) {
        out.push(finding({
          severity: "fail",
          title: `A localised manifest field does not resolve: ${i18nUnresolved[0].why}`,
          detail:
            "Localised fields are written as __MSG_name__ in manifest.json and the text lives in " +
            "_locales/<default_locale>/messages.json. Chrome substitutes them at load time, so a placeholder " +
            "with no matching message leaves the field empty and the package is rejected before review. " +
            "Until this is fixed, every check in this tool that reads your name or description is reading the " +
            "placeholder rather than your words.",
          evidence: i18nUnresolved.map((u) => ({ file: "manifest.json", line: 1, text: u.why })),
        }));
      }
      const desc = (manifest.description || "").trim();
      if (/__MSG_[A-Za-z0-9_@]+__/.test(desc)) return out; // unresolved: nothing honest to measure
      if (!desc) {
        out.push(finding({
          severity: "fail",
          title: "manifest.json has no description",
          evidence: [{ file: "manifest.json", line: 1, text: "description absent" }],
        }));
      } else if (desc.length < 25) {
        out.push(finding({
          severity: "warn",
          title: `The description is ${desc.length} characters, which is unlikely to describe a single purpose`,
          detail: "The reviewer checks the listing against what the extension does. A description too short to state a purpose cannot be checked against anything.",
          evidence: [{ file: "manifest.json", line: 1, text: desc }],
        }));
      }
      const icons = manifest.icons || {};
      if (!Object.keys(icons).length) {
        out.push(finding({
          severity: "warn",
          title: "manifest.json declares no icons",
          detail: "A missing icon is one of the listed triggers. Store listing images are set in the developer dashboard and cannot be checked from the package.",
          evidence: [{ file: "manifest.json", line: 1, text: "icons absent" }],
        }));
      }
      return out;
    },
  },

  {
    id: "insecure-transmission",
    category: "udp-secure",
    run({ files }) {
      // localhost over http is normal in development and is not a finding.
      // Comments are blanked first for the same reason unused-permissions blanks
      // them: "// old endpoint was http://api.example.com" is a URL the package
      // never contacts, and reporting it sends someone hunting for a call that
      // is not there. Markup is passed through untouched by codeView, so an
      // http:// src inside an HTML comment is still reported - that one is worth
      // keeping, because a commented-out <script src> is a byte away from live.
      // XML NAMESPACE URIs ARE IDENTIFIERS, NOT ENDPOINTS. `<svg xmlns=
      // "http://www.w3.org/2000/svg">` and `createElementNS("http://www.w3.org/
      // 2000/svg", ...)` never touch the network - the string is a name, and the
      // http:// spelling is fixed by the specification, so it cannot be "fixed"
      // to https even in principle. Reporting it told people to change a string
      // that would break their SVG if they changed it.
      //
      // This was the single most common warning the tool produced against real
      // extensions: 6 of 7 insecure-transmission hits across the corpus, in
      // darkreader, automa, screenity, voyager and return-youtube-dislike. Every
      // one was this namespace. Our own fixtures contained no inline SVG, which
      // is why every test passed while the rule was wrong on real code.
      //
      // The list is exact prefixes of specification-defined namespaces, not a
      // blanket w3.org exclusion: a plain-http link to a w3.org *document* is
      // still a plain-http link and stays reported.
      const XML_NAMESPACES = [
        "http://www.w3.org/2000/svg",
        "http://www.w3.org/1999/xhtml",
        "http://www.w3.org/1999/xlink",
        "http://www.w3.org/2000/xmlns/",
        "http://www.w3.org/XML/1998/namespace",
        "http://www.w3.org/1998/Math/MathML",
        "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
        "http://www.w3.org/2001/XMLSchema",
      ];
      const hits = grep(
        codeView(files),
        /["'`]http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])[^"'`\s]+/i,
        (f) => isCode(f) || isMarkup(f),
      ).filter((h) => {
        const url = String(h.match || "").replace(/^["'`]/, "");
        if (XML_NAMESPACES.some((ns) => url.startsWith(ns))) return false;
        // DOCTYPE system identifiers are the same case as namespaces and were
        // missed by the first pass: `<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//
        // EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">` names a
        // grammar, is fixed by the specification, and is not a channel anything
        // travels over. Found still firing on listen1 by running the PUBLISHED
        // tool after shipping the namespace fix, which is the only reason it was
        // caught - the local corpus had already gone quiet.
        //
        // Deliberately narrow: a `.dtd` under w3.org, not all of w3.org/TR,
        // which is where specification *documents* live. A plain-http link to a
        // document is still a plain-http link and stays reported.
        if (/^https?:\/\/(www\.)?w3\.org\/[^"'`\s]*\.dtd$/i.test(url)) return false;
        return true;
      });
      if (!hits.length) return [];
      return [finding({
        severity: "warn",
        title: "Plain http:// endpoints appear in the package",
        detail:
          "The policy is about sending user data over an insecure channel. This tool cannot tell whether user " +
          "data flows to these URLs, so check each one. Anything carrying user data must be https.",
        evidence: hits,
      })];
    },
  },

  {
    id: "crypto-mining",
    category: "cryptocurrency-mining",
    run({ files }) {
      // Comments blanked: this is a FAIL, and accusing someone of shipping a
      // miner on the strength of "// we removed the coinhive experiment" is the
      // expensive direction. Code in a comment does not mine anything.
      const hits = grep(codeView(files), /coinhive|cryptonight|cryptoloot|webminerpool|minergate|\bcoinimp\b/i, (f) => isCode(f) || isMarkup(f));
      if (!hits.length) return [];
      return [finding({
        severity: "fail",
        title: "Cryptocurrency mining code or a known mining service appears in the package",
        evidence: hits,
      })];
    },
  },

  {
    id: "obfuscation",
    category: "obfuscation",
    run({ files }) {
      const out = [];
      // The javascript-obfuscator signature. Minification is explicitly allowed
      // by Google, so line length alone is NOT reported: a webpack bundle is one
      // long line and is perfectly legal.
      for (const f of files.filter(isCode)) {
        const hexNames = (f.text.match(/_0x[0-9a-f]{4,}/gi) || []).length;
        if (hexNames >= 10) {
          out.push(finding({
            severity: "fail",
            title: `${f.path} carries ${hexNames} _0x-style identifiers, the signature of an obfuscator`,
            detail:
              "Google draws the line explicitly: minification is fine, obfuscation is not. Ship the minified " +
              "bundle, not the obfuscated one, and keep the build reproducible from the source you can show.",
            evidence: [{ file: f.path, line: 1, text: `${hexNames} occurrences of _0x[hex]` }],
          }));
        }
      }
      return out;
    },
  },

  {
    id: "keyword-stuffing",
    category: "keyword-stuffing",
    run({ manifest }) {
      if (!manifest?.description) return [];
      const desc = manifest.description;
      const words = desc.toLowerCase().match(/[a-z][a-z0-9-]{2,}/g) || [];
      const counts = {};
      for (const w of words) counts[w] = (counts[w] || 0) + 1;
      const repeated = Object.entries(counts)
        .filter(([w, n]) => n >= 4 && !STOPWORDS.has(w))
        .map(([w, n]) => `${w} x${n}`);
      const commas = (desc.match(/,/g) || []).length;
      const out = [];
      if (repeated.length) {
        out.push(finding({
          severity: "warn",
          title: `The description repeats terms: ${repeated.join(", ")}`,
          evidence: [{ file: "manifest.json", line: 1, text: desc.slice(0, 160) }],
        }));
      }
      if (commas >= 8 && words.length / Math.max(commas, 1) < 4) {
        out.push(finding({
          severity: "warn",
          title: "The description reads as a comma-separated keyword list rather than prose",
          detail: "Padding with site lists or locations to game search ranking is the named trigger.",
          evidence: [{ file: "manifest.json", line: 1, text: desc.slice(0, 160) }],
        }));
      }
      return out;
    },
  },

  {
    id: "ntp-override",
    category: "circumvents-api-ntp",
    run({ manifest, files }) {
      if (!manifest) return [];
      const overrides = manifest.chrome_url_overrides || {};
      // ONLY chrome_url_overrides.newtab excuses this, and the narrowing is the
      // whole point of the rule. It used to accept chrome_settings_overrides
      // .homepage or .search_provider as well - but those govern the HOMEPAGE and
      // the OMNIBOX, which are different surfaces with their own override APIs.
      // The effect was that an extension hijacking the New Tab Page from code
      // could silence a FAIL by declaring an unrelated homepage override, which
      // is the manoeuvre the policy exists to catch. Confirmed by running two
      // packages whose code was byte-identical: adding a homepage key turned
      // "1 failing" into "0 failing".
      //
      // What the detection below actually looks for is newtab and nothing else,
      // so the declaration that answers it must be newtab and nothing else. If a
      // future version detects omnibox or homepage manipulation, it needs its own
      // hits list paired with its own key - not a shared any-of-three flag.
      const declared = Boolean(overrides.newtab);
      const hits = grep(codeView(files), /chrome:\/\/newtab|["'`]about:newtab|chrome\.tabs\.update\([^)]*newtab/i, isCode);
      if (!hits.length || declared) return [];
      return [finding({
        severity: "fail",
        title: "The code touches the New Tab Page without declaring the official override",
        detail:
          "Changing the New Tab Page or the omnibox by any route other than the documented Override API is the " +
          "named trigger. Declare chrome_url_overrides.newtab (or chrome_settings_overrides) instead.",
        evidence: hits,
      })];
    },
  },

  // --- the four 1 August 2026 changes ---------------------------------------

  {
    id: "disclosure-2026",
    category: "udp-prominent-disclosure",
    change: "Disclosure Requirements Policy",
    run({ manifest }) {
      if (!manifest) return [];
      const declared = [...(manifest.permissions || []), ...(manifest.optional_permissions || [])];
      const dataPerms = declared.filter((p) => DATA_PERMISSIONS.includes(p));
      const broadHosts = [...new Set(declaredHosts(manifest).filter((h) => BROAD_HOSTS.includes(h)))];
      const broad = broadHosts.length > 0;
      if (!dataPerms.length && !broad) return [];
      return [finding({
        severity: "warn",
        title: `User data is in scope (${[...dataPerms, broad ? "broad host access" : null].filter(Boolean).join(", ")}), so disclosure must happen BEFORE installation`,
        detail:
          "This changed on 1 August 2026 and the change is easy to miss. The old rule only bit when the data was " +
          "NOT closely related to the extension's single purpose. The live policy now covers ANY user data. " +
          "The disclosure lives in your store listing, which this tool cannot see, so verify it yourself. " +
          "READ THE WARNING BELOW ABOUT GOOGLE'S OWN TROUBLESHOOTING PAGE.",
        evidence: [
          ...dataPerms.map((p) => ({ file: "manifest.json", line: 1, text: `"${p}"` })),
          // Named so the developer can find it: broad access reaches this rule
          // from three different manifest keys and the fix is in whichever one
          // they actually wrote.
          ...broadHosts.map((h) => ({ file: "manifest.json", line: 1, text: `"${h}"` })),
        ],
      })];
    },
  },

  {
    id: "limited-use-2026",
    category: "udp-other-requirements",
    change: "Limited Use Policy",
    run({ manifest }) {
      if (!manifest) return [];
      // optional_permissions COUNT, and leaving them out was drift rather than a
      // decision: disclosure-2026 twenty lines up reads both keys, and so does
      // unused-permissions, so one extension got told its history access was in
      // scope for disclosure and NOT in scope for limited use. An optional
      // permission collects exactly the same data once the user grants it; the
      // difference is when it is asked for, not what it reaches.
      const declared = [
        ...(manifest.permissions || []).map((p) => ({ p, optional: false })),
        ...(manifest.optional_permissions || []).map((p) => ({ p, optional: true })),
      ];
      const collecting = declared.filter(({ p }) => ["history", "topSites", "browsingData", "bookmarks", "cookies", "webRequest", "webNavigation"].includes(p));
      if (!collecting.length) return [];
      return [finding({
        severity: "warn",
        title: `Browsing-activity permissions declared: ${collecting.map(({ p, optional }) => (optional ? `${p} (optional)` : p)).join(", ")}`,
        detail:
          "Under the policy as updated on 1 August 2026, data collected must be necessary for the disclosed " +
          "single purpose. Write down, per permission, the visible feature that stops working without it. If you " +
          "cannot name one, that permission is the finding. Note the live policy DOES allow related operational " +
          "purposes such as maintaining, securing or measuring performance; the announcement's wording did not " +
          "convey that, so do not over-correct.",
        evidence: collecting.map(({ p, optional }) => ({ file: "manifest.json", line: 1, text: `"${p}"${optional ? " in optional_permissions" : ""}` })),
      })];
    },
  },

  {
    id: "prediction-markets-2026",
    category: "gambling",
    change: "Regulated Goods and Services",
    run({ manifest, files }) {
      const hits = grep(files, /prediction market|polymarket|kalshi|sportsbook|betting odds|parlay|real money gambling/i, (f) => isCode(f) || isMarkup(f));
      const desc = (manifest?.description || "") + " " + (manifest?.name || "");
      const inDesc = /prediction market|betting|gambling|casino|sportsbook/i.test(desc);
      if (!hits.length && !inDesc) return [];
      const evidence = hits.slice(0, 12);
      if (inDesc) evidence.unshift({ file: "manifest.json", line: 1, text: desc.trim().slice(0, 160) });
      return [finding({
        severity: "warn",
        title: "Prediction market or gambling terms appear in the package",
        detail:
          "Prediction markets became explicitly prohibited on 1 August 2026. A mention is not a violation, which " +
          "is why this warns: the policy bites on facilitating real money transactions. There is also a carve-out " +
          "the announcement left out entirely, quoted below, for simulated markets with no real money, provided " +
          "you clearly say no real money is involved.",
        evidence,
      })];
    },
  },

  {
    id: "ai-guardrail-2026",
    category: null,
    change: "Malicious and Prohibited Products Policy",
    run({ files, manifest }) {
      const hits = grep(files, /jailbreak|bypass (the )?(content )?(filter|guardrail|safety)|uncensored (gpt|llm|model)|remove (the )?safety (filter|guardrail)/i, (f) => isCode(f) || isMarkup(f));
      const desc = (manifest?.description || "") + " " + (manifest?.name || "");
      const inDesc = /jailbreak|uncensored|bypass.{0,12}(filter|guardrail)/i.test(desc);
      if (!hits.length && !inDesc) return [];
      const evidence = hits.slice(0, 12);
      if (inDesc) evidence.unshift({ file: "manifest.json", line: 1, text: desc.trim().slice(0, 160) });
      return [finding({
        severity: "info",
        title: "Language suggesting circumvention of an AI service's safety guardrails",
        detail:
          "Announced on 1 July 2026 as a new prohibition, effective 1 August. IT IS INFO RATHER THAN A FAILURE " +
          "FOR A SPECIFIC REASON: as of the dataset date this clause exists ONLY in the announcement blog post. " +
          "The words guardrail and AI-powered appear on no Chrome Web Store policy page, the live Malicious and " +
          "Prohibited Products page still carries a 2022 last-updated date, and there is no notification ID for " +
          "it. So there is nothing enforceable to quote at you, and equally nothing to rely on.",
        evidence,
      })];
    },
  },
];
