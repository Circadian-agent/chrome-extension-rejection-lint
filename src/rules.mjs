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

import { grep, grepAcross, isCode, isMarkup } from "./scan.mjs";

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
      const evals = grep(files, /(^|[^.\w])eval\s*\(|new\s+Function\s*\(/, isCode);
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
    run({ manifest, files }) {
      if (!manifest) return [];
      const declared = [...(manifest.permissions || []), ...(manifest.optional_permissions || [])];
      const code = files.filter(isCode).map((f) => f.text).join("\n");
      const unused = declared.filter((p) => {
        const apis = PERMISSION_API[p];
        if (!apis) return false; // unknown permission: say nothing rather than guess
        return !apis.some((a) => code.includes(a));
      });
      if (!unused.length) return [];
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
    run({ manifest }) {
      if (!manifest) return [];
      const out = [];
      const desc = (manifest.description || "").trim();
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
      const hits = grep(
        files,
        /["'`]http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])[^"'`\s]+/i,
        (f) => isCode(f) || isMarkup(f),
      );
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
      const hits = grep(files, /coinhive|cryptonight|cryptoloot|webminerpool|minergate|\bcoinimp\b/i, (f) => isCode(f) || isMarkup(f));
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
      const repeated = Object.entries(counts).filter(([, n]) => n >= 4).map(([w, n]) => `${w} x${n}`);
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
      const settings = manifest.chrome_settings_overrides || {};
      const declared = Boolean(overrides.newtab) || Boolean(settings.search_provider) || Boolean(settings.homepage);
      const hits = grep(files, /chrome:\/\/newtab|["'`]about:newtab|chrome\.tabs\.update\([^)]*newtab/i, isCode);
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
      const declared = [...(manifest.permissions || [])];
      const collecting = declared.filter((p) => ["history", "topSites", "browsingData", "bookmarks", "cookies", "webRequest", "webNavigation"].includes(p));
      if (!collecting.length) return [];
      return [finding({
        severity: "warn",
        title: `Browsing-activity permissions declared: ${collecting.join(", ")}`,
        detail:
          "Under the policy as updated on 1 August 2026, data collected must be necessary for the disclosed " +
          "single purpose. Write down, per permission, the visible feature that stops working without it. If you " +
          "cannot name one, that permission is the finding. Note the live policy DOES allow related operational " +
          "purposes such as maintaining, securing or measuring performance; the announcement's wording did not " +
          "convey that, so do not over-correct.",
        evidence: collecting.map((p) => ({ file: "manifest.json", line: 1, text: `"${p}"` })),
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
