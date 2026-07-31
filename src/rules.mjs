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

import { grep, grepAcross, grepLarge, largeWindows, isCode, isMarkup, codeView, excerptAround } from "./scan.mjs";
import {
  MANIFEST_EVIDENCE, PERMISSION_API, NO_NAMESPACE_PERMISSIONS,
  namespaceUsed, looksMinified, looksMinifiedLarge, bareImports,
} from "./audit.mjs";

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

// The chrome.* namespaces a permission unlocks live in audit.mjs and are imported
// above. A permission whose namespace never appears is the exact trigger Google
// names for Purple Potassium. There used to be a second copy of that table here,
// on the reasoning that this rule wants a boolean where the audit wants call
// sites - true of the consumers, not of the data, and the two drifted by four
// permissions before anyone counted them (T-0421).

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

// Replace every match with the same number of characters, keeping newlines
// where they are. Offsets and line numbers survive, so a hit found AFTER
// blanking still points at the right line - which is the whole reason this
// blanks rather than deletes. Same idea as stripComments() in scan.mjs: a
// construct that must not be searched is erased in place, not cut out.
function blank(text, re) {
  return text.replace(re, (m) => m.replace(/[^\n]/g, " "));
}

// ONE implementation of "is this directory a source tree", shared by the two
// rules that ask. It is memoised on the files array rather than plumbed through
// the context on purpose: a seam that a caller has to remember to fill is a
// seam that silently reads empty the first time somebody forgets (T-0291), and
// the failure would be this rule quietly never firing.
const bareCache = new WeakMap();
function bareOf(files) {
  if (bareCache.has(files)) return bareCache.get(files);
  const v = bareImports(codeView(files).filter(isCode));
  bareCache.set(files, v);
  return v;
}

// Every file the MANIFEST says the package contains. These are the references
// Chrome resolves at load time, so a missing one is not a style question - the
// package does not load at all.
//
// Wildcards are excluded: web_accessible_resources legitimately uses them and a
// pattern is not a path. Icons are excluded too, deliberately - scan() only
// reads text files, so an icon that is present would be invisible to the check
// and would report as missing on every package in the world.
const norm = (p) => String(p).split(/[\\/]/).join("/").replace(/^\.\//, "").replace(/[?#].*$/, "");
function declaredFiles(manifest) {
  const m = manifest || {};
  const out = [];
  const add = (v, key) => { if (typeof v === "string" && v && !v.includes("*")) out.push({ path: norm(v), key }); };
  add(m.background?.service_worker, "background.service_worker");
  add(m.background?.page, "background.page");
  for (const s of m.background?.scripts || []) add(s, "background.scripts");
  for (const cs of m.content_scripts || []) {
    for (const j of cs.js || []) add(j, "content_scripts[].js");
    for (const c of cs.css || []) add(c, "content_scripts[].css");
  }
  add(m.action?.default_popup, "action.default_popup");
  add(m.browser_action?.default_popup, "browser_action.default_popup");
  add(m.page_action?.default_popup, "page_action.default_popup");
  add(m.options_page, "options_page");
  add(m.options_ui?.page, "options_ui.page");
  add(m.devtools_page, "devtools_page");
  add(m.side_panel?.default_path, "side_panel.default_path");
  for (const [k, v] of Object.entries(m.chrome_url_overrides || {})) add(v, `chrome_url_overrides.${k}`);
  for (const p of m.sandbox?.pages || []) add(p, "sandbox.pages");
  return out;
}

// A file the scanner SKIPPED is present - it was too big or unreadable, not
// absent. Counting it as missing would be the exact inversion this codebase
// keeps warning about: an instrument failure rendering as a finding.
const missingCache = new WeakMap();
function missingDeclaredOf(manifest, files, skipped = []) {
  if (missingCache.has(files)) return missingCache.get(files);
  const present = new Set([...files.map((f) => norm(f.path)), ...skipped.map((s) => norm(s.path))]);
  const v = declaredFiles(manifest).filter((d) => !present.has(d.path));
  missingCache.set(files, v);
  return v;
}

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
      const bare = bareOf(files);
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

  // SECOND, AND FOR THE SAME REASON AS unbuilt-source: it decides whether the
  // findings under it are about a package at all. That rule catches a source
  // tree by its imports; this one catches a MANIFEST FRAGMENT, which has no
  // imports to give it away and which the import test therefore walks straight
  // past.
  //
  // `name` and `version` are the two keys Chrome requires of every manifest, so
  // a file missing either cannot load - it is not a strict manifest that needs
  // fixing, it is an input a build step merges into one. Measured on real
  // repositories rather than imagined: darkreader ships src/manifest.json at MV2
  // plus src/manifest-chrome-mv3.json holding ONLY the MV3 deltas (no name, no
  // version, no description), and automa ships src/manifest.chrome.json with a
  // name but no version - both assemble the real thing at build time.
  //
  // What this replaces is the reason it exists. Both of those repositories were
  // being told "manifest.json has no description" at severity FAIL, which is a
  // true sentence about the file and a wrong diagnosis of the situation: it
  // sends someone to add a description to a fragment that is not supposed to
  // have one, and it never mentions the two keys whose absence actually matters.
  //
  // WARN, not fail, on the same contract as unbuilt-source: distinguishing "a
  // fragment" from "a manifest with a real mistake in it" needs the build output,
  // which this tool cannot see.
  {
    id: "incomplete-manifest",
    // NO CATEGORY, deliberately, exactly as unbuilt-source. This is a finding
    // about where the tool is pointed, not about anything Google requires, and
    // attaching a policy quote to it would be a paraphrase of a rule that does
    // not cover this.
    run({ manifest }) {
      if (!manifest) return [];
      const missing = ["name", "version"].filter((k) => !String(manifest[k] ?? "").trim());
      if (!missing.length) return [];
      return [finding({
        severity: "warn",
        title: `manifest.json declares no ${missing.join(" and no ")}, so this is a build fragment rather than a package Chrome can load`,
        detail:
          `Chrome requires ${missing.join(" and ")} in every manifest and refuses to load a package without ` +
          "them, so a file missing them is almost always one input to a build step that merges several manifests " +
          "into the real one - a chrome-only variant, or a base shared with Firefox. Point this tool at your BUILD " +
          "OUTPUT, or at the unzipped package you would upload. Until you do, treat every finding below with care " +
          "and the ABSENCE of a finding with more: checks that read your name, version, description or icons are " +
          "reading a file that was never meant to hold them.",
        evidence: missing.map((k) => ({ file: "manifest.json", line: 1, text: `${k} absent` })),
      })];
    },
  },

  // THIRD AIMING RULE, and the sharpest of the three because it is not a
  // heuristic at all: Chrome resolves these paths at load time, so a package
  // missing one does not load. If the files the manifest names are not here,
  // this is not the package.
  //
  // It exists because two extensions were failed at severity FAIL for
  // permissions "never used" in code that was not in the directory:
  //
  //   Authenticator-Extension/Authenticator - the walker staged
  //     manifests/manifest-chrome.json, a directory of SEVEN JSON FILES AND NO
  //     CODE. We told a 2FA extension to delete storage, identity, alarms,
  //     scripting and contextMenus having read none of its source. Its manifest
  //     names dist/background.js and view/popup.html, neither of which is there.
  //
  //   uddin-rajaul/Neko-Tab - public/ holds the manifest, the icons and two
  //     scripts; the new tab page it declares (index.html) is built from src/.
  //     topSites, identity and history are used by that page.
  //
  // unbuilt-source cannot catch either: it looks for bare module imports, and
  // there is barely any code here to import anything. Absence of code reads
  // exactly like absence of a violation, which is the failure mode this whole
  // file keeps circling.
  //
  // WARN, on the same contract as the other two aiming rules. If the file really
  // is missing from the package you upload, Chrome refuses it outright and this
  // is the most important line in the output - but telling that apart from
  // "pointed at the wrong directory" needs the build output we cannot see.
  {
    id: "missing-declared-files",
    // NO CATEGORY, as with unbuilt-source and incomplete-manifest.
    run({ manifest, files, skipped = [] }) {
      if (!manifest) return [];
      const missing = missingDeclaredOf(manifest, files, skipped);
      if (!missing.length) return [];
      const names = missing.slice(0, 3).map((d) => d.path).join(", ");
      return [finding({
        severity: "warn",
        title: `manifest.json names ${missing.length} file(s) that are not in this directory: ${names}${missing.length > 3 ? ", ..." : ""}`,
        detail:
          "Chrome resolves these paths when it loads the package, so if they are still missing when you upload, " +
          "it is refused before any reviewer sees it. Far more often it means this directory is not the package - " +
          "the files are produced by a build, or the manifest is one of several kept together in a folder of their " +
          "own. Point this tool at your BUILD OUTPUT or at the unzipped package you would upload. Until you do, " +
          "treat the ABSENCE of a finding with particular care: checks that look for where a permission is used " +
          "are reading code that is not here.",
        evidence: missing.slice(0, 6).map((d) => ({ file: "manifest.json", line: 1, text: `${d.key}: ${d.path}` })),
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
    run({ manifest, files, skipped = [], oversized = [] }) {
      const out = [];
      // A TEST FILE IS NOT THE PACKAGE CHROME REVIEWS, and pretending otherwise
      // was this rule's largest source of wrong FAILs. Measured over 94 packages
      // from 160 public repos: of 20 remote-code findings, THREE cited nothing
      // but test code - Nagi-ovo/voyager was failed on one line in
      // `__tests__/preventAutoScrollScript.test.ts` and nothing else - and five
      // more buried their real site in test noise (scriptcat 13 of 15 sites,
      // TTV-AB 12 of 13, pie-ai-agent 6 of 7).
      //
      // Test files are what a build excludes; a developer who has to scroll past
      // twelve of them to find the one line that matters is the developer who
      // stops running the tool. So the sites are PARTITIONED, never deleted: a
      // package that really does ship its tests still gets told, just not at
      // FAIL. Silence is the failure mode this repo keeps punishing.
      const looksLikeTest = (f) =>
        /(^|\/)(__tests__|__test__|test|tests|spec|__mocks__|e2e|cypress)(\/|$)/i.test(f) ||
        /\.(test|spec)\.[cm]?[jt]sx?$/i.test(f) ||
        /(^|\/)test-[^/]*\.[cm]?[jt]sx?$/i.test(f);
      // Named in the FAIL text so the count a developer sees adds up. Without
      // this, evidence would list sites the title never accounts for.
      const testNote = (tests) => tests.length
        ? ` A further ${tests.length} site(s) are in test files, listed after the ones above; a build normally excludes those.`
        : "";
      // Shipped sites first so the line that matters is the line they read.
      const split = (hits, mk) => {
        if (!hits.length) return;
        const tests = hits.filter((h) => looksLikeTest(h.file));
        const shipped = hits.filter((h) => !looksLikeTest(h.file));
        out.push(mk(shipped, tests));
      };
      // [^>] already crosses newlines - a JS character class ignores line
      // structure - so the pattern was never the problem and must NOT be widened
      // to [\s\S]: that would run past the closing > of this tag and match a
      // remote src on some later <img>. The bug was that grep() fed it one line
      // at a time, so it was never shown a newline to cross.
      // AN HTML FILE NO EXTENSION PAGE CAN OPEN IS A WEBSITE, NOT A VIOLATION.
      // Rat-S/ai-chat-exporter is FAILed on three sites and all three are its
      // GitHub Pages site: `docs/404.html` loads cdn.tailwindcss.com and two
      // feedback pages embed a Tally widget. Nothing in that manifest references
      // `docs/`; the package ships `popup/`, `content/`, `background/`,
      // `options/`, `sidepanel/` and `schemas/`. So the highest-severity finding
      // this tool produces was 100% wrong on a real extension, and a developer
      // who deletes a CDN tag from their marketing site to satisfy us has been
      // actively misled. Found by auditing the low-star band the s106 sampling
      // fix added - a population the old 35-star corpus contained none of, and
      // the one that actually gets rejected.
      //
      // WHY THIS IS DECIDABLE FOR MARKUP AND NOT FOR CODE. A JS file can be
      // pulled in by any dynamic import or bundler chunk, so "unreachable" is
      // not provable. An HTML file only executes when something OPENS it, and
      // the manifest is where an extension declares its pages. That asymmetry is
      // why this partition is applied to the <script src> scan alone.
      //
      // THE DIRECTORY, NOT THE FILE, is the unit, and deliberately so. An
      // extension may open `popup/help.html` with `chrome.tabs.create` without
      // ever naming it in the manifest, and that page is real. But `popup/` is a
      // directory the manifest DOES reference, so it stays shipped. A directory
      // the manifest references nothing in at all is the project's website,
      // its documentation or its CI - not its page graph.
      //
      // AND IT PARTITIONS, IT DOES NOT DELETE - the same rule the test split
      // follows for the same reason. Every site is still listed and still named;
      // it just cannot carry FAIL on its own. Silence is the failure mode this
      // repo keeps punishing.
      // THE BASENAME IS CHECKED TOO, AND A REAL MISS IS WHY. The first version of
      // this partition compared source-tree paths against a manifest that
      // describes the BUILT layout, and demoted a genuine violation in
      // google/archat: its manifest declares `options_ui.page: "options.html"`
      // while the repository keeps that page at `options/options.html` and the
      // rollup config flattens it on build. The directory `options/` is named
      // nowhere in the manifest, so a directory-only test called Google's own
      // extension a website and walked past a Google Tag Manager <script> in it.
      // Caught by A/B-ing the change over the cached SOURCE trees - the release
      // A/B could not have caught it, because a built zip has no `options/` to
      // flatten. A basename match resolves the ambiguity toward FAIL, which is
      // the safe direction for the highest-severity rule in the tool.
      const liveDirs = new Set([""]);
      const liveNames = new Set();
      const collectRefs = (v) => {
        if (typeof v === "string") {
          if (/^(https?:|data:|\/\/)/i.test(v) || !/\.[a-z0-9]{2,5}$/i.test(v)) return;
          const p = v.replace(/^\.?\//, "");
          // Every ancestor of a referenced file is part of the page graph:
          // `content/lib/*.js` makes both `content/lib` and `content` live.
          const parts = p.split("/");
          liveNames.add(parts[parts.length - 1].toLowerCase());
          for (let i = parts.length - 1; i >= 0; i--) liveDirs.add(parts.slice(0, i).join("/"));
          return;
        }
        if (Array.isArray(v)) { v.forEach(collectRefs); return; }
        if (v && typeof v === "object") { Object.values(v).forEach(collectRefs); }
      };
      collectRefs(manifest || {});
      const offPackage = (f) => {
        const i = f.lastIndexOf("/");
        if (liveNames.has(f.slice(i + 1).toLowerCase())) return false;
        return !liveDirs.has(i < 0 ? "" : f.slice(0, i));
      };

      const remoteScriptAll = grepAcross(files, /<script[^>]+src\s*=\s*["'](https?:)?\/\/[^"']+/i, isMarkup);
      const remoteScript = remoteScriptAll.filter((h) => !offPackage(h.file) || looksLikeTest(h.file));
      const website = remoteScriptAll.filter((h) => offPackage(h.file) && !looksLikeTest(h.file));
      // Emitted whenever there are any, NOT only when nothing else fired. Gating
      // it on "no other sites" is how a partition quietly becomes a deletion:
      // a package with one real violation and three website hits would report
      // the one and drop the three without saying so.
      if (website.length) {
        out.push(finding({
          severity: "warn",
          title: `A <script> tag loads remote code, but only in pages your manifest never opens (${website.length} site(s))`,
          detail:
            "Every site is in a directory your manifest references nothing in - typically a project website, a docs "
            + "folder or CI. Chrome only reviews what you upload, and a page no extension surface can open cannot "
            + "run, which is why this is not a failure. Check it against the zip you actually upload: if these files "
            + "DO ship and a page of yours opens one, it is the real violation and Google names it as the first "
            + "trigger for this category.",
          evidence: website,
        }));
      }
      split(remoteScript, (shipped, tests) => shipped.length
        ? finding({
            severity: "fail",
            title: "A <script> tag loads code from outside the extension package",
            detail: "Google names this as the first trigger for this category. The referenced file must be vendored into the package."
              + testNote(tests),
            evidence: [...shipped, ...tests],
          })
        : finding({
            severity: "warn",
            title: `A <script> tag loads remote code, but only in test files (${tests.length} site(s))`,
            detail:
              "Every site is in a file this tool reads as a test. Builds normally exclude those, so this is very "
              + "likely not in the package you upload - which is why it is not a failure. Check your build output: "
              + "if these files DO ship, it is the real violation and Google names it as the first trigger for this category.",
            evidence: tests,
          }));
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
      // COMMENTS BLANKED FIRST, and only comments. Fannon/search-bookmarks was
      // failed on `popup/js/model/validateOptions.js:6`, whose text reads "This
      // is a CSP-safe recursive validator that doesn't require eval() or
      // Function()" - a sentence saying the code does NOT do this, quoted back
      // as proof that it does. A comment cannot execute, so blanking one can
      // never hide a violation.
      //
      // STRING LITERALS ARE DELIBERATELY LEFT ALONE (T-0411). Blanking them
      // would also silence automa, which assembles code inside a template
      // literal and then injects it - a real violation. `stripComments` steps
      // over strings and preserves newlines, so line numbers still line up.
      //
      // TWO SITE SHAPES ARE PROVABLY NOT STRING EXECUTION AND ARE SKIPPED
      // (T-0414, measured on 79 shipped release packages rather than source
      // trees). Both are skipped per MATCH, so the scan continues along the same
      // line - see grep() in scan.mjs for why that distinction is the whole
      // point. Between them they were the SOLE evidence behind 8 of 23 FAILs.
      //
      // 1. `new Function("return this")` is webpack's globalThis shim. A BUNDLER
      //    emits it; no developer wrote it and none can delete it without
      //    changing bundler config. The argument is an eleven-character literal,
      //    so it cannot carry anything from the network - and webpack already
      //    wraps it in try/catch precisely because an extension CSP blocks it.
      //    Present in 13 of the 23 packages, and the only site in floccus,
      //    aniskip, copycat and chatGPTBox. It was also MASKING a real
      //    `new Function(scriptText)(window)` in two screenity bundles.
      // 2. `eval(a, b){` is a METHOD DEFINITION NAMED eval, not a call: a call
      //    is never followed by a block. less.js declares `eval()` on its AST
      //    node classes, which FAILed openstyles/stylus on three sites that are
      //    all definitions. The `[^.\w$]` guard cannot see these because the
      //    preceding character in minified code is `}`.
      //
      // STRING-BLANKING IS REFUSED, AND THIS IS THE MEASUREMENT RATHER THAN A
      // PREFERENCE (T-0416, settled on the 82 cached release packages).
      //
      // T-0416 proposed blanking plain string literals while sparing template
      // literals that interpolate, so that HackTools' XSS cheat-sheet text and
      // scriptcat's bundled ESLint metadata stop FAILing. Implemented as a
      // probe, that rule reclassified 28 sites - and only FOUR of them are the
      // inert text it was aimed at. Six were REAL violations that a
      // quote-tracking scan had misread, and eighteen were executable source
      // deliberately embedded as a string (ace's worker in dejavu, an injected
      // bundle in nanobrowser, a whole webpack bundle in wechatsync, which
      // executes text fetched from a remote page).
      //
      // THE MECHANISM IS THE PART THAT TRANSFERS. `stripComments` bails a
      // quoted string at a NEWLINE, which bounds the damage of a mispaired
      // quote to one line. A minified bundle is ONE line - screenity's is
      // 462,552 characters with zero newlines - so that bound never applies and
      // a single misread quote reclassifies the rest of the file.
      //
      // THE CONTROL THAT SETTLES IT is inside one package. screenity ships the
      // same bundled library twice, and both copies execute the text of a
      // <script> element they found: `new Function(x[P])(window)` in
      // cloudrecorder.bundle.js and `new Function(k[E])(window)` in
      // contentScript.bundle.js, byte-identical but for minifier variable
      // names. A quote-tracking scan calls the first one CODE and puts the
      // second inside a 93,061-character "string literal". Identical code, two
      // answers - so the scan cannot be a basis for silencing anything, and
      // blanking would have silenced the very violation s101 unmasked.
      //
      // THE DIRECTION OF SAFETY INVERTS WHEN THE SCANNER IS REUSED. Missing a
      // comment leaves code visible, which is why stripComments resolves every
      // ambiguity toward "not a comment". Asking the SAME scanner to blank
      // strings turns each of those misreads into a deleted violation. A
      // fail-safe scanner is only fail-safe for the question it was built for.
      //
      // What IS fixed here is the part that needs no string tracking at all:
      // `eval()` with an empty argument list executes nothing and returns
      // undefined, so it is provably not string execution - the same kind of
      // local, per-match proof as the two skips below. That is scriptcat's two
      // sites, whose text is "Disallow the use of `eval()`". HackTools' two
      // sites are real-looking calls (`eval('ale'+'rt(0)')`) that happen to sit
      // in a string, and nothing local separates them from a genuine call, so
      // they are LEFT FAILING rather than guessed at.
      const BUNDLER_GLOBAL_SHIM = /^new\s+Function\s*\(\s*(["'])return this\1\s*\)/;
      const EVAL_METHOD_DEF = /^eval\s*\(\s*(?:[A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*)*)?\s*\)\s*\{/;
      const EVAL_NO_ARGS = /^eval\s*\(\s*\)/;
      const executesAString = (m, line) => {
        // m[1] is the leading non-identifier char of the eval branch, which is
        // part of the match but not part of the site.
        const at = m.index + (m[1] ? m[1].length : 0);
        const tail = line.slice(at, at + 80);
        return !BUNDLER_GLOBAL_SHIM.test(tail) && !EVAL_METHOD_DEF.test(tail)
          && !EVAL_NO_ARGS.test(tail);
      };
      const source = new Map(files.map((f) => [f.path, f.lines]));
      const EVAL_RE = /(^|[^.\w$])eval\s*\(|new\s+Function\s*\(/;
      const evals = grep(codeView(files), EVAL_RE, isCode, executesAString)
        // Report the ORIGINAL line, not the blanked one: evidence a developer
        // reads has to match what is in their editor.
        //
        // RE-EXCERPT IT, do not paste the whole line back. Substituting the raw
        // line here used to discard grep()'s excerpt AND its 160-char cap, which
        // is how a 9,155-character line of malware reached the report rendered as
        // its innocent first 22 characters (`export default config;`, then 507
        // spaces of padding). The excerpt has to follow the match through the
        // substitution, which is what `col` is for.
        .map((h) => {
          const original = source.get(h.file)?.[h.line - 1];
          return original === undefined
            ? h
            : { ...h, text: excerptAround(original, h.col ?? 0, h.match?.length ?? 0) };
        })
        // THE FILES TOO BIG TO HOLD ARE SEARCHED, NOT APOLOGISED FOR (T-0417).
        // Same pattern, same per-match `accept`, same comment blanking - the
        // only difference is that grepLarge slides a window over the file
        // instead of holding it. These are appended rather than reported
        // separately so a 4 MB content script produces the same FAIL as a 4 KB
        // one; the size of the file is the tool's problem, not the developer's.
        .concat(grepLarge(oversized, EVAL_RE, { filter: isCode, code: true, accept: executesAString }));
      split(evals, (shipped, tests) => shipped.length
        ? finding({
            severity: "fail",
            title: "eval() or new Function() executes a string as code",
            detail:
              "Google's trigger is executing a string fetched from a remote source. This tool cannot prove where "
              + "your string comes from, so review each site: if the string is a literal in your own package it is "
              + "defensible, and if any part of it arrives over the network it is the violation."
              + testNote(tests),
            evidence: [...shipped, ...tests],
          })
        : finding({
            severity: "warn",
            title: `eval() or new Function() appears only in test files (${tests.length} site(s))`,
            detail:
              "Every site is in a file this tool reads as a test, and builds normally exclude those, so this is "
              + "very likely not in the package you upload. That is why it is not a failure. Confirm against your "
              + "build output: if these files do ship, review each site as a real remote-code risk.",
            evidence: tests,
          }));
      const DYN_IMPORT_RE = /import\s*\(\s*["'`](https?:)?\/\//;
      const dynImport = grepAcross(files, DYN_IMPORT_RE, isCode)
        // Not comment-blanked, matching grepAcross above: this pattern needs a
        // URL literal, which a prose comment does not carry by accident.
        .concat(grepLarge(oversized, DYN_IMPORT_RE, { filter: isCode }));
      split(dynImport, (shipped, tests) => shipped.length
        ? finding({
            severity: "fail",
            title: "A dynamic import() pulls a module from a remote URL",
            ...(tests.length ? { detail: testNote(tests).trim() } : {}),
            evidence: [...shipped, ...tests],
          })
        : finding({
            severity: "warn",
            title: `A dynamic import() pulls a remote module, but only in test files (${tests.length} site(s))`,
            detail:
              "Every site is in a file this tool reads as a test, which a build normally excludes. Confirm against "
              + "your build output: if these files do ship, it is a real remote-code violation.",
            evidence: tests,
          }));
      // "NO REMOTE CODE FOUND" IS A CLAIM ABOUT ALL THE CODE, and this rule was
      // making it about the code it happened to open. Same asymmetry
      // unused-permissions carries above, at a higher severity: scan.mjs skips
      // any file over 2 MB and lists it honestly, and this rule then went silent
      // as though the package were clean.
      //
      // MEASURED ON THE 82 CACHED RELEASE PACKAGES, not argued: 23 skip at least
      // one file for size, 13 of those produced no remote-code failure at all,
      // and in THREE of them an unread file holds a site this rule would have
      // reported. Anarios/return-youtube-dislike ships
      // `new Function('return (' + source + ');')()` in a 4.0 MB content script;
      // nanobrowser has two sites in a 3.8 MB service worker; bitwarden two more
      // in a 3.2 MB background.js. 27 reportable sites sit in unread files
      // across 7 packages. The tool told all three they were clean.
      //
      // The limit itself is left alone deliberately - a bigger number only moves
      // the cliff, and page-assist ships an 8.3 MB chunk. What must not survive
      // is the SILENCE, because a developer reads "no findings" as "nothing
      // there" and this is the rule Google enforces first.
      //
      // WHAT IS LEFT OF THAT GAP after T-0417 is HTML, and only HTML. The
      // JavaScript is now streamed above, so the warning must subtract exactly
      // what was streamed - printing "could not check" about a file this rule
      // did read is the same defect pointing the other way, and it would train
      // someone to go looking by hand for a site the tool already found.
      const streamed = new Set(oversized.filter(isCode).map((o) => o.path));
      const unreadCode = skipped.filter((s) =>
        /\.(js|mjs|cjs|ts|jsx|tsx|html?)$/i.test(s.path || "") && !streamed.has(s.path));
      if (unreadCode.length) {
        out.push(finding({
          severity: "warn",
          title: `${unreadCode.length} file(s) were too large to read, so this rule could not check them`,
          detail:
            "This is a limitation of the scan, not a defect found in your extension. JavaScript over 2 MB is "
            + "searched in a streaming pass, but these files are not, so remote code inside one of them would not "
            + "appear above - treat the result of this rule as covering only the files listed as read. Search these "
            + "yourself for eval(, new Function(, a dynamic import() of a URL, and <script src> pointing off-package.",
          evidence: unreadCode.map((s) => ({ file: s.path, line: 1, text: s.why })),
        }));
      }
      return out;
    },
  },

  {
    id: "unused-permissions",
    category: "excessive-permissions",
    run({ manifest, files, skipped = [], oversized = [] }) {
      if (!manifest) return [];
      const declared = [...(manifest.permissions || []), ...(manifest.optional_permissions || [])];
      // Comments blanked first. A permission whose only trace is "// we used to
      // call chrome.bookmarks.getTree here" is the COMMONEST real form of an
      // unused permission - the feature was deleted and the note left behind -
      // and reading raw text made this rule blind to exactly that case while
      // audit.mjs reported it. Shared with audit.mjs so the two cannot disagree.
      const view = codeView(files).filter(isCode);
      const code = view.map((f) => f.text).join("\n");
      let unused = declared.filter((p) => {
        const apis = PERMISSION_API[p];
        if (!apis) return false; // unknown permission: say nothing rather than guess
        // A permission with no namespace to look for is not a permission we
        // failed to find. namespaceUsed answers false for an empty pattern list,
        // and false here means FAIL, so without this activeTab would be reported
        // as unused on every extension that declares it - the one permission
        // Google's own advice, and this linter's narrowing advice, tells people
        // to move TO.
        if (NO_NAMESPACE_PERMISSIONS.has(p)) return false;
        // Not a literal `chrome.storage` test: a minifier aliases the namespace
        // and the literal test then reads as "never used". See namespaceUsed.
        if (namespaceUsed(code, apis)) return false;
        // Some permissions are earned by the manifest with no JavaScript at all
        // (a declarativeNetRequest static ruleset, a side_panel path). This rule
        // is a FAIL, so a false one here deletes a working feature.
        return !MANIFEST_EVIDENCE[p]?.(manifest);
      });
      // THE FILES TOO BIG TO HOLD ARE READ HERE TOO, and note which direction
      // that runs in. Finding a namespace in one can only ever REMOVE a
      // permission from this list - it is evidence of use, and use is the
      // fail-safe answer for this rule. Nothing below can add one.
      const largeCode = (oversized || []).filter(isCode);
      for (const f of largeCode) {
        if (!unused.length) break;
        for (const w of largeWindows(f, { code: true })) {
          unused = unused.filter((p) => !namespaceUsed(w.view, PERMISSION_API[p]));
          if (!unused.length) break;
        }
      }
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
      // Subtract exactly what was streamed and no more. The remaining entries
      // are oversized HTML and genuinely unreadable files, which really were not
      // read.
      const streamed = new Set(largeCode.map((o) => o.path));
      const unread = skipped.filter((s) =>
        /\.(js|mjs|cjs|ts|jsx|tsx|html?)$/i.test(s.path || "") && !streamed.has(s.path));
      // AND THE ONES WE DID READ STILL COUNT TOWARD (2), which is the half that
      // matters. Having read the bytes of a bundle is not having seen the name:
      // over the 82 cached release packages, dropping the unread caveat without
      // this would have turned 17 permissions in 7 packages into "declared but
      // never used", among them contextMenus and idle on Bitwarden, which uses
      // both. Every one is held here, because every oversized file in those
      // packages runs to between 170,000 and 1,056,768 characters on one line.
      const minified = [...looksMinified(view), ...looksMinifiedLarge(largeCode)];
      const bare = bareImports(view);
      // A DECLARED FILE THAT IS NOT HERE IS THE STRONGEST OF THESE FOUR, and it
      // was the one missing. The other three all describe code we read but could
      // not fully follow; this one says a piece of the package is ABSENT, which
      // absence-of-a-call cannot be distinguished from. Authenticator's manifest
      // names dist/background.js and we were linting a folder of seven JSON
      // files - "never used" there is a claim about nothing at all.
      const gone = missingDeclaredOf(manifest, files, skipped);
      if (unread.length || minified.length || bare.length || gone.length) {
        const why = gone.length
          ? `manifest.json names ${gone.length} file(s) that are not in this directory (${gone[0].key}: ${gone[0].path}), so the code that uses these permissions is not here to be read`
          : unread.length
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
    run({ manifest, files = [], skipped = [], i18nUnresolved = [] }) {
      if (!manifest) return [];
      // EVERY CHECK IN THIS RULE REASONS FROM AN ABSENCE, which makes it the one
      // rule most easily wrong about a directory that is not the final package.
      // A fragment is not missing a description, it is a file that never carried
      // one; incomplete-manifest says so in the words that lead somewhere, and
      // repeating it here as "no description" at FAIL is the wrong diagnosis
      // that rule exists to replace.
      if (!String(manifest.name ?? "").trim() || !String(manifest.version ?? "").trim()) return [];

      // "MISSING" IS A CLAIM ABOUT THE PACKAGE YOU WOULD UPLOAD, so it is a warn
      // when that package has not been built. Same move, and the same reasoning,
      // as unused-permissions downgrading "never used" when it could not read
      // all the code.
      //
      // The case that forced it: Nagi-ovo/voyager was failed for a __MSG_extName__
      // that "does not resolve", on a tree whose messages.json files sit in
      // src/locales/ and are copied to _locales/ by the build. The sentence is
      // true of the directory and false of the extension, and it was the highest
      // severity this tool emits.
      //
      // APPLIED AT ONE EXIT ON PURPOSE. This started life at the bottom of the
      // rule and was dead for the real case: a manifest whose DESCRIPTION is a
      // placeholder returns early a few lines below, which is precisely the
      // shape voyager has, so the downgrade never ran on the extension that
      // motivated it. The unit test passed anyway because its fixture used a
      // plain description and fell through to the end - a green assertion about
      // a path the reported case does not take. The corpus is what caught it.
      const finish = (list) => {
        // Missing declared files count for the same reason bare imports do, and
        // more strongly: Authenticator's _locales really is elsewhere, because
        // the directory we were handed holds nothing but manifests.
        if (!list.length || (!bareOf(files).length && !missingDeclaredOf(manifest, files, skipped).length)) return list;
        return list.map((f) => (f.severity !== "fail" ? f : {
          ...f,
          severity: "warn",
          detail: `${f.detail ? `${f.detail} ` : ""}Reported as a warning rather than a failure because this ` +
            "directory looks like source rather than a built package (see unbuilt-source above), and a build step " +
            "commonly supplies exactly these files - _locales/ is frequently copied in from elsewhere in the tree. " +
            "Re-run against your build output to get a definite answer.",
        }));
      };

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
      if (/__MSG_[A-Za-z0-9_@]+__/.test(desc)) return finish(out); // unresolved: nothing honest to measure
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
      return finish(out);
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
      if (declared) return [];

      // MENTIONING THE NEW TAB PAGE IS NOT OVERRIDING IT. This rule used to fire
      // on the URL appearing anywhere in the code, and against a corpus of 27
      // real packages that produced FOUR findings and ZERO true positives - a
      // rule with no demonstrated precision, at the top severity.
      //
      // The two benign shapes it could not tell from a hijack:
      //
      //   1. NAVIGATING TO the page. xifangczy/cat-catch (21k stars):
      //        if (tabs.length === 1) {
      //            await chrome.tabs.create({ url: 'chrome://newtab' });
      //      which is the documented way to close your last tab without closing
      //      the window.
      //
      //   2. RECOGNISING the page in order to LEAVE IT ALONE, which is the more
      //      common of the two and the one I missed on the first pass at this.
      //      obsidianmd/obsidian-clipper (19k):
      //        export function isBlankPage(url: string): boolean {
      //          return url === 'about:blank' || url === 'chrome://newtab/' ...
      //      used by isNormalPageUrl() to decide where a content script MAY be
      //      injected. Chrome forbids content scripts on chrome:// pages, so
      //      every careful extension has a guard like this - which means the old
      //      rule fired hardest on the extensions being most careful.
      //      extension-js and scriptscat/scriptcat were the same shape.
      //
      // So the question is not whether the URL appears. It is whether the code
      // REDIRECTS AWAY from it: the violation is replacing what the user gets
      // when they open a new tab. That needs two things near each other - a
      // reference to the page and a navigation - and neither alone means
      // anything. The old rule asked for one of them.
      //
      // Benign DESTINATIONS are blanked first (create/open/update TO the page,
      // all of which merely visit it), then a reference must sit within 200
      // characters of a real tabs.update() call. The proximity window is what
      // keeps a predicate in one function from pairing with a navigation in an
      // unrelated one further down the file.
      //
      // THIS IS A NARROWING, SO THE RISK IS A MISS. Two deliberate limits, named
      // so a later reader does not mistake them for oversights: an aliased or
      // destructured tabs API is not matched (`chrome.` or `browser.` is
      // required, which is also what keeps a test file's mockTabsUpdate out),
      // and a hijack that redirects by some route other than tabs.update is not
      // matched. Both are places to widen if a real case ever turns up; neither
      // is worth failing 4 innocent packages to cover today.
      const NTP = String.raw`(?:chrome|edge):\/\/newtab|about:newtab`;
      const visitsNtp = new RegExp(
        String.raw`(?:(?:chrome|browser)\.)?(?:tabs|windows)\.(?:create|update)\s*\([^;]{0,120}?url\s*:\s*["'\`]\s*(?:${NTP})[^"'\`]*["'\`]` +
        "|" +
        String.raw`window\.open\s*\(\s*["'\`]\s*(?:${NTP})[^"'\`]*["'\`]`, "gi");
      const view = codeView(files).map((f) => {
        if (!isCode(f)) return f;
        const text = blank(f.text, visitsNtp);
        return { ...f, text, lines: text.split("\n") };
      });
      const redirect = String.raw`(?:chrome|browser)\.tabs\.update\s*\(`;
      const hits = grepAcross(view, new RegExp(
        String.raw`(?:${NTP})[\s\S]{0,200}?${redirect}` + "|" + String.raw`${redirect}[\s\S]{0,200}?(?:${NTP})`,
        "gi"), isCode);
      if (!hits.length) return [];
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
