// Read an unpacked extension directory into memory, once, so every rule works
// from the same picture instead of walking the tree again.
//
// WHAT IS DELIBERATELY NOT READ: node_modules, .git, and anything over 2 MB.
// A rule that greps a 40 MB bundled vendor file produces a "finding" in code the
// developer did not write and cannot fix, which trains people to ignore output.
// Skipped files are RECORDED and reported, because a silent skip is how a linter
// says "clean" about a directory it never looked at.

import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, relative, extname } from "node:path";

// EVERY JSON FILE IN AN EXTENSION IS READ THROUGH THIS, and it exists for one
// byte sequence. `readFileSync(f, "utf8")` keeps a leading UTF-8 BOM (U+FEFF) in
// the string, and `JSON.parse` rejects it - while Chrome accepts it, because
// Chromium's JSON reader consumes a BOM before parsing. So a file Chrome loads
// without complaint reads to us as "not valid JSON".
//
// That is not hypothetical and it is not rare enough to ignore. In a corpus of
// 160 public repos, 4 of 2220 `messages.json` files carry a BOM, and two of them
// belong to extensions published on the Web Store right now: MarvellousSuspender
// (the maintained fork of The Great Suspender) and SmartProxy. MarvellousSuspender
// was reported at FAIL - "a localised manifest field does not resolve" - about a
// file with 374 perfectly good keys in it.
//
// THE DAMAGE IS WORSE THAN THE ONE FINDING. That extension's manifest carries
// `"name": "__MSG_ext_extension_name__"` with `default_locale: en`, so failing to
// read the locale file means we never learn its name or description at all, and
// every rule that reads either one is then reading a placeholder. One unparsed
// byte at offset 0 silently changes the input of four other rules.
//
// The manifest reader gets the same treatment. No manifest.json in the corpus
// carries a BOM today, so that half is a latent trap rather than a measured one -
// but it is the same one-line mistake at a far worse site, since an unparseable
// manifest aborts the whole scan and reports a working extension as unreadable.
const stripBom = (s) => (s.charCodeAt(0) === 0xfeff ? s.slice(1) : s);
const parseJson = (text) => JSON.parse(stripBom(text));

const SKIP_DIRS = new Set(["node_modules", ".git", ".svn", "dist-zip", ".cache"]);
const MAX_BYTES = 2 * 1024 * 1024;
const TEXT_EXT = new Set([
  ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".json", ".html", ".htm",
  ".css", ".txt", ".md", ".webmanifest",
]);

export function scan(root) {
  const files = [];
  const skipped = [];

  const walk = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      skipped.push({ path: relative(root, dir) || ".", why: `unreadable: ${e.code || e.message}` });
      return;
    }
    for (const e of entries) {
      const full = join(dir, e.name);
      const rel = relative(root, full);
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) { skipped.push({ path: rel, why: "not part of a submitted package" }); continue; }
        walk(full);
        continue;
      }
      if (!e.isFile()) continue;
      const ext = extname(e.name).toLowerCase();
      if (!TEXT_EXT.has(ext)) continue; // images, fonts, binaries: nothing to read
      let st;
      try { st = statSync(full); } catch { continue; }
      if (st.size > MAX_BYTES) {
        skipped.push({ path: rel, why: `${(st.size / 1048576).toFixed(1)} MB, over the 2 MB read limit` });
        continue;
      }
      let text;
      try { text = readFileSync(full, "utf8"); } catch (err) {
        skipped.push({ path: rel, why: `unreadable: ${err.code || err.message}` });
        continue;
      }
      files.push({ path: rel, ext, text, lines: text.split("\n") });
    }
  };

  walk(root);

  const manifestPath = join(root, "manifest.json");
  let manifest = null;
  let manifestError = null;
  if (!existsSync(manifestPath)) {
    // NAME THE ACTUAL PROBLEM. "no manifest.json in this directory" was printed
    // for a path that is not a directory and for a path that does not exist at
    // all, which sends someone to look for a file in a folder that was never
    // there - the same shape of misdiagnosis as measuring the length of an
    // unresolved __MSG_ placeholder. Pointing at manifest.json itself is the
    // commonest of these and the message now says so outright.
    let st = null;
    try { st = statSync(root); } catch { /* below */ }
    manifestError = !st
      ? `there is nothing at ${root}`
      : st.isDirectory()
        ? "no manifest.json in this directory"
        : /(^|[\\/])manifest\.json$/i.test(root)
          ? `${root} is the manifest itself. Point webstore-lint at the directory that contains it.`
          : `${root} is a file, not an unpacked extension directory`;
  } else {
    try {
      manifest = parseJson(readFileSync(manifestPath, "utf8"));
    } catch (e) {
      manifestError = `manifest.json is not valid JSON: ${e.message}`;
    }
  }

  const { manifest: localized, unresolved } = resolveI18n(manifest, files, skipped);

  return { root, files, skipped, manifest: localized, manifestRaw: manifest, i18nUnresolved: unresolved, manifestError };
}

// Chrome's own localisation, resolved before any rule reads the manifest.
//
// WHY THIS IS NOT COSMETIC. A localised extension does not put its description in
// manifest.json at all: it writes "__MSG_extDescription__" there and the real
// sentence lives in _locales/<default_locale>/messages.json. Three rules read
// that text - keyword-stuffing, prediction-markets-2026, ai-guardrail-2026 - and
// listing-metadata measures its length. Reading the placeholder literally meant
// TWO extensions with the identical description got opposite answers depending on
// whether they were localised, and the localised one got the wrong answer BOTH
// ways: a bogus "the description is 22 characters" warning, and total silence
// about a description reading "prediction market ... sportsbook betting". The
// silent direction is the dangerous one, because the finding it dropped is the
// one about a policy that starts being enforced on 1 August 2026.
//
// FAIL-SAFE DIRECTION: an unresolvable placeholder is left EXACTLY as written.
// This function never invents text. What it cannot resolve it reports, and the
// caller decides - a substituted guess would put words in a developer's listing
// that they never wrote.
//
// Only `name` and `description` are substituted, because those are the fields the
// rules read. Chrome allows __MSG_ in several other manifest fields; adding one
// here means checking that no rule reads it structurally first.
const I18N_FIELDS = ["name", "description"];

export function resolveI18n(manifest, files, skipped = []) {
  const unresolved = [];
  if (!manifest) return { manifest, unresolved };

  const needs = I18N_FIELDS.filter((f) => typeof manifest[f] === "string" && /__MSG_[A-Za-z0-9_@]+__/.test(manifest[f]));
  if (!needs.length) return { manifest, unresolved };

  const locale = typeof manifest.default_locale === "string" ? manifest.default_locale : null;
  const wanted = locale ? `_locales/${locale}/messages.json` : null;
  const file = wanted ? files.find((f) => f.path.split(/[\\/]/).join("/") === wanted) : null;
  // A locale file the scanner refused to read (over the size limit, unreadable)
  // is NOT evidence that a message is missing. Staying quiet there is the same
  // fail-safe direction as everything else in this file.
  const wasSkipped = wanted ? skipped.some((s) => s.path.split(/[\\/]/).join("/") === wanted) : false;

  let messages = null;
  if (file) {
    try {
      const parsed = parseJson(file.text);
      // Chrome treats message names as case-insensitive, so the lookup is too.
      messages = new Map(Object.entries(parsed).map(([k, v]) => [k.toLowerCase(), v]));
    } catch (e) {
      unresolved.push({ field: null, placeholder: null, why: `${wanted} is not valid JSON: ${e.message}` });
    }
  }

  const out = { ...manifest };
  for (const field of needs) {
    out[field] = manifest[field].replace(/__MSG_([A-Za-z0-9_@]+)__/g, (whole, key) => {
      const entry = messages?.get(key.toLowerCase());
      const text = entry && typeof entry.message === "string" ? entry.message : null;
      if (text !== null) return text;
      if (wasSkipped) return whole; // reported by the scanner already; do not double-accuse
      unresolved.push({
        field,
        placeholder: whole,
        why: !locale
          ? `manifest.json uses ${whole} but declares no default_locale`
          : !file
            ? `manifest.json uses ${whole} but the package has no ${wanted}`
            : `${wanted} has no message named ${key}`,
      });
      return whole;
    });
  }
  return { manifest: out, unresolved };
}

// Find every line matching a pattern, with its file and 1-indexed line number.
// Evidence is what separates a finding from an opinion, so every rule uses this
// rather than testing whole-file text and reporting the file alone.
//
// ONE MATCH PER LINE, AND ON MINIFIED CODE A LINE IS THE WHOLE FILE. That is
// fine for evidence - one site is enough to make a developer look - but it means
// WHICHEVER SITE COMES FIRST IN THE FILE IS THE ONLY SITE ANYONE EVER SEES. If
// that first site is something the rule would rather not report, the effect is
// not a tidier finding: it is a REAL site, later in the same line, that the tool
// silently never mentions. Measured on shipped packages (T-0414): screenity's
// `cloudrecorder.bundle.js` and `contentScript.bundle.js` each begin with
// webpack's `new Function("return this")` globalThis shim, and each hides a
// `new Function(scriptText)(window)` further along the same 460 KB line.
//
// So `accept` does NOT filter the returned hits. It is consulted per MATCH, and
// a rejected match makes the scan CONTINUE ALONG THE SAME LINE to the next one.
// Rejecting a site can therefore only ever reveal another site or leave the line
// unreported - never mask one. Filtering afterwards would have dropped both
// screenity files entirely and called that an improvement.
export function grep(files, re, filter = () => true, accept = null) {
  const hits = [];
  const push = (f, i, m) =>
    hits.push({ file: f.path, line: i + 1, match: m[0].slice(0, 120), text: f.lines[i].trim().slice(0, 160) });
  for (const f of files) {
    if (!filter(f)) continue;
    for (let i = 0; i < f.lines.length; i++) {
      if (!accept) {
        const rx = new RegExp(re.source, re.flags.replace("g", ""));
        const m = rx.exec(f.lines[i]);
        if (m) push(f, i, m);
        continue;
      }
      // `g` is required to advance lastIndex; the caller's regex may not have it.
      const rx = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
      let m;
      while ((m = rx.exec(f.lines[i])) !== null) {
        if (m[0].length === 0) { rx.lastIndex++; continue; } // a zero-width match never advances
        if (accept(m, f.lines[i])) { push(f, i, m); break; }
      }
    }
  }
  return hits;
}

// The same search, but over the whole file instead of line by line, still
// reporting the 1-indexed line the match STARTS on so the evidence is unchanged.
//
// WHY BOTH EXIST. grep() above is line-based, and for most rules that is right:
// the pattern and the evidence are one line. But an HTML attribute is not
// line-shaped. A long <script src="..."> wrapped across lines - which is exactly
// what a formatter does to it - was invisible to grep(), so two byte-identical
// pages differing ONLY in where the line breaks fell got different answers, and
// the silent one was the formatted one. That was in remote-code, the highest
// severity rule in the tool and the first trigger Google names for MV3.
//
// Use this for any pattern that can legally span a newline. Do NOT use it for
// patterns anchored to line structure - matching across lines is the whole
// point, and for a line-anchored rule that is a false positive waiting to happen.
export function grepAcross(files, re, filter = () => true) {
  const hits = [];
  for (const f of files) {
    if (!filter(f)) continue;
    const rx = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
    let m;
    while ((m = rx.exec(f.text)) !== null) {
      // Count the newlines before the match rather than searching the lines
      // array, so a match that spans lines is attributed to the line it opens on.
      const line = f.text.slice(0, m.index).split("\n").length;
      hits.push({
        file: f.path,
        line,
        match: m[0].replace(/\s+/g, " ").slice(0, 120),
        text: (f.lines[line - 1] || "").trim().slice(0, 160),
      });
      // A zero-length match would spin forever.
      if (m.index === rx.lastIndex) rx.lastIndex++;
    }
  }
  return hits;
}

export const isCode = (f) => [".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"].includes(f.ext);
export const isMarkup = (f) => [".html", ".htm"].includes(f.ext);

// Blank out comments, keeping every other byte where it was.
//
// WHY THIS LIVES HERE rather than in the one rule that first needed it: a
// commented-out call used to count as a call site, so an extension that DELETED
// its chrome.bookmarks code and left "// we used to call chrome.bookmarks.getTree
// here" behind was reported as USING bookmarks. That is Google's Purple Potassium
// case exactly. Two separate places ask that question - audit.mjs for the ledger
// and the unused-permissions rule for the verdict - and when they disagreed the
// tool contradicted itself. The drift between two copies has already been a bug
// here once (see declaredHosts), so this is shared.
//
// Comment bytes become SPACES rather than being removed, so offsets, line counts
// and therefore every reported line number are unchanged.
//
// THE FAIL-SAFE DIRECTION IS DELIBERATE. Blanking real code would invent an
// "unused" verdict, and that advice deletes a permission the extension needs -
// the expensive direction. So blanking happens ONLY from a comment opener found
// in normal state: strings and template literals are tracked and skipped, and an
// ambiguous slash is resolved toward "not a comment". A missed comment leaves a
// permission reading "used", which is a miss rather than a false accusation.
export function stripComments(text) {
  const out = text.split("");
  const n = text.length;
  let i = 0;
  let prev = ""; // last significant (non-space) character, for the regex/divide call
  const blank = (a, b) => {
    for (let k = a; k < b && k < n; k++) if (out[k] !== "\n") out[k] = " ";
  };

  while (i < n) {
    const c = text[i];
    const d = text[i + 1];

    if (c === "/" && d === "/") {
      let j = i + 2;
      while (j < n && text[j] !== "\n") j++;
      blank(i, j);
      i = j;
      continue;
    }
    if (c === "/" && d === "*") {
      let j = text.indexOf("*/", i + 2);
      j = j === -1 ? n : j + 2;
      blank(i, j);
      i = j;
      continue;
    }
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < n && text[j] !== c && text[j] !== "\n") j += text[j] === "\\" ? 2 : 1;
      i = j + 1;
      prev = c;
      continue;
    }
    if (c === "`") {
      let j = i + 1;
      while (j < n && text[j] !== "`") j += text[j] === "\\" ? 2 : 1;
      i = j + 1;
      prev = c;
      continue;
    }
    // A slash here is either division or a regex literal. Only the regex case
    // needs skipping, and guessing wrong that way merely means a comment inside
    // the span is missed - the safe direction. An unescaped // cannot appear
    // inside a regex literal anyway, because it would have closed it.
    if (c === "/" && (prev === "" || "=(,:[!&|?{};+-*%~^<>return".includes(prev))) {
      let j = i + 1;
      let cls = false;
      while (j < n && text[j] !== "\n") {
        const e = text[j];
        if (e === "\\") { j += 2; continue; }
        if (e === "[") cls = true;
        else if (e === "]") cls = false;
        else if (e === "/" && !cls) break;
        j++;
      }
      i = j + 1;
      prev = "/";
      continue;
    }
    if (!/\s/.test(c)) prev = c;
    i++;
  }
  return out.join("");
}

// The same files with comments blanked, computed once. Every call-site question
// is about code, not prose. Non-code files are passed through untouched.
export function codeView(files) {
  return files.map((f) => {
    if (!isCode(f)) return f;
    const text = stripComments(f.text);
    return { ...f, text, lines: text.split("\n") };
  });
}
