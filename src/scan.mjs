// Read an unpacked extension directory into memory, once, so every rule works
// from the same picture instead of walking the tree again.
//
// WHAT IS DELIBERATELY NOT READ: node_modules, .git, and anything over 2 MB.
// A rule that greps a 40 MB bundled vendor file produces a "finding" in code the
// developer did not write and cannot fix, which trains people to ignore output.
// Skipped files are RECORDED and reported, because a silent skip is how a linter
// says "clean" about a directory it never looked at.

import { readdirSync, readFileSync, statSync, existsSync, openSync, readSync, closeSync } from "node:fs";
import { join, relative, extname } from "node:path";
import { StringDecoder } from "node:string_decoder";

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
  // Files too big to hold in memory, kept as a work list rather than only as an
  // apology. `skipped` stays exactly as it was, because every other rule really
  // did not read these and its honesty warning has to keep counting them; a rule
  // that DOES stream one subtracts it from that list itself.
  const oversized = [];

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
        oversized.push({ path: rel, abs: full, ext, size: st.size });
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

  return { root, files, skipped, oversized, manifest: localized, manifestRaw: manifest, i18nUnresolved: unresolved, manifestError };
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
// THERE IS ONE IMPLEMENTATION AND IT IS THE RESUMABLE ONE, on purpose. The
// streaming scan (grepLarge, below) has to blank comments in a file it never
// holds whole, and the obvious way to get that is a second copy of this state
// machine that walks a chunk. The drift between two copies of a shared rule has
// already been a bug in this file once (see declaredHosts in rules.mjs), and
// this one decides whether a FAIL-severity site is visible - so instead
// stripComments() is a single call to the chunk stepper with the whole file as
// one chunk, and test/lint.test.mjs asserts the two paths AGREE byte for byte
// on real bundles at several chunk sizes.
export const initialCommentState = () => ({ mode: "code", quote: '"', cls: false, prev: "" });

// Blank the comments in ONE chunk, carrying the parse state across the seam.
//
// `atEof` false means another chunk is coming, and then this NEVER consumes the
// final character of the chunk: every decision here needs at most one character
// of lookahead (`//` against `/*`, `*/` closing a block, a backslash escaping
// the next byte), and a seam through the middle of any of those pairs decides it
// wrong. The unconsumed tail comes back as `held` and the caller prepends it to
// the next chunk. Holding one character uniformly is cheaper to reason about
// than three special cases, and it is why there is no `pendingSlash` in the
// state object.
//
// Returns { out, held, state }: `out` is the blanked text for the part actually
// consumed, so out.length + held.length === text.length and every byte offset in
// `out` is still the offset it had in the file.
export function stripCommentsChunk(text, state = initialCommentState(), { atEof = true } = {}) {
  const n = text.length;
  const out = text.split("");
  let { mode, quote, cls, prev } = state;
  // Nothing past `stop` is consumed, so every inner scan is bounded by it too.
  // Bounding only the outer loop would let a backslash skip step over the held
  // character, which is exactly the seam this is protecting.
  const stop = atEof ? n : Math.max(0, n - 1);
  const blank = (a, b) => {
    for (let k = a; k < b && k < n; k++) if (out[k] !== "\n") out[k] = " ";
  };

  let i = 0;
  while (i < stop) {
    if (mode === "line") {
      let j = i;
      while (j < stop && text[j] !== "\n") j++;
      blank(i, j);
      i = j;
      if (j < stop) mode = "code"; // the newline itself is left for code mode
      continue;
    }
    if (mode === "block") {
      const k = text.indexOf("*/", i);
      if (k !== -1 && k + 2 <= stop) { blank(i, k + 2); i = k + 2; mode = "code"; continue; }
      // Not closed inside this chunk. A trailing `*` has to be HELD, not
      // blanked: blanking it destroys the first half of a `*/` that straddles
      // the seam, and the next chunk then searches for a closer whose asterisk
      // no longer exists - so the block comment swallows the rest of the file.
      // Same failure as the backslash below, and it is why holding one character
      // is not enough on its own.
      let end = stop;
      if (!atEof && end > i && text[end - 1] === "*") end--;
      blank(i, end);
      i = end;
      break;
    }
    if (mode === "str" || mode === "tpl") {
      // A single-quoted or double-quoted string bails at a newline; a template
      // literal does not. Both are STEPPED OVER, never blanked - see the header
      // above and T-0416 for why blanking them is refused.
      const ends = mode === "str" ? (ch) => ch === quote || ch === "\n" : (ch) => ch === "`";
      let j = i;
      // A BACKSLASH IS TWO CHARACTERS AND THE SEAM MUST NOT FALL BETWEEN THEM -
      // handing the escaped character to the next call as an ordinary one ends
      // the string early when it is the closing quote (`\"`, which every
      // embedded JSON blob is full of). No guard is needed for it HERE, and that
      // is a measured claim rather than an assumption: the skip may run j past
      // `stop`, and consuming exactly as far as j - rather than to stop - takes
      // the escaped character with it, which is correct. A version WITH an
      // explicit guard was tried and proved an equivalent mutant, agreeing at
      // every chunk size from 1 upward on the seam fixtures and byte for byte
      // over 36 MB of real bundles. It was removed rather than kept as comfort:
      // a branch that cannot change an answer cannot be tested, and a comment
      // claiming it protects something would be false.
      while (j < stop) {
        if (text[j] === "\\") { j += 2; continue; }
        if (ends(text[j])) break;
        j++;
      }
      if (j < stop && ends(text[j])) { prev = mode === "str" ? quote : "`"; i = j + 1; mode = "code"; continue; }
      i = j;
      break; // holding from j: nothing after it can be decided without the next chunk

    }
    if (mode === "re") {
      let j = i;
      let done = false;
      while (j < stop) {
        const e = text[j];
        if (e === "\\") { j += 2; continue; } // consuming to j, not to stop, carries the escape
        if (e === "\n") break;
        if (e === "[") cls = true;
        else if (e === "]") cls = false;
        else if (e === "/" && !cls) { done = true; break; }
        j++;
      }
      if (done || (j < stop && text[j] === "\n")) { i = j + 1; mode = "code"; prev = "/"; continue; }
      i = j;
      break; // nothing after j can be decided without the next chunk

    }

    const c = text[i];
    const d = text[i + 1];

    if (c === "/" && d === "/") { blank(i, i + 2); i += 2; mode = "line"; continue; }
    if (c === "/" && d === "*") { blank(i, i + 2); i += 2; mode = "block"; continue; }
    if (c === '"' || c === "'") { quote = c; i++; mode = "str"; continue; }
    if (c === "`") { i++; mode = "tpl"; continue; }
    // A slash here is either division or a regex literal. Only the regex case
    // needs skipping, and guessing wrong that way merely means a comment inside
    // the span is missed - the safe direction. An unescaped // cannot appear
    // inside a regex literal anyway, because it would have closed it.
    if (c === "/" && (prev === "" || "=(,:[!&|?{};+-*%~^<>return".includes(prev))) {
      i++;
      cls = false;
      mode = "re";
      continue;
    }
    if (!/\s/.test(c)) prev = c;
    i++;
  }

  return {
    out: out.slice(0, i).join(""),
    held: text.slice(i),
    state: { mode, quote, cls, prev },
  };
}

// Blank out comments, keeping every other byte where it was.
export function stripComments(text) {
  return stripCommentsChunk(text, initialCommentState(), { atEof: true }).out;
}

// Search a file that is too large to hold in memory, in overlapping windows.
//
// WHY THIS EXISTS. scan() does not read a file over 2 MB, and the remote-code
// rule then went silent about it - which a developer reads as "nothing there",
// on the one rule Google enforces first. Measured on 82 shipped release
// packages: 23 skip a code file for size and THREE of them hide a real site in
// one, including `new Function('return (' + source + ');')()` in a 4.0 MB
// content script.
//
// RAISING THE LIMIT IS NOT THE FIX and was rejected: page-assist ships an 8.3 MB
// chunk, so a bigger number only moves the cliff, and it costs that memory on
// every scan of every package. This reads a fixed window instead, so a 40 MB
// file costs the same as a 3 MB one.
//
// THE OVERLAP IS THE WHOLE CORRECTNESS ARGUMENT. grepAcross deliberately matches
// across newlines, so a window boundary can fall through the middle of a match.
// Every window therefore keeps the last OVERLAP characters of the previous one,
// and hits are deduplicated by their ABSOLUTE offset in the file - not by their
// offset in the window, which changes every time the window slides. OVERLAP must
// stay comfortably longer than the longest pattern any caller passes.
const WINDOW = 1 << 20; // 1 MB read
const OVERLAP = 8192;

// A match must be reported at a line number and with text a developer can
// recognise. Neither is free here: the file is never whole, and on a minified
// bundle "the line" is millions of characters. So the line is counted from the
// newlines actually passed over, and the evidence is a SNIPPET around the match
// rather than the line - which is what grep() would have produced anyway once it
// truncated a 460 KB line to 160 characters.
// The windowing itself, separated from what any one caller does with it, for the
// same reason stripComments has exactly one implementation: two rules now read
// these files and a second copy of the slide-and-overlap arithmetic is a bug
// waiting to be fixed in one place only.
//
// Yields { raw, view, base, lineBase } per window. `raw` is the original text,
// `view` is the same span with comments blanked when `code` is true, and the two
// are always the same length - stripComments preserves offsets, which is what
// lets a match found in `view` be quoted from `raw` and counted in lines.
export function* largeWindows(f, { code = false } = {}) {
  let fd;
  try { fd = openSync(f.abs, "r"); } catch { return; }
  const decoder = new StringDecoder("utf8");
  const buf = Buffer.allocUnsafe(WINDOW);
  let raw = "";        // window of original text
  let view = "";       // same window, comments blanked when code is true
  let base = 0;        // absolute offset of raw[0]
  let lineBase = 1;    // 1-indexed line number of raw[0]
  let heldRaw = "";    // characters stripCommentsChunk could not decide yet
  let state = initialCommentState();
  try {
    for (;;) {
      const n = readSync(fd, buf, 0, WINDOW, null);
      const atEof = n === 0;
      const chunk = heldRaw + (atEof ? decoder.end() : decoder.write(buf.subarray(0, n)));
      let add = chunk;
      if (code) {
        const r = stripCommentsChunk(chunk, state, { atEof });
        state = r.state;
        heldRaw = r.held;
        add = r.out;
        raw += chunk.slice(0, r.out.length);
      } else {
        heldRaw = "";
        raw += chunk;
      }
      view += add;
      yield { raw, view, base, lineBase };
      if (atEof) break;
      // Slide, keeping the overlap. Everything dropped is accounted for in base
      // and lineBase so absolute offsets and line numbers keep counting.
      if (view.length > OVERLAP) {
        const drop = view.length - OVERLAP;
        lineBase += countNewlines(raw, 0, drop);
        base += drop;
        view = view.slice(drop);
        raw = raw.slice(drop);
      }
    }
  } finally {
    closeSync(fd);
  }
}

export function grepLarge(oversized, re, { filter = () => true, code = false, accept = null, maxPerFile = 25 } = {}) {
  const hits = [];
  for (const f of oversized || []) {
    if (!filter(f)) continue;
    const emitted = new Set();
    let truncated = false;

    const search = ({ raw, view, base, lineBase }) => {
      const rx = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
      let m;
      while ((m = rx.exec(view)) !== null) {
        if (m[0].length === 0) { rx.lastIndex++; continue; }
        const abs = base + m.index;
        if (emitted.has(abs)) continue;
        // `accept` is consulted per MATCH and a rejection CONTINUES along the
        // window, exactly as in grep(): rejecting a site can only ever reveal
        // another one, never mask it.
        if (accept && !accept(m, view)) continue;
        emitted.add(abs);
        if (emitted.size > maxPerFile) { truncated = true; return; }
        const line = lineBase + countNewlines(raw, 0, m.index);
        const from = Math.max(0, m.index - 40);
        hits.push({
          file: f.path,
          line,
          match: m[0].replace(/\s+/g, " ").slice(0, 120),
          text: raw.slice(from, from + 200).replace(/\s+/g, " ").trim().slice(0, 160),
        });
      }
    };

    for (const w of largeWindows(f, { code })) {
      search(w);
      if (truncated) break;
    }

    if (truncated) {
      hits.push({
        file: f.path,
        line: 1,
        match: "",
        text: `more than ${maxPerFile} sites in this file; the rest are not listed`,
      });
    }
  }
  return hits;
}

const countNewlines = (s, from, to) => {
  let c = 0;
  for (let i = from; i < to; i++) if (s.charCodeAt(i) === 10) c++;
  return c;
};

// The same files with comments blanked, computed once. Every call-site question
// is about code, not prose. Non-code files are passed through untouched.
export function codeView(files) {
  return files.map((f) => {
    if (!isCode(f)) return f;
    const text = stripComments(f.text);
    return { ...f, text, lines: text.split("\n") };
  });
}
