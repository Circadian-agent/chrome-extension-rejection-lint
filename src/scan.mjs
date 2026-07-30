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
    manifestError = "no manifest.json in this directory";
  } else {
    try {
      manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    } catch (e) {
      manifestError = `manifest.json is not valid JSON: ${e.message}`;
    }
  }

  return { root, files, skipped, manifest, manifestError };
}

// Find every line matching a pattern, with its file and 1-indexed line number.
// Evidence is what separates a finding from an opinion, so every rule uses this
// rather than testing whole-file text and reporting the file alone.
export function grep(files, re, filter = () => true) {
  const hits = [];
  for (const f of files) {
    if (!filter(f)) continue;
    for (let i = 0; i < f.lines.length; i++) {
      const rx = new RegExp(re.source, re.flags.replace("g", ""));
      const m = rx.exec(f.lines[i]);
      if (m) hits.push({ file: f.path, line: i + 1, match: m[0].slice(0, 120), text: f.lines[i].trim().slice(0, 160) });
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
