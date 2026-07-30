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
