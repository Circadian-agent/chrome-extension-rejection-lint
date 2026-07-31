// Tests for the framework build hint (src/scan.mjs buildHint, surfaced by lint()).
//
// WHY THIS EXISTS: 90 of 160 public extension repos cannot be linted as checked
// in, and 45 of those are a framework build whose manifest is generated. Telling
// those developers "no manifest.json in this directory" sends them looking for a
// file that does not exist anywhere yet.
//
// THE CONTROLS ARE THE POINT, and there are two kinds. First, the hint must not
// appear where it would be wrong - a directory that HAS a manifest, a path that
// is a file, a path that does not exist. Each of those already had a specific
// and correct message, and burying it under a build hint would be a regression
// dressed as a feature. Second, "no hint" is also what a buildHint that silently
// threw would produce, so every negative assertion here is paired with a
// positive one in the same fixture family: if detection were simply broken, the
// positive checks go red rather than the suite passing quietly.
//
// ORDERING IS TESTED ON PURPOSE. A wxt project also depends on vite and a plasmo
// project also has a package.json, so "wxt wins over vite" is a real assertion
// about the FRAMEWORKS list order and not a tautology - reverse the list and it
// fails.

import { buildHint, scan } from "../src/scan.mjs";
import { lint } from "../src/lint.mjs";
import { join } from "node:path";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";

let pass = 0, fail = 0;
const check = (name, cond, extra = "") => {
  if (cond) { pass++; }
  else { fail++; console.log(`  FAIL  ${name}${extra ? `\n        ${extra}` : ""}`); }
};

// Build a throwaway project directory. `pkg` is written only when given, so the
// "no package.json at all" case is reachable.
function project({ pkg, files = {}, dirs = [] } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "wsl-hint-"));
  if (pkg) writeFileSync(join(dir, "package.json"), JSON.stringify(pkg));
  for (const d of dirs) mkdirSync(join(dir, d), { recursive: true });
  for (const [p, text] of Object.entries(files)) {
    mkdirSync(join(dir, p, ".."), { recursive: true });
    writeFileSync(join(dir, p), text);
  }
  return dir;
}

console.log("--- framework detection");

const wxtByFile = project({ files: { "wxt.config.ts": "export default {}" } });
const h1 = buildHint(wxtByFile);
check("wxt detected from wxt.config.ts", /wxt project/.test(h1 || ""), h1);
check("wxt hint names the real output directory", /\.output\/chrome-mv3/.test(h1 || ""), h1);
check("wxt hint names the build command", /npx wxt build/.test(h1 || ""), h1);

const wxtByDep = project({ pkg: { devDependencies: { wxt: "^0.19.0" } } });
check("wxt detected from a devDependency alone", /wxt project/.test(buildHint(wxtByDep) || ""));

const plasmo = project({ pkg: { dependencies: { plasmo: "^0.88.0" } } });
const h2 = buildHint(plasmo);
check("Plasmo detected", /Plasmo project/.test(h2 || ""), h2);
// prod, not dev: dev is commoner in the corpus but prod is what gets submitted.
check("Plasmo hint names the PROD output directory", /build\/chrome-mv3-prod/.test(h2 || ""), h2);
check("Plasmo hint does not send you to the dev build", !/chrome-mv3-dev/.test(h2 || ""), h2);

const crxjs = project({ pkg: { devDependencies: { "@crxjs/vite-plugin": "^2.0.0" } } });
check("CRXJS detected", /CRXJS project/.test(buildHint(crxjs) || ""));
check("CRXJS hint names dist", /webstore-lint dist/.test(buildHint(crxjs) || ""));

console.log("\n--- the generic bundlers name no directory, deliberately");

const webpack = project({ pkg: { devDependencies: { webpack: "^5.0.0" } } });
const h3 = buildHint(webpack);
check("bare webpack is still recognised", /webpack build/.test(h3 || ""), h3);
// Guessing `dist` for an arbitrary webpack config is the same misdiagnosis one
// level down, so the hint must ask rather than assert.
check("bare webpack does NOT invent an output path", !/webstore-lint (dist|build|\.output)/.test(h3 || ""), h3);
check("bare webpack points at 'your build output directory'", /build output directory/.test(h3 || ""), h3);

console.log("\n--- ordering: the specific framework wins over the bundler it uses");

const wxtAndVite = project({ pkg: { devDependencies: { wxt: "^0.19.0", vite: "^5.0.0" } } });
check("a wxt project that also has vite reports wxt", /wxt project/.test(buildHint(wxtAndVite) || ""));
const plasmoAndWebpack = project({ pkg: { dependencies: { plasmo: "^0.88.0" }, devDependencies: { webpack: "^5.0.0" } } });
check("a plasmo project that also has webpack reports Plasmo", /Plasmo project/.test(buildHint(plasmoAndWebpack) || ""));

console.log("\n--- already built: say where it landed, do not ask for another build");

const built = project({
  pkg: { devDependencies: { wxt: "^0.19.0" } },
  files: { ".output/chrome-mv3/manifest.json": "{}" },
});
const h4 = buildHint(built);
check("an already-built wxt project is recognised as built", /already built it/.test(h4 || ""), h4);
check("the built hint points straight at the output", /webstore-lint \.output\/chrome-mv3/.test(h4 || ""), h4);
check("the built hint does not tell you to build again", !/npx wxt build/.test(h4 || ""), h4);

// An EMPTY output directory must not count as built. This is the assertion that
// separates "the manifest is there" from "the folder is there", and it is the
// one that would let us send somebody to an empty directory.
const emptyOut = project({ pkg: { devDependencies: { wxt: "^0.19.0" } }, dirs: [".output/chrome-mv3"] });
const h5 = buildHint(emptyOut);
check("an EMPTY output directory does not count as built", !/already built/.test(h5 || ""), h5);
check("and it still tells you to run the build", /npx wxt build/.test(h5 || ""), h5);

console.log("\n--- CONTROLS: where the hint must not appear at all");

const plain = project({});
check("a bare directory with nothing in it gets no hint", buildHint(plain) === null);

const notNode = project({ files: { "README.md": "hello" } });
check("a non-node project gets no hint", buildHint(notNode) === null);

const unrelatedNode = project({ pkg: { dependencies: { express: "^4.0.0" } } });
check("a node project with no bundler gets no hint", buildHint(unrelatedNode) === null);

// A package.json that does not parse must not crash: a stack trace here would
// replace a usable error message with a broken tool.
const badPkg = project({});
writeFileSync(join(badPkg, "package.json"), "{ this is not json");
let threw = false;
let h6 = null;
try { h6 = buildHint(badPkg); } catch { threw = true; }
check("an invalid package.json does not throw", !threw);
check("an invalid package.json yields no hint", h6 === null);

console.log("\n--- CONTROLS through the real call site, which is what ships");

// THE REACHABILITY CONTROL. buildHint in isolation happily fires on a repo that
// has BOTH a manifest and a webpack config; what makes that harmless is that
// scan() only calls it when there is no manifest. Assert the guard, not the
// function.
const hasManifestAndWebpack = project({
  pkg: { devDependencies: { webpack: "^5.0.0" } },
  files: { "manifest.json": JSON.stringify({ manifest_version: 3, name: "x", version: "1.0" }) },
});
check("buildHint alone WOULD fire on a manifest+webpack project", buildHint(hasManifestAndWebpack) !== null);
check("but scan() never asks for it when a manifest exists", scan(hasManifestAndWebpack).manifestHint == null);

// A path that is a file, and a path that does not exist, each already had a
// precise message. The hint must not displace either.
const fileTarget = join(hasManifestAndWebpack, "manifest.json");
const ctxFile = scan(fileTarget);
check("pointing at manifest.json keeps its own message", /is the manifest itself/.test(ctxFile.manifestError || ""), ctxFile.manifestError);
check("pointing at manifest.json produces no build hint", ctxFile.manifestHint == null);

const ctxMissing = scan(join(plain, "nope"));
check("a nonexistent path keeps its own message", /there is nothing at/.test(ctxMissing.manifestError || ""), ctxMissing.manifestError);
check("a nonexistent path produces no build hint", ctxMissing.manifestHint == null);

// THE TWO ASSERTIONS ABOVE PASS FOR TWO REASONS AT ONCE, and mutating the guard
// out of scan.mjs proved it: buildHint already returns null for a file and for a
// missing path, so "no hint" is satisfied whether or not the call site checks
// isDirectory(). An assertion satisfied by the failure it is meant to catch is
// worth nothing, so the mechanism that actually protects those cases is asserted
// here directly, against buildHint itself.
check("buildHint on a FILE path returns null on its own",
  buildHint(join(hasManifestAndWebpack, "manifest.json")) === null);
check("buildHint on a MISSING path returns null on its own",
  buildHint(join(plain, "nope")) === null);
// ...and the positive control that keeps the two above from being vacuous: the
// same function, given the real directory, does produce a hint.
check("CONTROL: buildHint on the containing directory DOES fire",
  buildHint(hasManifestAndWebpack) !== null);

console.log("\n--- the hint reaches the reported finding, and severity is unchanged");

const r = lint(wxtByFile);
const f = r.findings.find((x) => x.rule === "manifest");
check("the manifest finding still exists", !!f);
check("its detail is the build hint", /wxt project/.test(f?.detail || ""), f?.detail);
// Nothing was checked, so a green result would be a lie whichever message prints.
check("severity is still fail", f?.severity === "fail");
check("counts still report one failure", r.counts.fail === 1);

// Positive control on the fallback: the generic sentence must survive for the
// cases it is right for, or this change quietly deletes it.
const rPlain = lint(plain);
const fPlain = rPlain.findings.find((x) => x.rule === "manifest");
check("a directory with no framework keeps the generic detail",
  /Point webstore-lint at the directory holding manifest\.json/.test(fPlain?.detail || ""), fPlain?.detail);

console.log(`\nbuild hint: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
console.log("build hint: all checks passed");
