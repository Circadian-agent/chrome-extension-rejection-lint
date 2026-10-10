import { test } from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { lint, auditPermissions } from "../src/lint.mjs";

const fixture = fileURLToPath(new URL("./fixtures/clean", import.meta.url));
const cli = fileURLToPath(new URL("../bin/webstore-lint.mjs", import.meta.url));
const action = fileURLToPath(new URL("../action/report.mjs", import.meta.url));
function setup(t) {
  const temp = mkdtempSync(join(tmpdir(), "webstore-links-"));
  t.after(() => rmSync(temp, { recursive: true, force: true }));
  const root = join(temp, "extension");
  cpSync(fixture, root, { recursive: true });
  return { temp, root };
}
const coverage = result => result.findings.find(f => f.rule === "symbolic-links");

test("linked code is disclosed without reading its target; a copied target is checked", t => {
  const { temp, root } = setup(t);
  const target = join(temp, "outside.js");
  writeFileSync(target, "eval(remoteSource);\n");
  symlinkSync(target, join(root, "loader.js"));
  const result = lint(root);
  assert.equal(result.counts.fail, 0);
  assert.equal(coverage(result)?.severity, "warn");
  assert.equal(coverage(result)?.citation, null);
  assert.ok(result.skipped.some(s => s.path === "loader.js" && s.kind === "symlink"));
  assert.ok(!result.files.some(f => f.path === "loader.js"));
  assert.ok(!JSON.stringify(result).includes("eval(remoteSource)"));
  rmSync(join(root, "loader.js"));
  cpSync(target, join(root, "loader.js"));
  const copied = lint(root);
  assert.equal(coverage(copied), undefined);
  assert.ok(copied.findings.some(f => f.rule === "remote-code" && f.severity === "fail"));
});

test("linked directory cannot turn unseen permission calls into a policy failure", t => {
  const { temp, root } = setup(t);
  const target = join(temp, "scripts");
  mkdirSync(target);
  writeFileSync(join(target, "worker.js"), "chrome.storage.local.get('settings');\n");
  symlinkSync(target, join(root, "linked"), "dir");
  writeFileSync(join(root, "content.js"), "import './linked/worker.js';\n");
  const manifest = JSON.parse(readFileSync(join(root, "manifest.json")));
  manifest.background = { service_worker: "linked/worker.js" };
  writeFileSync(join(root, "manifest.json"), JSON.stringify(manifest));
  const result = lint(root);
  assert.ok(coverage(result));
  assert.equal(result.findings.find(f => f.rule === "unused-permissions")?.severity, "warn");
  assert.ok(!result.findings.some(f => f.rule === "missing-declared-files"));
  const audit = auditPermissions(root).audit;
  assert.ok(audit.confidence.skipped.some(s => s.path === "linked"));
  assert.match(audit.confidence.caveat, /incomplete/);
});

test("linked locale is unread, not evidence that its messages are missing", t => {
  const { temp, root } = setup(t);
  const locales = join(temp, "locales");
  mkdirSync(join(locales, "en"), { recursive: true });
  writeFileSync(join(locales, "en", "messages.json"), JSON.stringify({ title: { message: "Reading Time" } }));
  symlinkSync(locales, join(root, "_locales"), "dir");
  const manifest = JSON.parse(readFileSync(join(root, "manifest.json")));
  manifest.name = "__MSG_title__";
  manifest.default_locale = "en";
  writeFileSync(join(root, "manifest.json"), JSON.stringify(manifest));
  const result = lint(root);
  assert.ok(coverage(result));
  assert.equal(result.manifest.name, "__MSG_title__");
  assert.deepEqual(result.i18nUnresolved, []);
});

test("dangling and cyclic links are disclosed without traversal or a hang", t => {
  const { root } = setup(t);
  symlinkSync("missing.js", join(root, "dangling.js"));
  symlinkSync(".", join(root, "cycle"), "dir");
  const run = spawnSync(process.execPath, [cli, root, "--json"], { encoding: "utf8", timeout: 5000 });
  assert.equal(run.status, 0, run.stderr);
  const result = JSON.parse(run.stdout);
  assert.deepEqual(result.skipped.filter(s => s.kind === "symlink").map(s => s.path).sort(), ["cycle", "dangling.js"]);
  assert.ok(coverage(result));
});

test("a linked manifest is unreadable and its external contents are not loaded", t => {
  const { temp, root } = setup(t);
  const target = join(temp, "external-manifest.json");
  writeFileSync(target, JSON.stringify({ manifest_version: 3, name: "EXTERNAL_CONTENT_MARKER" }));
  rmSync(join(root, "manifest.json"));
  symlinkSync(target, join(root, "manifest.json"));
  const result = lint(root);
  assert.match(result.manifestError || "", /symbolic link/);
  assert.ok(!JSON.stringify(result).includes("EXTERNAL_CONTENT_MARKER"));
  const run = spawnSync(process.execPath, [action], {
    env: { ...process.env, WSL_PATH: root, WSL_FAIL_ON: "never" }, encoding: "utf8", timeout: 5000,
  });
  assert.equal(run.status, 1, run.stderr);
});

test("CLI and Action expose skipped links and respect the warning threshold", t => {
  const { root, temp } = setup(t);
  symlinkSync("missing", join(root, "linked"));
  const text = spawnSync(process.execPath, [cli, root], { encoding: "utf8", timeout: 5000 });
  assert.equal(text.status, 0);
  assert.match(text.stdout, /symbolic link/);
  assert.match(text.stdout, /not read: linked/);
  for (const [failOn, expected] of [["warn", 1], ["fail", 0], ["never", 0]]) {
    const summary = join(temp, `summary-${failOn}.md`);
    const run = spawnSync(process.execPath, [action], {
      env: { ...process.env, WSL_PATH: root, WSL_FAIL_ON: failOn, GITHUB_STEP_SUMMARY: summary },
      encoding: "utf8", timeout: 5000,
    });
    assert.equal(run.status, expected, run.stderr);
    assert.match(readFileSync(summary, "utf8"), /symbolic link/);
    assert.doesNotMatch(readFileSync(summary, "utf8"), /No findings/);
  }
});

test("ordinary packages and an explicitly selected linked root still scan normally", t => {
  const { temp, root } = setup(t);
  const alias = join(temp, "selected-root");
  symlinkSync(root, alias, "dir");
  for (const path of [root, alias]) {
    const result = lint(path);
    assert.deepEqual(result.counts, { fail: 0, warn: 0, info: 0 });
    assert.deepEqual(result.skipped, []);
  }
});
