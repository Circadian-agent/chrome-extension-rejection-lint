import { test } from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { lint } from "../src/lint.mjs";

const fixture = fileURLToPath(new URL("./fixtures/clean", import.meta.url));
const cli = fileURLToPath(new URL("../bin/webstore-lint.mjs", import.meta.url));
const action = fileURLToPath(new URL("../action/report.mjs", import.meta.url));
function setup(t, scripts) {
  const root = mkdtempSync(join(tmpdir(), "webstore-content-types-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  cpSync(fixture, root, { recursive: true });
  const manifest = JSON.parse(readFileSync(join(root, "manifest.json")));
  delete manifest.permissions;
  manifest.content_scripts = scripts.map(s => ({ matches: ["https://example.com/*"], ...s }));
  writeFileSync(join(root, "manifest.json"), JSON.stringify(manifest));
  return root;
}
const typeFinding = result => result.findings.find(f => f.rule === "content-script-file-types");

test("existing unsupported content scripts report the load blocker without a policy citation", t => {
  for (const name of ["content.txt", "content.json", "content.cjs", "content.ts", "content.jsx", "content", "content.png"]) {
    const root = setup(t, [{ js: [name] }]);
    writeFileSync(join(root, name), "document.title = 'loaded';\n");
    const result = lint(root);
    const finding = typeFinding(result);
    assert.equal(finding?.severity, "warn", name);
    assert.equal(finding.citation, null);
    assert.match(finding.detail, /entire content_scripts entry/);
    assert.ok(finding.evidence.some(e => e.text.includes(name)));
    assert.ok(!result.findings.some(f => f.rule === "missing-declared-files"), name);
  }
});

test("invalid stylesheet type identifies the affected entry even beside valid JavaScript", t => {
  const root = setup(t, [{ js: ["content.js"], css: ["style.txt"] }, { js: ["second.js"] }]);
  writeFileSync(join(root, "style.txt"), "body { color: red; }\n");
  writeFileSync(join(root, "second.js"), "document.title = 'second';\n");
  const result = lint(root);
  const finding = typeFinding(result);
  assert.equal(finding?.severity, "warn");
  assert.ok(finding.evidence.some(e => e.text === "content_scripts[0].css: style.txt"));
  assert.equal(finding.evidence.length, 1);
});

test("Chromium-supported JS and legacy SCSS suffixes are accepted without missing-file claims", t => {
  const root = setup(t, [{ js: ["content.js", "module.mjs", "custom.user.js", "UPPER.JS"], css: ["style.css", "legacy.scss", "UPPER.SCSS"] }]);
  for (const name of ["module.mjs", "custom.user.js", "UPPER.JS"]) writeFileSync(join(root, name), "document.title = 'loaded';\n");
  for (const name of ["style.css", "legacy.scss", "UPPER.SCSS"]) writeFileSync(join(root, name), "body { color: red; }\n");
  const result = lint(root);
  assert.equal(typeFinding(result), undefined);
  assert.ok(!result.findings.some(f => f.rule === "missing-declared-files"));
  assert.deepEqual(result.counts, { fail: 0, warn: 0, info: 0 });
});

test("permission absence is uncertain while a content script entry cannot load", t => {
  const root = setup(t, [{ js: ["content.txt"] }]);
  rmSync(join(root, "content.js"));
  writeFileSync(join(root, "content.txt"), "chrome.storage.local.get('settings');\n");
  const manifest = JSON.parse(readFileSync(join(root, "manifest.json")));
  manifest.permissions = ["storage"];
  writeFileSync(join(root, "manifest.json"), JSON.stringify(manifest));
  const result = lint(root);
  assert.equal(typeFinding(result)?.severity, "warn");
  const unused = result.findings.find(f => f.rule === "unused-permissions");
  assert.equal(unused?.severity, "warn");
  assert.match(unused.detail, /file type/);
});

test("ordinary source files and background workers are outside this content-script check", t => {
  const root = setup(t, [{ js: ["content.js"] }]);
  writeFileSync(join(root, "source.ts"), "const ready = true;\n");
  const manifest = JSON.parse(readFileSync(join(root, "manifest.json")));
  manifest.background = { service_worker: "source.ts" };
  writeFileSync(join(root, "manifest.json"), JSON.stringify(manifest));
  assert.equal(typeFinding(lint(root)), undefined);
});

test("valid but absent content-script resources still report missing files", t => {
  const root = setup(t, [{ js: ["absent.js"], css: ["absent.scss"] }]);
  const result = lint(root);
  assert.equal(typeFinding(result), undefined);
  const missing = result.findings.find(f => f.rule === "missing-declared-files");
  assert.ok(missing?.evidence.some(e => e.text.includes("absent.js")));
  assert.ok(missing?.evidence.some(e => e.text.includes("absent.scss")));
});

test("CLI and Action expose the loading warning and preserve threshold behavior", t => {
  const root = setup(t, [{ js: ["content.txt"] }]);
  writeFileSync(join(root, "content.txt"), "document.title = 'loaded';\n");
  const text = spawnSync(process.execPath, [cli, root], { encoding: "utf8", timeout: 5000 });
  assert.equal(text.status, 0, text.stderr);
  assert.match(text.stdout, /unsupported file type/);
  for (const [failOn, status] of [["warn", 1], ["fail", 0], ["never", 0]]) {
    const summary = join(root, `summary-${failOn}.md`);
    const run = spawnSync(process.execPath, [action], {
      env: { ...process.env, WSL_PATH: root, WSL_FAIL_ON: failOn, GITHUB_STEP_SUMMARY: summary },
      encoding: "utf8", timeout: 5000,
    });
    assert.equal(run.status, status, run.stderr);
    assert.match(readFileSync(summary, "utf8"), /unsupported file type/);
  }
});
