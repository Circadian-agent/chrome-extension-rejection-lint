import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const CLI = fileURLToPath(new URL("../bin/webstore-lint.mjs", import.meta.url));
const CLEAN = fileURLToPath(new URL("./fixtures/clean", import.meta.url));
const run = (...args) => spawnSync(process.execPath, [CLI, ...args], {
  encoding: "utf8", timeout: 5000,
});

test("an explicit privacy check cannot silently disappear into another report mode", () => {
  for (const mode of ["--permissions", "--policy"]) {
    for (const args of [
      [CLEAN, mode, "--privacy-policy", "not-a-url"],
      ["--privacy-policy", "not-a-url", "--json", mode, CLEAN],
      [CLEAN, "--quiet", mode, "--privacy-policy", "not-a-url"],
    ]) {
      const result = run(...args);
      assert.equal(result.status, 2, args.join(" "));
      assert.equal(result.stdout, "", "an invalid combination must not emit a partial report");
      assert.match(result.stderr, /cannot be combined/);
      assert.ok(result.stderr.includes(mode));
      assert.match(result.stderr, /--privacy-policy/);
      assert.match(result.stderr, /No checks were run/);
      assert.match(result.stderr, /separately/);
    }
  }
});

test("policy data and permission audit modes cannot silently replace one another", () => {
  for (const args of [
    [CLEAN, "--permissions", "--policy"],
    ["--policy", "--permissions", CLEAN, "--json"],
    ["--policy", "--permissions", "--privacy-policy", "not-a-url", CLEAN],
  ]) {
    const result = run(...args);
    assert.equal(result.status, 2);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /--policy/);
    assert.match(result.stderr, /--permissions/);
  }
});

test("separate privacy and permission commands still produce their actual reports", () => {
  for (const args of [
    [CLEAN, "--privacy-policy", "not-a-url", "--json"],
    ["--privacy-policy", "not-a-url", CLEAN, "--json"],
  ]) {
    const result = run(...args);
    assert.equal(result.status, 1);
    assert.ok(JSON.parse(result.stdout).findings.some(f =>
      f.rule === "privacy-policy-url" && f.severity === "fail"));
  }
  const permissions = run(CLEAN, "--permissions", "--json");
  assert.equal(permissions.status, 0);
  assert.ok(Array.isArray(JSON.parse(permissions.stdout).ledger));
  const policy = run("--policy");
  assert.equal(policy.status, 0);
  assert.match(policy.stdout, /verified rejection categories/);
});

test("a supported privacy check fetches the page, while rejected modes make no request", () => {
  const url = "https://example.com/privacy";
  const runWithFetch = (...args) => spawnSync(process.execPath, ["--input-type=module", "--eval", `
    globalThis.fetch = async url => {
      process.stderr.write("FETCH " + url + "\\n");
      return new Response("Missing policy", { status: 404 });
    };
    process.argv = [process.execPath, ${JSON.stringify(CLI)}, ...${JSON.stringify(args)}];
    await import(${JSON.stringify(pathToFileURL(CLI).href)});
  `], { encoding: "utf8", timeout: 5000 });

  const checked = runWithFetch(CLEAN, "--privacy-policy", url, "--json");
  assert.equal(checked.status, 1);
  assert.equal(checked.stderr, `FETCH ${url}\n`);
  assert.ok(JSON.parse(checked.stdout).findings.some(f =>
    f.rule === "privacy-policy-url" && f.title.includes("404")));

  for (const mode of ["--permissions", "--policy"]) {
    const rejected = runWithFetch(CLEAN, mode, "--privacy-policy", url);
    assert.equal(rejected.status, 2);
    assert.doesNotMatch(rejected.stderr, /FETCH/);
    assert.equal(rejected.stdout, "");
  }
  const offline = runWithFetch(CLEAN, "--permissions");
  assert.equal(offline.status, 0);
  assert.equal(offline.stderr, "");
});

test("help documents separate modes without running checks", () => {
  const result = run("--help", "--policy", "--permissions", "--privacy-policy", "not-a-url");
  assert.equal(result.status, 0);
  assert.match(result.stdout, /separate commands/);
  assert.equal(result.stderr, "");
});
