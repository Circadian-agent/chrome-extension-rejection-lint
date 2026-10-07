import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, openSync, closeSync, readFileSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../bin/webstore-lint.mjs", import.meta.url));

test("permission reports survive a slow pipe, including all confidence caveats", () => {
  const dir = mkdtempSync(join(tmpdir(), "wsl-permission-output-"));
  try {
    writeFileSync(join(dir, "manifest.json"), JSON.stringify({
      manifest_version: 3, name: "Bundled extension", version: "1.0",
      permissions: ["storage"],
    }));
    // Many bundled chunks make the confidence warnings exceed pipe buffers.
    const chunks = 2500;
    for (let i = 0; i < chunks; i++) {
      const name = `chunk-${String(i).padStart(4, "0")}-${"a".repeat(70)}.js`;
      writeFileSync(join(dir, name), `const value="${"x".repeat(2100)}";`);
    }
    for (const flags of [["--permissions", "--json"], ["--permissions"]]) {
      // File writes are synchronous, giving a complete reference for the pipe.
      const output = join(dir, "report.txt");
      const fd = openSync(output, "w");
      let file;
      try {
        file = spawnSync(process.execPath, [CLI, dir, ...flags], {
          stdio: ["ignore", fd, "pipe"], timeout: 15000,
        });
      } finally { closeSync(fd); }
      assert.equal(file.status, 0);
      const expected = readFileSync(output, "utf8");
      assert.ok(Buffer.byteLength(expected) > 300000);

      // Pass paths as arguments, never interpolate them into shell code.
      // A slow downstream consumer exposes forced-exit data loss that a fast
      // spawnSync reader can hide, especially for the many small text writes.
      const piped = spawnSync("bash", ["-o", "pipefail", "-c",
        '"$1" "$2" "$3" "${@:4}" | "$1" -e \'setTimeout(() => process.stdin.pipe(process.stdout), 1500)\'',
        "wsl-test", process.execPath, CLI, dir, ...flags,
      ], { encoding: "utf8", maxBuffer: 10 * 1024 * 1024, timeout: 15000 });
      assert.equal(piped.status, 0, piped.stderr);
      assert.equal(piped.stdout.length, expected.length, flags.join(" "));
      assert.equal(piped.stdout, expected, flags.join(" "));
      if (flags.includes("--json")) {
        const report = JSON.parse(piped.stdout);
        assert.equal(report.confidence.minified.length, chunks);
        assert.match(report.confidence.caveat, /must be checked against the original source/);
        assert.equal(report.ledger[0].permission, "storage");
      } else {
        assert.equal((piped.stdout.match(/minified, so call sites are unreliable:/g) || []).length, chunks);
        assert.doesNotMatch(piped.stdout, /failing, .* needing your judgement/);
      }
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("permission JSON keeps its own shape and rejects an unreadable extension", () => {
  const clean = fileURLToPath(new URL("./fixtures/clean", import.meta.url));
  const result = spawnSync(process.execPath, [CLI, clean, "--permissions", "--json"], { encoding: "utf8" });
  assert.equal(result.status, 0);
  assert.ok(Array.isArray(JSON.parse(result.stdout).ledger));
  const missing = spawnSync(process.execPath, [CLI, join(clean, "missing"), "--permissions", "--json"], { encoding: "utf8" });
  assert.equal(missing.status, 1);
  assert.equal(missing.stdout, "");
  assert.match(missing.stderr, /there is nothing at/);
});
