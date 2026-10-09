import { test } from "node:test";
import assert from "node:assert/strict";
import { checkPolicyUrl } from "../src/privacy.mjs";

const URL = "https://example.com/privacy";
const policy = "Our privacy policy describes personal data we collect, retain and share. ".repeat(12);

// A real Response exercises its body reader. Model fetch's signal propagation
// without opening sockets or depending on an external server staying broken.
function responseStream(signal, { prefix = "", error } = {}) {
  return new Response(new ReadableStream({
    start(controller) {
      if (prefix) controller.enqueue(new TextEncoder().encode(prefix));
      if (error) controller.error(error);
      else signal.addEventListener("abort", () => controller.error(signal.reason), { once: true });
    },
  }));
}

async function boundedCheck(fetchImpl) {
  let watchdog;
  try {
    return await Promise.race([
      checkPolicyUrl(URL, { timeoutMs: 30, fetchImpl }),
      new Promise((_, reject) => {
        watchdog = setTimeout(() => reject(new Error("privacy check outlived its deadline")), 500);
      }),
    ]);
  } finally {
    clearTimeout(watchdog);
  }
}

for (const prefix of ["", policy]) {
  test(`headers followed by a stalled ${prefix ? "partial" : "empty"} body time out without a content verdict`, async () => {
    const findings = await boundedCheck(async (_, { signal }) => responseStream(signal, { prefix }));
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, "warn");
    assert.match(findings[0].title, /within 0\.03s/);
    assert.doesNotMatch(findings[0].title, /reads like|does not read like/);
    assert.match(findings[0].detail, /not the same as the address being broken/);
  });
}

test("a body read failure is a network warning, not an empty-policy verdict", async () => {
  const findings = await boundedCheck(async (_, { signal }) =>
    responseStream(signal, { error: new TypeError("terminated") }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "warn");
  assert.match(findings[0].title, /could not be read.*terminated/);
  assert.doesNotMatch(findings[0].detail, /0 characters/);
});

test("a timeout before headers remains a network warning", async () => {
  const findings = await boundedCheck(async (_, { signal }) => new Promise((_, reject) => {
    signal.addEventListener("abort", () => reject(signal.reason), { once: true });
  }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "warn");
  assert.match(findings[0].title, /within 0\.03s/);
});

test("a complete policy still gets a reachability verdict and releases the timer", async () => {
  let signal;
  const findings = await boundedCheck(async (_, options) => {
    signal = options.signal;
    return new Response(policy);
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "info");
  assert.match(findings[0].title, /reachable and reads like a policy/);
  await new Promise(resolve => setTimeout(resolve, 60));
  assert.equal(signal.aborted, false, "the deadline must be cleared after a completed body");
});

test("a non-success status fails promptly without waiting for its stalled body", async () => {
  let signal;
  const findings = await boundedCheck(async (_, options) => {
    signal = options.signal;
    return { status: 404, ok: false, url: URL, text() { throw new Error("must not read this body"); } };
  });
  assert.equal(findings[0].severity, "fail");
  assert.match(findings[0].title, /answers 404/);
  assert.equal(signal.aborted, true, "stop downloading a body that will not be inspected");
});
