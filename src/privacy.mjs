// The ONE check in this package that makes a network request, and it only runs
// when you pass --privacy-policy <url>.
//
// WHY IT EXISTS, and it is a real case rather than a guess. A developer's
// extension was rejected under Purple Lithium and the cause was mundane: the
// privacy policy URL in their listing 404'd, because the GitHub repository behind
// it was private. Chrome DevRel diagnosed it in one reply on the chromium-
// extensions group. Nothing about that needs a human to spot, and nothing about
// it is visible in the package - which is exactly why the rest of this tool
// warns about the privacy policy rather than checking it.
//
// GOOGLE NAMES THESE TRIGGERS IN ITS OWN WORDS on the udp-disclosure-policy
// category, which is why this is a policy check and not an opinion:
//   "The privacy policy URL is not working."
//   "The privacy policy is not accessible."
//   "The privacy policy URL is not leading to privacy policy."
//
// THE DESIGN CONSTRAINT THIS MUST NOT BREAK. lint() is synchronous, offline and
// reads nothing but your files, and people run it in CI on packages they have
// not published. So this lives outside the rule set entirely: a separate async
// entry point the CLI calls only when a URL is supplied. No URL, no socket.
//
// WHAT IT DOES NOT DO, stated plainly because the rest of the tool is careful
// about this. It checks that the address answers and that the page looks like
// prose about data. It cannot judge whether your policy is ADEQUATE, and a
// reachable policy is not an approved one. Reviewers read the words.

// Hosts a Chrome reviewer's browser can never reach. Refusing them is honest
// policy advice first - a policy URL on localhost is a rejection waiting to
// happen - and it doubles as the guard that keeps this from being pointed at
// something inside a network by whoever wrote the URL.
const UNREACHABLE_HOST = [
  /^localhost$/i,
  /\.localhost$/i,
  /^127\./,
  /^0\./,
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^169\.254\./,
  /^\[?::1\]?$/,
  /^\[?f[cd][0-9a-f]{2}:/i,
  /\.local$/i,
  /\.internal$/i,
];

const CATEGORY = "udp-disclosure-policy";

const f = (severity, title, detail, evidence = []) => ({
  rule: "privacy-policy-url",
  category: CATEGORY,
  severity,
  title,
  detail,
  evidence,
});

// Words that a page about data handling contains and a landing page or an error
// shell does not. Deliberately shallow, and the finding says so: this is the
// difference between "the address answers" and "the address answers with
// something plausibly about data", not a reading of your policy.
const DATA_WORDS = [
  "privacy", "personal", "data", "information", "collect", "cookie",
  "process", "retain", "share", "third party", "third-party",
];

/**
 * @returns {Promise<object[]>} findings, in the same shape lint() produces, so
 * the CLI renders them through the same path. Empty means the URL is reachable
 * and looks like a policy.
 */
export async function checkPolicyUrl(url, { timeoutMs = 10000, fetchImpl = fetch } = {}) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return [f(
      "fail",
      "The privacy policy URL is not a URL",
      'Google lists "The privacy policy URL is not working" as a trigger for this category. ' +
        "Paste the address exactly as it appears in the Privacy tab of your dashboard, including the scheme.",
      [{ file: "--privacy-policy", text: url }],
    )];
  }

  if (u.protocol !== "https:" && u.protocol !== "http:") {
    return [f(
      "fail",
      `The privacy policy URL uses ${u.protocol} rather than https`,
      "A reviewer opens this address in a browser. Only http and https are openable.",
      [{ file: "--privacy-policy", text: url }],
    )];
  }

  const host = u.hostname;
  if (UNREACHABLE_HOST.some((re) => re.test(host))) {
    return [f(
      "fail",
      `The privacy policy URL points at ${host}, which nobody outside your network can open`,
      'Google lists "The privacy policy is not accessible" as a trigger. A loopback, private or .local ' +
        "address resolves on your machine and nowhere else, so the reviewer sees nothing. " +
        "This check makes no request to such a host.",
      [{ file: "--privacy-policy", text: url }],
    )];
  }

  const findings = [];
  if (u.protocol === "http:") {
    findings.push(f(
      "warn",
      "The privacy policy URL is plain http",
      "It will probably still load, but browsers mark it insecure and the same policy family requires " +
        "user data to be transmitted with modern cryptography. Serve the policy over https.",
      [{ file: "--privacy-policy", text: url }],
    ));
  }

  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  let res;
  try {
    res = await fetchImpl(u.href, {
      signal: ctl.signal,
      redirect: "follow",
      headers: {
        // Some hosts serve a different page to something that does not look like
        // a browser, and the question here is what a reviewer sees.
        accept: "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
        "user-agent": "webstore-lint (privacy policy reachability check)",
      },
    });
  } catch (e) {
    clearTimeout(timer);
    // COULD NOT LOOK IS NOT THE SAME FACT AS NOT THERE. A DNS failure on the
    // developer's own machine, an offline CI runner or a proxy is not evidence
    // about the URL, so this warns and says which it is rather than failing.
    const aborted = e.name === "AbortError";
    return [...findings, f(
      "warn",
      aborted
        ? `The privacy policy URL did not answer within ${timeoutMs / 1000}s`
        : `The privacy policy URL could not be reached from here: ${e.message}`,
      "This is not the same as the address being broken. It may be your network, a proxy, or an offline " +
        "runner. Open it yourself in a private browser window before you trust either answer. " +
        "A reviewer will be doing exactly that.",
      [{ file: "--privacy-policy", text: url }],
    )];
  }
  clearTimeout(timer);

  const finalUrl = res.url || u.href;
  const redirected = finalUrl.replace(/\/$/, "") !== u.href.replace(/\/$/, "");

  if (!res.ok) {
    return [...findings, f(
      "fail",
      `The privacy policy URL answers ${res.status}`,
      'Google lists "The privacy policy URL is not working" as a trigger for this category, and a ' +
        "404 here is one of the most common causes of an otherwise clean rejection. If the page lives " +
        "in a source repository, check the repository is PUBLIC: a private repo serves 404 to everyone " +
        "but you, and it looks fine while you are logged in.",
      [{ file: redirected ? `${url} -> ${finalUrl}` : url, text: `HTTP ${res.status}` }],
    )];
  }

  let body = "";
  try {
    body = await res.text();
  } catch {
    body = "";
  }

  // Strip tags and scripts before counting words, or a single-page app's bundle
  // reads as a wall of text that mentions everything.
  const text = body
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  const hits = DATA_WORDS.filter((w) => text.toLowerCase().includes(w));

  if (text.length < 400 || hits.length < 3) {
    findings.push(f(
      "warn",
      `The privacy policy URL answers 200 but the page does not read like a privacy policy`,
      'Google lists "The privacy policy URL is not leading to privacy policy" as a trigger. This check ' +
        "is shallow on purpose: it counted the visible text and looked for words a policy about data " +
        `contains. It found ${text.length} characters and ${hits.length} of those words` +
        `${hits.length ? ` (${hits.join(", ")})` : ""}. That can be wrong - a policy rendered by ` +
        "JavaScript looks empty to any fetch, including a crawler's. Open the address in a private " +
        "window with JavaScript disabled and see what a reviewer would see.",
      [{ file: redirected ? `${url} -> ${finalUrl}` : url, text: `HTTP 200, ${text.length} chars of text` }],
    ));
    return findings;
  }

  if (redirected) {
    findings.push(f(
      "info",
      "The privacy policy URL redirects",
      `It ends at ${finalUrl}. That is fine, and worth knowing: put the address you want reviewed in ` +
        "the dashboard field, since a redirect chain is one more thing that can break later.",
      [{ file: url, text: `-> ${finalUrl}` }],
    ));
  }

  findings.push(f(
    "info",
    "The privacy policy URL is reachable and reads like a policy",
    `HTTP 200, ${text.length} characters of visible text, mentioning ${hits.join(", ")}. ` +
      "That is reachability only. Whether the words actually describe what your extension collects is " +
      "what a reviewer reads it for, and this tool cannot judge it.",
    [{ file: finalUrl, text: `HTTP 200, ${text.length} chars of text` }],
  ));
  return findings;
}
