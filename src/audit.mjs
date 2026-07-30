// The permission ledger: for every permission the manifest asks for, what in the
// code actually needs it, and whether a narrower permission would have done.
//
// WHY THIS IS A SEPARATE PASS FROM THE RULES. A rule answers "is this a
// violation". Excessive permissions is not answerable that way, because the
// question Google actually asks is comparative: "If more than one permission
// could be used to implement a feature, you must request those with the least
// access to data or functionality." That is a claim about an alternative that
// was not taken, so it needs the call sites, not a yes or no.
//
// The Chrome Web Store dashboard makes the developer type a justification for
// every permission, and Purple Potassium is what comes back when those are thin.
// A justification is only as good as the evidence under it, so this pass exists
// to produce the evidence: permission -> the exact lines that require it.
//
// WHAT THIS DELIBERATELY WILL NOT DO: guess. Three separate honesty rules run
// through the file.
//
//   1. A permission with no entry in PERMISSION_API is reported UNKNOWN, never
//      unused. Silence about a permission we do not model is correct; calling it
//      unused because we have no pattern for it is a false accusation that gets
//      a developer to delete something their extension needs.
//   2. Every narrowing suggestion carries the evidence that motivated it AND the
//      condition that would make it wrong. A reviewer-facing claim we cannot
//      support is worse than no claim.
//   3. Text findings are drawn from the packaged JavaScript only. Minified or
//      bundled code defeats call-site analysis, and when that is detected the
//      pass says so rather than reporting a confident zero.

import { isCode } from "./scan.mjs";

// Permission -> the namespaces whose presence proves it is used. Kept in this
// file rather than shared with rules.mjs because this pass needs the call sites
// and rules.mjs only needs a boolean, and the two drift for good reasons.
export const PERMISSION_API = {
  cookies: ["chrome.cookies", "browser.cookies"],
  history: ["chrome.history", "browser.history"],
  topSites: ["chrome.topSites", "browser.topSites"],
  bookmarks: ["chrome.bookmarks", "browser.bookmarks"],
  downloads: ["chrome.downloads", "browser.downloads"],
  browsingData: ["chrome.browsingData", "browser.browsingData"],
  management: ["chrome.management", "browser.management"],
  tabs: ["chrome.tabs", "browser.tabs"],
  webRequest: ["chrome.webRequest", "browser.webRequest"],
  webNavigation: ["chrome.webNavigation", "browser.webNavigation"],
  identity: ["chrome.identity", "browser.identity"],
  storage: ["chrome.storage", "browser.storage"],
  notifications: ["chrome.notifications", "browser.notifications"],
  contextMenus: ["chrome.contextMenus", "browser.contextMenus"],
  alarms: ["chrome.alarms", "browser.alarms"],
  scripting: ["chrome.scripting", "browser.scripting"],
  debugger: ["chrome.debugger", "browser.debugger"],
  proxy: ["chrome.proxy", "browser.proxy"],
  privacy: ["chrome.privacy", "browser.privacy"],
  contentSettings: ["chrome.contentSettings", "browser.contentSettings"],
  pageCapture: ["chrome.pageCapture", "browser.pageCapture"],
  desktopCapture: ["chrome.desktopCapture", "browser.desktopCapture"],
  idle: ["chrome.idle", "browser.idle"],
  power: ["chrome.power", "browser.power"],
  tts: ["chrome.tts", "browser.tts"],
  activeTab: [], // granted by user gesture; no namespace of its own
  offscreen: ["chrome.offscreen", "browser.offscreen"],
  sidePanel: ["chrome.sidePanel", "browser.sidePanel"],
  declarativeNetRequest: ["chrome.declarativeNetRequest", "browser.declarativeNetRequest"],
};

// Which Chrome data-disclosure category a permission drags you into. Used to
// answer the Privacy practices tab, which is where Purple Nickel is decided.
const DISCLOSURE_CATEGORY = {
  cookies: "Authentication information / website content",
  history: "Web history",
  topSites: "Web history",
  bookmarks: "Personal communications or user-generated content",
  browsingData: "Web history",
  tabs: "Web history (tab URLs are browsing history)",
  webNavigation: "Web history",
  webRequest: "Web history and website content",
  identity: "Personally identifiable information",
  downloads: "User activity",
  management: "User activity",
  pageCapture: "Website content",
  desktopCapture: "Website content",
  debugger: "Website content",
};

const BROAD = new Set(["<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/", "file:///*"]);

// Find every line where a namespace is touched. Whole-file includes() cannot do
// this: it answers "somewhere" and a justification needs "here".
function callSites(files, needles) {
  const hits = [];
  for (const f of files) {
    if (!isCode(f)) continue;
    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      for (const n of needles) {
        if (line.includes(n)) {
          hits.push({ file: f.path, line: i + 1, api: n, text: line.trim().slice(0, 160) });
          break;
        }
      }
    }
  }
  return hits;
}

// Minified code defeats line-level evidence: a whole bundle on one line makes
// every call site look like the same place, and an absence of call sites in a
// bundle is not an absence in the source. Detected and declared, never assumed
// away - an audit that reports a confident zero over a bundle is the same class
// of error as a health check that passes on failure.
function looksMinified(files) {
  const suspect = [];
  for (const f of files) {
    if (!isCode(f)) continue;
    const longest = f.lines.reduce((m, l) => Math.max(m, l.length), 0);
    const avg = f.text.length / Math.max(1, f.lines.length);
    if (longest > 2000 || (avg > 300 && f.text.length > 20000)) {
      suspect.push({ file: f.path, longestLine: longest, avgLineLength: Math.round(avg) });
    }
  }
  return suspect;
}

// --- the narrowing analysis --------------------------------------------------
//
// Each entry states the alternative, the evidence that suggests it, and the
// condition under which the suggestion is WRONG. That last field is not padding:
// it is what makes the output usable in a reply to a reviewer, and what stops a
// developer deleting a permission they turn out to need.

function narrowings({ manifest, files, used }) {
  const out = [];
  const perms = new Set([...(manifest.permissions || []), ...(manifest.optional_permissions || [])]);
  const hosts = [...(manifest.host_permissions || []), ...(manifest.permissions || []).filter((p) => typeof p === "string" && (p.includes("://") || p === "<all_urls>"))];

  // tabs -> activeTab. The single most cited narrowing, because chrome.tabs is
  // reached for out of habit while the extension only ever wants the tab the
  // user just acted on.
  if (perms.has("tabs")) {
    const sites = used.tabs || [];
    const needsAll = sites.filter((s) => /tabs\.(onUpdated|onCreated|onRemoved|onActivated|query\s*\(\s*\{[^}]*\}|getAllInWindow)/.test(s.text) && !/active:\s*true/.test(s.text));
    if (sites.length && !needsAll.length) {
      out.push({
        from: "tabs", to: "activeTab",
        why: "Every chrome.tabs call site here reads the tab the user is already acting on. activeTab grants that on a user gesture and asks for no host permission and no warning at install.",
        evidence: sites.slice(0, 8),
        wrongIf: "you enumerate or observe tabs the user has not interacted with (background sync, tab counters, session restore). Then tabs is correct and this is the justification to give.",
      });
    }
  }

  // storage declared while only web storage is used.
  if (perms.has("storage")) {
    const chromeStorage = used.storage || [];
    const webStorage = callSites(files, ["localStorage", "sessionStorage"]);
    if (!chromeStorage.length && webStorage.length) {
      out.push({
        from: "storage", to: "(remove it)",
        why: "The storage permission governs chrome.storage, which never appears here. localStorage and sessionStorage are plain web APIs and need no permission at all.",
        evidence: webStorage.slice(0, 8),
        wrongIf: "chrome.storage is called from a file this pass could not read - check the skipped list before deleting the permission.",
      });
    }
  }

  // webRequest -> declarativeNetRequest, the MV3 answer. Only when the
  // permission is actually used: if it is declared and never called, the advice
  // is "delete it", and saying both is the kind of doubled-up output that gets a
  // linter muted.
  if (perms.has("webRequest") && (used.webRequest || []).length) {
    const sites = used.webRequest;
    const blocking = sites.filter((s) => /blocking|onBeforeRequest|onBeforeSendHeaders/.test(s.text));
    out.push({
      from: "webRequest", to: "declarativeNetRequest",
      why: "Under Manifest V3 the blocking form of webRequest is unavailable to most extensions, and declarativeNetRequest covers request blocking and modification without the extension seeing the traffic. Reviewers read a webRequest request as broader than the job needs unless observation is genuinely the feature.",
      evidence: (blocking.length ? blocking : sites).slice(0, 8),
      wrongIf: "you genuinely need to OBSERVE requests rather than change them, or you hold the declarativeNetRequestFeedback use case. Say which, in those words.",
    });
  }

  // Broad host permissions against the hosts the code actually contacts.
  const broadHosts = hosts.filter((h) => BROAD.has(h));
  if (broadHosts.length) {
    const urls = new Set();
    for (const f of files) {
      if (!isCode(f)) continue;
      for (const m of f.text.matchAll(/https?:\/\/([a-z0-9.-]+\.[a-z]{2,})(?![a-z])/gi)) {
        const host = m[1].toLowerCase();
        if (!/^(www\.)?(w3|example|localhost|schemas?)\b/.test(host)) urls.add(host);
      }
    }
    const concrete = [...urls].sort();
    out.push({
      from: broadHosts.join(", "), to: concrete.length ? concrete.map((h) => `https://${h}/*`).join(", ") : "(no concrete host found in code)",
      why: concrete.length
        ? `The packaged code only ever names ${concrete.length} host(s). A match pattern list is narrower than every site, and it removes the "Read and change all your data on all websites" install warning that costs installs.`
        : "No concrete host appears in the packaged code, so the breadth of this request is not evidenced by anything this pass can see.",
      evidence: concrete.slice(0, 20).map((h) => ({ file: "(derived from code)", line: 0, api: h, text: `https://${h}` })),
      wrongIf: "the extension is a general-purpose tool that genuinely runs on sites the user chooses at runtime (an ad blocker, a reader mode, a password manager). Then every site is the honest answer, and the fix is to justify it rather than narrow it.",
    });
  }

  // scripting + broad hosts where activeTab would carry the injection.
  if (perms.has("scripting") && broadHosts.length) {
    const sites = used.scripting || [];
    const onGesture = sites.filter((s) => /executeScript/.test(s.text));
    if (onGesture.length) {
      out.push({
        from: "scripting + " + broadHosts.join(", "), to: "scripting + activeTab",
        why: "Injection that happens because the user clicked can run under activeTab, which grants the current tab for the duration of that gesture and needs no host permission.",
        evidence: onGesture.slice(0, 8),
        wrongIf: "you inject on page load, without a click, on sites the user has not chosen. Then a host permission is required and the narrowing does not apply.",
      });
    }
  }

  return out;
}

// --- the audit ---------------------------------------------------------------

export function audit({ manifest, files, skipped }) {
  if (!manifest) return null;

  const declared = [
    ...(manifest.permissions || []).map((p) => ({ name: p, where: "permissions" })),
    ...(manifest.optional_permissions || []).map((p) => ({ name: p, where: "optional_permissions" })),
  ].filter((p) => typeof p.name === "string" && !p.name.includes("://") && p.name !== "<all_urls>");

  const used = {};
  const ledger = [];

  for (const { name, where } of declared) {
    const apis = PERMISSION_API[name];
    if (!apis) {
      ledger.push({ permission: name, where, status: "unknown", sites: [],
        note: "This pass carries no API pattern for this permission, so it says nothing rather than guessing. Absence here is not evidence of disuse." });
      continue;
    }
    const sites = apis.length ? callSites(files, apis) : [];
    used[name] = sites;
    if (name === "activeTab") {
      ledger.push({ permission: name, where, status: "used", sites: [],
        note: "activeTab is granted by a user gesture and has no namespace of its own, so it has no call sites by construction. It is the narrow answer, not a finding." });
      continue;
    }
    ledger.push({
      permission: name, where,
      status: sites.length ? "used" : "unused",
      sites: sites.slice(0, 12),
      siteCount: sites.length,
      disclosure: DISCLOSURE_CATEGORY[name] || null,
      note: sites.length
        ? null
        : "Declared, and its chrome.* namespace appears in none of the packaged JavaScript this pass could read. This is Google's stated trigger for Purple Potassium.",
    });
  }

  const minified = looksMinified(files);

  return {
    manifestVersion: manifest.manifest_version,
    ledger,
    narrowings: narrowings({ manifest, files, used }),
    disclosures: ledger
      .filter((l) => l.status === "used" && l.disclosure)
      .map((l) => ({ permission: l.permission, category: l.disclosure, sites: l.sites.slice(0, 3) })),
    confidence: {
      filesRead: files.filter(isCode).length,
      skipped,
      minified,
      // The one sentence that keeps this honest. Every "unused" verdict below is
      // scoped to what was actually read, and this names the gap.
      caveat: minified.length || skipped.length
        ? "Call-site evidence is incomplete: see minified and skipped. An 'unused' verdict over a bundle or an unread file is not a finding, and must be checked against the original source before any permission is deleted."
        : "Every packaged JavaScript file was read as source. Call-site evidence is complete over the submitted package.",
    },
  };
}
