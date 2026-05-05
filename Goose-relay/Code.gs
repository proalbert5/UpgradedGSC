// Upgraded By @proalbert5
// GooseRelay forwarder.
//
// Apps Script web app deployed as: Execute as: Me, Access: Anyone (or Anyone with Google account).
// All traffic is AES-GCM encrypted by the client; this script is a dumb pipe
// and never sees plaintext or holds the key.
//
// Wire: client POSTs base64(encrypted batch). We forward the bytes verbatim
// to RELAY_URL and return its response body verbatim.
//
// Replace RELAY_URL with your VPS address before deploying.

const RELAY_URL = 'http://YOUR.VPS.IP:8443/tunnel';
const FORWARDER_VERSION = 1;
const PROTOCOL_VERSION = 1;
const MAX_PAYLOAD_MB = 10;                     // optional size limit
const MAX_PAYLOAD_BYTES = MAX_PAYLOAD_MB * 1024 * 1024;
const MAX_RETRIES = 1;
const BACKOFF_MS = 400;

// Browser headers for better stealth
const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0"
];

function doPost(e) {
  bumpInvocationCount_();
  const payload = (e && e.postData && e.postData.contents) || '';
  if (payload === '') {
    return ContentService
      .createTextOutput("Missing payload")
      .setMimeType(ContentService.MimeType.TEXT);
  };
  // optional size limit
  if (payload.length > MAX_PAYLOAD_BYTES) {
    console.warn("Payload too large: " + payload.length);
    return ContentService
      .createTextOutput("Payload exceeds " + MAX_PAYLOAD_MB + " MB limit")
      .setMimeType(ContentService.MimeType.TEXT);
  };
  // jitter (5-15ms)
  Utilities.sleep(Math.floor(Math.random() * 10) + 5);

  let lastError;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      // Build stealth headers inside the loop
      const ua = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
      const headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "no-cache",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive"
      };
      // Optional client hints for Chrome
      if (ua.includes("Chrome/") && !ua.includes("Edg/")) {
        const version = ua.match(/Chrome\/(\d+)/)[1];
        const platform = ua.includes("Windows") ? "Windows" : (ua.includes("Mac") ? "macOS" : "Linux");
        headers["Sec-CH-UA"] = `"Google Chrome";v="${version}", "Chromium";v="${version}", "Not_A Brand";v="24"`;
        headers["Sec-CH-UA-Mobile"] = "?0";
        headers["Sec-CH-UA-Platform"] = `"${platform}"`;
        headers["Sec-Fetch-Dest"] = "document";
        headers["Sec-Fetch-Mode"] = "navigate";
        headers["Sec-Fetch-Site"] = "none";
        headers["Sec-Fetch-User"] = "?1";
      } else if (ua.includes("Firefox/")) {
        headers["Sec-Fetch-Dest"] = "document";
        headers["Sec-Fetch-Mode"] = "navigate";
        headers["Sec-Fetch-Site"] = "none";
        headers["TE"] = "trailers";
      };

      const resp = UrlFetchApp.fetch(RELAY_URL, {
        method: 'post',
        contentType: 'text/plain',
        payload: payload,
        muteHttpExceptions: true,
        followRedirects: false,
        deadline: 30,   // unchanged
        headers: headers
      });
      const code = resp.getResponseCode();
      if (code === 200) {
        return ContentService
          .createTextOutput(resp.getContentText())
          .setMimeType(ContentService.MimeType.TEXT);
      };
      lastError = "Upstream status " + code;
      console.warn("Attempt " + (attempt+1) + " failed: " + lastError);
    } catch (err) {
      lastError = err.toString();
      console.warn("Attempt " + (attempt+1) + " error: " + lastError);
    };
    if (attempt < MAX_RETRIES) {
      Utilities.sleep(BACKOFF_MS);
    };
  };
  console.error("All retries failed: " + lastError);
  return ContentService
    .createTextOutput("Upstream error")
    .setMimeType(ContentService.MimeType.TEXT);
};

// doGet returns this deployment's per-day invocation count so the client can
// log real per-deployment usage alongside its own client-side counter. The
// day boundary tracks the Apps Script quota window (midnight Pacific). Format
// is JSON so the client can parse without ambiguity:
//   {"ok":true,"date":"2026-05-04","count":1234}
function doGet(e) {
  if (e && e.parameter && e.parameter.legacy === '1') {
    return ContentService
      .createTextOutput('GooseRelay forwarder OK')
      .setMimeType(ContentService.MimeType.TEXT);
  };
  const props = PropertiesService.getScriptProperties();
  const today = pacificDateKey_();
  const count = parseInt(props.getProperty('count_' + today) || '0', 10);
  const out = {
    ok: true,
    date: today,
    count: count,
    version: FORWARDER_VERSION,
    protocol: PROTOCOL_VERSION,
  };
  return ContentService
    .createTextOutput(JSON.stringify(out))
    .setMimeType(ContentService.MimeType.JSON);
};

function pacificDateKey_() {
  return Utilities.formatDate(new Date(), 'America/Los_Angeles', 'yyyy-MM-dd');
};

// bumpInvocationCount_ records one invocation in PropertiesService keyed by
// today's PT date. Best-effort: under high concurrency two requests may read
// the same value and write the same incremented number, slightly under-counting.
// That's acceptable for an informational counter — adding a LockService gate
// would add tens of ms to every tunnel request, which costs more than perfect
// accuracy is worth.
function bumpInvocationCount_() {
  try {
    const props = PropertiesService.getScriptProperties();
    const today = pacificDateKey_();
    const key = 'count_' + today;
    const raw = props.getProperty(key);
    if (raw === null) {
      // First request of a new day — purge yesterday's keys so the property
      // store doesn't grow unbounded (capped at 9 KB / 500 entries by Google).
      pruneStaleCounts_(props, today);
    };
    const cur = raw === null ? 0 : parseInt(raw, 10);
    props.setProperty(key, String(cur + 1));
  } catch (err) {
    // Property writes can fail under contention; counting is informational
    // so we swallow the error rather than break the tunnel request.
  };
};

function pruneStaleCounts_(props, today) {
  const keys = props.getKeys();
  const keep = 'count_' + today;
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i];
    if (k.indexOf('count_') === 0 && k !== keep) {
      props.deleteProperty(k);
    };
  };
};