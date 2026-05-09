// Upgraded By @ProAlbert5
/**
 * MasterHttpRelay — Google Apps Script
 *
 * DEPLOYMENT:
 *   1. Go to https://script.google.com → New project
 *   2. Delete the default code, paste THIS entire file
 *   3. Click Deploy → New deployment
 *   4. Type: Web app  |  Execute as: Me  |  Who has access: Anyone
 *   5. Copy the Deployment ID into config.json as "script_id"
 *
 * CHANGE THE AUTH KEY BELOW TO YOUR OWN SECRET!
 */

const AUTH_KEY = "AUTH_KEY";

// Keep browser capability headers (sec-ch-ua*, sec-fetch-*) intact.
// Some modern apps, notably Google Meet, use them for browser gating.
// Headers that reveal the user's real IP are also stripped here as a
// second line of defence (the Python client strips them first).
const SKIP_HEADERS = {
  host: 1, connection: 1, "content-length": 1,
  "transfer-encoding": 1, "proxy-connection": 1, "proxy-authorization": 1,
  priority: 1, te: 1,
  // IP-leaking / proxy-metadata headers
  "x-forwarded-for": 1, "x-forwarded-host": 1, "x-forwarded-proto": 1,
  "x-forwarded-port": 1, "x-real-ip": 1, forwarded: 1, via: 1,
  // Internal relay hop-count header — must not be forwarded to target sites.
  "x-mhr-hop": 1,
  // UrlFetchApp does not decompress gzip/br/deflate responses — stripping
  // accept-encoding forces targets to reply with plain (uncompressed) bodies
  // so the relay never has to handle compressed content it cannot decode.
  "accept-encoding": 1
};

// If fetchAll fails, only retry methods that are safe to replay.
const SAFE_REPLAY_METHODS = { GET: 1, HEAD: 1, OPTIONS: 1 };

// Pattern that matches any Google Apps Script execution endpoint.
// Used to detect relay loops when an exit node is misconfigured to
// point back at a GAS deployment.
const GAS_URL_RE = /^https?:\/\/script\.google\.com\/macros\//i;
const FALLBACK_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36";

const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0"
];

function _shouldSkipHeader(headerName) {
  return SKIP_HEADERS[headerName.toLowerCase()] === 1;
};

function _maybeGzip(bytes) {
  try {
    var compressed = Utilities.gzip(Utilities.newBlob(bytes)).getBytes();
    if (compressed.length < bytes.length) return { b: compressed, gz: true };
  } catch (e) {};
  return {
    b: bytes,
    gz: false
  };
};

function doPost(e) {
  try {
    var req = JSON.parse(e.postData.contents);
    if (req.k !== AUTH_KEY) return _json({ e: "unauthorized" });
    // Batch mode: { k, q: [...] }
    if (Array.isArray(req.q)) return _doBatch(req.q);
    // Single mode
    return _json(_doSingleWithFallback(req));
  } catch (err) {
    return _json({ e: String(err) });
  };
};

function _doSingleWithFallback(req) {
  if (!req.u || typeof req.u !== "string" || !req.u.match(/^https?:\/\//i))
    return { e: "bad url" };
  if (GAS_URL_RE.test(req.u))
    return { e: "loop detected: cannot relay to Google Apps Script URL" };
  try {
    var optsFull = _buildOpts(req, false);
    var respFull = UrlFetchApp.fetch(req.u, optsFull);
    if (respFull.getResponseCode() < 500) {
      var gzFull = _maybeGzip(respFull.getContent());
      var resFull = {
        s: respFull.getResponseCode(),
        h: _respHeaders(respFull),
        b: Utilities.base64Encode(gzFull.b),
      };
      if (gzFull.gz) resFull.gz = 1;
      return resFull;
    };
  } catch (err) {}; // Fallback to simple headers
  try {
    var optsSimple = _buildOpts(req, true);
    var respSimple = UrlFetchApp.fetch(req.u, optsSimple);
    var gzSimple = _maybeGzip(respSimple.getContent());
    var resSimple = {
      s: respSimple.getResponseCode(),
      h: _respHeaders(respSimple),
      b: Utilities.base64Encode(gzSimple.b),
    };
    if (gzSimple.gz) resSimple.gz = 1;
    return resSimple;
  } catch (e) {
    return {
      e: "fetch_failed",
      details: e.toString()
    };
  };
};

function _doBatch(items) {
  var fetchArgs = [], fetchIndex = [], fetchMethods = [], errorMap = {};

  for (var i = 0; i < items.length; i++) {
    var it = items[i];
    if (!it || typeof it !== "object") { errorMap[i] = "bad item"; continue; };
    if (!it.u || typeof it.u !== "string" || !it.u.match(/^https?:\/\//i)) { errorMap[i] = "bad url"; continue; };
    try {
      var opts = _buildOpts(it, false);
      opts.url = it.u;
      fetchArgs.push(opts);
      fetchIndex.push(i);
      fetchMethods.push(String(it.m || "GET").toUpperCase());
    } catch (err) {
      errorMap[i] = String(err);
    };
  };

  var responses = [];
  if (fetchArgs.length) {
    try {
      responses = UrlFetchApp.fetchAll(fetchArgs);
    } catch (err) {
      responses = new Array(fetchArgs.length);
      for (var j = 0; j < fetchArgs.length; j++) {
        var method = fetchMethods[j];
        if (!SAFE_REPLAY_METHODS[method]) {
          errorMap[fetchIndex[j]] = "batch fetchAll failed; unsafe method not replayed";
          responses[j] = null;
          continue;
        };
        try {
          var fallbackReq = fetchArgs[j];
          var fallbackUrl = fallbackReq.url;
          var fallbackOpts = {};
          for (var key in fallbackReq) {
            if (Object.prototype.hasOwnProperty.call(fallbackReq, key) && key !== "url") {
              fallbackOpts[key] = fallbackReq[key];
            };
          };
          responses[j] = UrlFetchApp.fetch(fallbackUrl, fallbackOpts);
        } catch (singleErr) {
          errorMap[fetchIndex[j]] = String(singleErr);
          responses[j] = null;
        };
      };
    };
  };

  var results = [], rIdx = 0;
  for (var i = 0; i < items.length; i++) {
    if (errorMap[i]) {
      results.push({ e: errorMap[i] });
    } else {
      var resp = responses[rIdx++];
      if (!resp) {
        results.push({ e: "fetch failed" });
      } else {
        var gz = _maybeGzip(resp.getContent());
        var itemRes = {
          s: resp.getResponseCode(),
          h: _respHeaders(resp),
          b: Utilities.base64Encode(gz.b),
        };
        if (gz.gz) itemRes.gz = 1;
        results.push(itemRes);
      };
    };
  };
  return _json({ q: results });
};

function _buildOpts(req, simple) {
  var opts = {
    method: (req.m || "GET").toLowerCase(),
    muteHttpExceptions: true,
    followRedirects: req.r !== false,
    validateHttpsCertificates: true,
    escaping: false,
  };
  var headers = { "x-mhr-hop": "1" };
  if (simple) {
    headers["User-Agent"] = FALLBACK_UA;
    headers["Accept"] = "*/*";
    headers["Accept-Language"] = "en-US,en;q=0.9";
    headers["Accept-Encoding"] = "gzip, deflate";
    headers["Cache-Control"] = "no-cache";
  } else {
    var p = _getRandomProfile();
    headers["User-Agent"] = p.ua;
    headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8";
    headers["Accept-Language"] = "en-US,en;q=0.9";
    headers["Accept-Encoding"] = "gzip, deflate, br";
    headers["Cache-Control"] = "no-cache";
    headers["DNT"] = "1";
    headers["Upgrade-Insecure-Requests"] = "1";
    if (p.type === "chrome" || p.type === "edge") {
      headers["Sec-CH-UA"] = p.type === "chrome"
        ? `"Google Chrome";v="${p.ver}", "Chromium";v="${p.ver}", "Not_A Brand";v="24"`
        : `"Microsoft Edge";v="${p.ver}", "Chromium";v="${p.ver}", "Not_A Brand";v="24"`;
      headers["Sec-CH-UA-Mobile"] = "?0";
      headers["Sec-CH-UA-Platform"] = `"${p.plat}"`;
      headers["Sec-Fetch-Dest"] = "document";
      headers["Sec-Fetch-Mode"] = "navigate";
      headers["Sec-Fetch-Site"] = "none";
      headers["Sec-Fetch-User"] = "?1";
    } else if (p.type === "firefox") {
      headers["Sec-Fetch-Dest"] = "document";
      headers["Sec-Fetch-Mode"] = "navigate";
      headers["Sec-Fetch-Site"] = "none";
      headers["TE"] = "trailers";
    } else if (p.type === "safari") {
      headers["Sec-Fetch-Dest"] = "document";
      headers["Sec-Fetch-Mode"] = "navigate";
      headers["Sec-Fetch-Site"] = "none";
      headers["Sec-Fetch-User"] = "?1";
    };
  };
  if (req.h && typeof req.h === "object") {
    for (var k in req.h) {
      if (Object.prototype.hasOwnProperty.call(req.h, k) && !_shouldSkipHeader(k)) {
        headers[k] = req.h[k];
      };
    };
  };
  opts.headers = headers;
  if (req.b) {
    opts.payload = Utilities.base64Decode(req.b);
    if (req.ct) opts.contentType = req.ct;
  };
  // Jitter (5-15ms) to avoid pattern detection
  Utilities.sleep(Math.floor(Math.random() * 10) + 5);
  return opts;
};

// Caching browser's profiles
var _profiles = null;
function _getProfile() {
  if (!_profiles) {
    _profiles = [
      { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36", type: "chrome", plat: "Windows", ver: "149" },
      { ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36", type: "chrome", plat: "macOS", ver: "149" },
      { ua: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36", type: "chrome", plat: "Linux", ver: "149" },
      { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0", type: "firefox", plat: "Windows", ver: "138" },
      { ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0", type: "firefox", plat: "macOS", ver: "138" },
      { ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15", type: "safari", plat: "macOS", ver: "18.5" },
      { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0", type: "edge", plat: "Windows", ver: "149" }
    ];
  };
  return _profiles[Math.floor(Math.random() * _profiles.length)];
};

function _respHeaders(resp) {
  try {
    if (typeof resp.getAllHeaders === "function") return resp.getAllHeaders();
  } catch (e) {};
  return resp.getHeaders();
};

function doGet(e) {
  return HtmlService.createHtmlOutput(
    "<!DOCTYPE html><html><head><title>DomainFront Relay</title></head>" +
      '<body style="font-family:sans-serif;max-width:600px;margin:40px auto">' +
      "<h1> Relay Active </h1><p>Service is running normally.</p>" +
      "</body></html>"
  );
};

function _json(obj) {
  return HtmlService.createHtmlOutput(JSON.stringify(obj))
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
};
