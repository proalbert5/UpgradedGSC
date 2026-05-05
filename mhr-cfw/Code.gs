// Upgraded By @proalbert5
// Google Apps Script Files

const AUTH_KEY = "AUTH_KEY";
const WORKER_URL = "https://{WORKER_URL}";

const SKIP_HEADERS = {
  host: 1, connection: 1, "content-length": 1,
  "transfer-encoding": 1, "proxy-connection": 1, "proxy-authorization": 1,
  // IP-leaking / proxy-metadata headers
  "x-forwarded-for": 1, "x-forwarded-host": 1, "x-forwarded-proto": 1,
  "x-forwarded-port": 1, "x-real-ip": 1, "forwarded": 1, "via": 1,
};

const FALLBACK_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36";
const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0"
];
const MAX_RETRIES = 1;
const BACKOFF_MS = 400;

function doPost(e) {
  try {
    var req = JSON.parse(e.postData.contents);
    if (req.k !== AUTH_KEY) return _json({ e: "unauthorized" });
    if (Array.isArray(req.q)) return _doBatch(req.q);
    return _json(_doSingleWithFallback(req));
  } catch (err) {
    return _json({ e: String(err) });
  };
};

function _doSingleWithFallback(req) {
  if (!req.u || typeof req.u !== "string" || !req.u.match(/^https?:\/\//i))
    return { e: "bad url" };
  // Try via Worker first
  if (WORKER_URL && WORKER_URL.length) {
    try {
      var res = _callWorker(req, false);
      if (res && res.s && res.s >= 500 && res.s < 600) throw new Error();
      return res;
    } catch (e) {
      try {
        return _callWorker(req, true);
      } catch (e2) {
        return _doSingleDirect(req);
      };
    };
  };
  return _doSingleDirect(req);
};

function _callWorker(req, simple) {
  var payload = _buildWorkerPayload(req, simple);
  var resp = UrlFetchApp.fetch(WORKER_URL, {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true,
    followRedirects: true
  });
  var status = resp.getResponseCode();
  var text = resp.getContentText();
  if (status !== 200) throw new Error("Worker returned " + status);
  return JSON.parse(text);
};

function _doSingleDirect(req) {
  // Try full headers then simple fallback
  try {
    var optsFull = _buildDirectOpts(req, false);
    var respFull = UrlFetchApp.fetch(req.u, optsFull);
    if (respFull.getResponseCode() < 500) {
      return {
        s: respFull.getResponseCode(),
        h: _respHeaders(respFull),
        b: Utilities.base64Encode(respFull.getContent())
      };
    };
  } catch (e) {};
  var optsSimple = _buildDirectOpts(req, true);
  var respSimple = UrlFetchApp.fetch(req.u, optsSimple);
  return {
    s: respSimple.getResponseCode(),
    h: _respHeaders(respSimple),
    b: Utilities.base64Encode(respSimple.getContent())
  };
};

function _buildWorkerPayload(req, simple) {
  var headers = {};
  if (req.h && typeof req.h === "object") {
    for (var k in req.h) {
      if (req.h.hasOwnProperty(k) && !SKIP_HEADERS[k.toLowerCase()]) {
        headers[k] = req.h[k];
      };
    };
  };
  // Add stealth headers if not simple
  if (!simple) {
    var ua = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
    headers["User-Agent"] = ua;
    headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8";
    headers["Accept-Language"] = "en-US,en;q=0.9";
    headers["Accept-Encoding"] = "gzip, deflate, br";
    headers["Cache-Control"] = "no-cache";
    headers["DNT"] = "1";
    headers["Upgrade-Insecure-Requests"] = "1";
    headers["Connection"] = "keep-alive";
    // Client hints for Chrome and Firefox
    if (ua.includes("Chrome/") && !ua.includes("Edg/")) {
      var version = ua.match(/Chrome\/(\d+)/)[1];
      var platform = ua.includes("Windows") ? "Windows" : (ua.includes("Mac") ? "macOS" : "Linux");
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
  } else {
    headers["User-Agent"] = FALLBACK_UA;
    headers["Accept"] = "*/*";
    headers["Accept-Language"] = "en-US,en;q=0.9";
    headers["Accept-Encoding"] = "gzip, deflate";
    headers["Cache-Control"] = "no-cache";
  };
  // Add jitter for better speed
  Utilities.sleep(Math.floor(Math.random() * 10) + 5);
  return {
    u: req.u,
    m: (req.m || "GET").toUpperCase(),
    h: headers,
    b: req.b || null,
    ct: req.ct || null,
    r: req.r !== false
  };
};

function _buildDirectOpts(req, simple) {
  var opts = {
    method: (req.m || "GET").toLowerCase(),
    muteHttpExceptions: true,
    followRedirects: req.r !== false,
    validateHttpsCertificates: true,
    escaping: false
  };
  var headers = {};
  if (simple) {
    headers["User-Agent"] = FALLBACK_UA;
    headers["Accept"] = "*/*";
    headers["Accept-Language"] = "en-US,en;q=0.9";
    headers["Accept-Encoding"] = "gzip, deflate";
    headers["Cache-Control"] = "no-cache";
  } else {
    var ua = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
    headers["User-Agent"] = ua;
    headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8";
    headers["Accept-Language"] = "en-US,en;q=0.9";
    headers["Accept-Encoding"] = "gzip, deflate, br";
    headers["Cache-Control"] = "no-cache";
    headers["DNT"] = "1";
    headers["Upgrade-Insecure-Requests"] = "1";
    headers["Connection"] = "keep-alive";
    if (ua.includes("Chrome/") && !ua.includes("Edg/")) {
      var v = ua.match(/Chrome\/(\d+)/)[1];
      var p = ua.includes("Windows") ? "Windows" : (ua.includes("Mac") ? "macOS" : "Linux");
      headers["Sec-CH-UA"] = `"Google Chrome";v="${v}", "Chromium";v="${v}", "Not_A Brand";v="24"`;
      headers["Sec-CH-UA-Mobile"] = "?0";
      headers["Sec-CH-UA-Platform"] = `"${p}"`;
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
  };
  if (req.h && typeof req.h === "object") {
    for (var k in req.h) {
      if (!SKIP_HEADERS[k.toLowerCase()]) headers[k] = req.h[k];
    };
  };
  opts.headers = headers;
  if (req.b) {
    opts.payload = Utilities.base64Decode(req.b);
    if (req.ct) opts.contentType = req.ct;
  };
  return opts;
};

function _respHeaders(resp) {
  try {
    if (typeof resp.getAllHeaders === "function") return resp.getAllHeaders();
  } catch(e) {};
  return resp.getHeaders();
};

function _doBatch(items) {
  var fetchArgs = [], errorMap = {};
  for (var i = 0; i < items.length; i++) {
    var item = items[i];
    if (!item.u || typeof item.u !== "string" || !item.u.match(/^https?:\/\//i)) {
      errorMap[i] = "bad url";
      continue;
    };
    var payload = _buildWorkerPayload(item, false);
    fetchArgs.push({
      url: WORKER_URL,
      method: "post",
      contentType: "application/json",
      payload: JSON.stringify(payload),
      muteHttpExceptions: true,
      followRedirects: true
    });
  };
  var responses = [];
  if (fetchArgs.length) {
    try {
      responses = UrlFetchApp.fetchAll(fetchArgs);
    } catch (err) {
      for (var j = 0; j < fetchArgs.length; j++) {
        errorMap[j] = "batch fetchAll failed";
      };
    };
  };
  var results = [], rIdx = 0;
  for (var i = 0; i < items.length; i++) {
    if (errorMap[i]) {
      results.push({ e: errorMap[i] });
    } else {
      var resp = responses[rIdx++];
      try {
        results.push(JSON.parse(resp.getContentText()));
      } catch (e) {
        results.push({ e: "invalid worker response", raw: resp.getContentText() });
      };
    };
  };
  return _json({ q: results });
};

function doGet(e) {
  return HtmlService.createHtmlOutput(
    "<!DOCTYPE html><html><head><title>My App</title></head>" +
      '<body style="font-family:sans-serif;max-width:600px;margin:40px auto">' +
      "<h1>Relay Active</h1><p>Cloudflare Working Succesfuly.</p>" +
      "</body></html>"
  );
};

function _json(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
};