// Upgraded By @ProAlbert5
// MasterHttpRelay exit node for Cloudflare Workers.
// Deploy as HTTP endpoint and set PSK to a strong secret.

const PSK = "CHANGE_ME_TO_A_STRONG_SECRET";

const STRIP_HEADERS = new Set([
  "host",
  "connection",
  "content-length",
  "transfer-encoding",
  "proxy-connection",
  "proxy-authorization",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-forwarded-port",
  "x-real-ip",
  "forwarded",
  "via",
  "x-mhr-hop",
  "accept-encoding",
]);

// Simple fallback headers
const SIMPLE_HEADERS = {
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
  "Accept": "*/*",
  "Accept-Language": "en-US,en;q=0.9",
  "Accept-Encoding": "gzip, deflate, br",
  "Cache-Control": "no-cache",
};

function decodeBase64ToBytes(input) {
  const bin = atob(input);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

function encodeBytesToBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
};

function sanitizeHeaders(h) {
  const out = {};
  if (!h || typeof h !== "object") return out;
  for (const [k, v] of Object.entries(h)) {
    if (!k) continue;
    if (STRIP_HEADERS.has(k.toLowerCase())) continue;
    out[k] = String(v ?? "");
  };
  return out;
};

export default {
  async fetch(req) {
    try {
      if (req.method === "GET") {
        return Response.json(
          {
            ok: true,
            status: "healthy",
            message: "Everything is OK. Worker is deployed and reachable.",
            usage: "Send POST with relay payload for actual proxy requests.",
          },
          { status: 200 }
        );
      };

      if (req.method !== "POST") {
        return Response.json(
          {
            e: "method_not_allowed",
            message: "Use POST for relay requests. GET is only a health check.",
          },
          { status: 405 }
        );
      };

      const body = await req.json();
      if (!body || typeof body !== "object") {
        return Response.json({ e: "bad_json" }, { status: 400 });
      };

      if (!PSK) {
        return Response.json({ e: "server_psk_missing" }, { status: 500 });
      };

      const k = String(body.k ?? "");
      const u = String(body.u ?? "");
      const m = String(body.m ?? "GET").toUpperCase();
      const h = sanitizeHeaders(body.h);
      const b64 = body.b;
      const followRedirect = body.r !== false;

      if (k !== PSK) return Response.json({ e: "unauthorized" }, { status: 401 });
      if (!/^https?:\/\//i.test(u)) return Response.json({ e: "bad_url" }, { status: 400 });

      // Loop detection
      try {
        const targetHost = new URL(u).hostname.toLowerCase();
        const workerHost = new URL(req.url).hostname.toLowerCase();
        if (targetHost === workerHost) {
          return Response.json(
            { e: "loop_detected", detail: "target URL resolves to this Worker" },
            { status: 508 }
          );
        };
      } catch (_) {};

      const hopHeader = req.headers.get("x-mhr-hop");
      if (hopHeader && /\/macros\/s\//i.test(u)) {
        return Response.json(
          { e: "loop_detected", detail: "GAS→Worker→GAS relay loop" },
          { status: 508 }
        );
      };

      let payload;
      if (typeof b64 === "string" && b64.length > 0) payload = decodeBase64ToBytes(b64);
      const requestBody = payload ? Uint8Array.from(payload) : undefined;

      async function doFetch(headersObj) {
        const outgoingHeaders = new Headers(headersObj);
        outgoingHeaders.set("x-mhr-hop", "1");
        return fetch(u, {
          method: m,
          headers: outgoingHeaders,
          body: requestBody,
          redirect: followRedirect ? "follow" : "manual",
        });
      };

      let resp;
      try {
        resp = await doFetch(h);
        if (resp.status >= 500 && resp.status < 600) {
          resp = await doFetch(SIMPLE_HEADERS);
        };
      } catch (err) {
        resp = await doFetch(SIMPLE_HEADERS);
      };

      const data = new Uint8Array(await resp.arrayBuffer());
      const respHeaders = {};
      resp.headers.forEach((value, key) => {
        respHeaders[key] = value;
      });

      return Response.json({
        s: resp.status,
        h: respHeaders,
        b: encodeBytesToBase64(data),
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return Response.json({ e: message }, { status: 500 });
    };
  }
};
