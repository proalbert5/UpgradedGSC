// Upgraded by @proalbert5
// Cloudflare Worker File

const WORKER_URL = "https://myworker.workers.dev";   // must match the URL in Code.gs, need to exist https://
const DEFAULT_UPSTREAM_TIMEOUT_MS = 25000;

function decodeBase64ToBytes(input) {
  const bin = atob(input);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function encodeBytesToBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function sanitizeReplyHeaders(headers) {
  const out = {};
  for (const [k, v] of headers.entries()) {
    const lower = k.toLowerCase();
    if (lower === "set-cookie" || lower === "server" || lower === "x-powered-by") continue;
    out[k] = v;
  }
  return out;
}

export default {
  async fetch(request, env) {
    try {
      const hop = request.headers.get("x-relay-hop");
      const fwdHop = request.headers.get("x-fwd-hop");
      if (hop === "1" || fwdHop === "1") {
        return json({ e: "loop detected" }, 508);
      }
      if (request.method === "GET") {
        return json({ ok: true, status: "healthy", message: "Relay is Active." }, 200);
      }
      if (request.method !== "POST") {
        return json({ e: "Method not allowed." }, 405);
      }
      let req;
      try {
        req = await request.json();
      } catch (_) {
        return json({ e: "bad_json" }, 400);
      }
      if (!req.u || typeof req.u !== "string") {
        return json({ e: "missing url" }, 400);
      }
      const targetUrl = new URL(req.u);
      const blockedHosts = [WORKER_URL.replace(/^https?:\/\//, "")];
      if (blockedHosts.some(h => targetUrl.hostname.endsWith(h))) {
        return json({ e: "self-fetch blocked" }, 400);
      }
      const upstreamUrl = (env && env.UPSTREAM_FORWARDER_URL) || "";
      if (upstreamUrl) {
        const upstreamResp = await forwardViaUpstream(req, env, upstreamUrl);
        if (upstreamResp) return upstreamResp;
      }
      const headers = new Headers();
      if (req.h && typeof req.h === "object") {
        const stripSet = new Set([
          "host", "connection", "content-length", "transfer-encoding",
          "proxy-connection", "proxy-authorization", "priority", "te",
          "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
          "x-forwarded-port", "x-real-ip", "forwarded", "via"
        ]);
        for (const [k, v] of Object.entries(req.h)) {
          if (!stripSet.has(k.toLowerCase())) headers.set(k, v);
        }
      }
      headers.set("x-relay-hop", "1");
      const fetchOptions = {
        method: (req.m || "GET").toUpperCase(),
        headers,
        redirect: req.r === false ? "manual" : "follow"
      };
      if (req.b) {
        try {
          const binary = decodeBase64ToBytes(req.b);
          fetchOptions.body = binary;
        } catch (err) {
          return json({ e: "invalid_base64" }, 400);
        }
      }
      let resp;
      try {
        resp = await fetch(targetUrl.toString(), fetchOptions);
      } catch (err) {
        return json({ e: "upstream_fetch_failed: " + err.message }, 502);
      }
      const data = new Uint8Array(await resp.arrayBuffer());
      const base64 = encodeBytesToBase64(data);
      const responseHeaders = sanitizeReplyHeaders(resp.headers);
      return json({
        s: resp.status,
        h: responseHeaders,
        b: base64
      });
    } catch (err) {
      return json({ e: String(err) }, 500);
    }
  }
};

async function forwardViaUpstream(req, env, upstreamUrl) {
  const failMode = (env.UPSTREAM_FAIL_MODE || "closed").toLowerCase();
  const timeoutMs = parseInt(env.UPSTREAM_TIMEOUT_MS, 10) || DEFAULT_UPSTREAM_TIMEOUT_MS;
  const authKey = env.UPSTREAM_AUTH_KEY || "";
  let parsed;
  try {
    parsed = new URL(upstreamUrl);
  } catch (_) {
    return upstreamFailure("invalid UPSTREAM_FORWARDER_URL", failMode);
  }
  if (parsed.protocol !== "https:") {
    return upstreamFailure("UPSTREAM_FORWARDER_URL must be https://", failMode);
  }
  if (parsed.hostname.endsWith(WORKER_URL.replace(/^https?:\/\//, ""))) {
    return upstreamFailure("self-forward blocked", failMode);
  }
  if (!authKey) {
    return upstreamFailure("UPSTREAM_AUTH_KEY missing", failMode);
  }
  const payload = {
    u: req.u,
    m: req.m,
    h: req.h,
    b: req.b,
    ct: req.ct,
    r: req.r
  };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(upstreamUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-upstream-auth": authKey
      },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    if (!resp.ok) {
      return upstreamFailure("forwarder status " + resp.status, failMode);
    }
    const body = await resp.text();
    return new Response(body, {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  } catch (err) {
    return upstreamFailure(String(err && err.message || err), failMode);
  } finally {
    clearTimeout(timer);
  }
}

function upstreamFailure(reason, failMode) {
  if (failMode === "open") {
    console.warn("upstream forwarder failed (falling back to direct):", reason);
    return null;
  }
  return json({ e: "upstream forwarder failed: " + reason }, 502);
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" }
  });
}