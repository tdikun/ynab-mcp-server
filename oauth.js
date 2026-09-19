// Minimal single-user OAuth 2.1 authorization server for http.js, so hosts
// that cannot send a static Authorization header (claude.ai connectors) can
// still connect. The only "user" is whoever knows MCP_AUTH_TOKEN: /authorize
// shows a page asking for it, then issues a PKCE-bound authorization code.
//
// Everything is stateless. Client ids, codes, access tokens, and refresh
// tokens are HMAC-signed payloads keyed from MCP_AUTH_TOKEN, so they survive
// redeploys and rotating MCP_AUTH_TOKEN revokes all of them at once. The one
// piece of memory is the used-code set that makes codes single-use within
// their 60-second lifetime.

import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";

const CODE_TTL_S = 60;
const ACCESS_TTL_S = 60 * 60;
const REFRESH_TTL_S = 90 * 24 * 60 * 60;
const MAX_FORM_BYTES = 64 * 1024;
const MAX_FAILURES = 10;
const FAILURE_WINDOW_MS = 15 * 60 * 1000;

const b64u = (buf) => Buffer.from(buf).toString("base64url");
const now = () => Math.floor(Date.now() / 1000);

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

function safeEqual(a, b) {
  const ha = createHash("sha256").update(a).digest();
  const hb = createHash("sha256").update(b).digest();
  return timingSafeEqual(ha, hb);
}

function isAllowedRedirectUri(uri) {
  try {
    const u = new URL(uri);
    if (u.hash) return false;
    if (u.protocol === "https:") return true;
    return u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1");
  } catch {
    return false;
  }
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_FORM_BYTES) throw new Error("body too large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export function createOAuth({ secret, baseUrl }) {
  const key = createHash("sha256").update(`ynab-mcp-oauth-v1:${secret}`).digest();
  const usedCodes = new Map(); // jti -> exp
  let failures = [];

  function sign(payload) {
    const body = b64u(JSON.stringify(payload));
    return `${body}.${b64u(createHmac("sha256", key).update(body).digest())}`;
  }

  function verify(token, typ) {
    if (typeof token !== "string") return null;
    const [body, sig, extra] = token.split(".");
    if (!body || !sig || extra !== undefined) return null;
    const expected = b64u(createHmac("sha256", key).update(body).digest());
    if (!safeEqual(sig, expected)) return null;
    try {
      const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
      if (payload.typ !== typ) return null;
      if (payload.exp && payload.exp < now()) return null;
      return payload;
    } catch {
      return null;
    }
  }

  function json(res, status, body) {
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(JSON.stringify(body));
  }

  function oauthError(res, status, error, description) {
    json(res, status, { error, error_description: description });
  }

  function page(res, status, inner) {
    res.writeHead(status, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https: http://localhost:* http://127.0.0.1:*; frame-ancestors 'none'",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
    });
    res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>YNAB MCP sign-in</title><style>
body{font:16px/1.5 system-ui,sans-serif;background:#f4f5f7;color:#1c1f26;margin:0;padding:16px;display:grid;place-items:center;min-height:100vh;box-sizing:border-box}
main{background:#fff;border-radius:12px;padding:28px;max-width:420px;width:100%;box-shadow:0 2px 12px rgba(0,0,0,.08);box-sizing:border-box}
h1{font-size:20px;margin:0 0 8px}p{margin:0 0 16px;color:#4a5060}code{word-break:break-all}
input[type=password]{width:100%;padding:10px;font:inherit;border:1px solid #c5c9d3;border-radius:8px;box-sizing:border-box;margin-bottom:16px}
button{width:100%;padding:11px;font:inherit;font-weight:600;border:0;border-radius:8px;background:#3b5bdb;color:#fff;cursor:pointer}
.err{color:#c92a2a}
@media (prefers-color-scheme:dark){body{background:#14161b;color:#e9ecf2}main{background:#1e2128}p{color:#a5acba}input[type=password]{background:#14161b;color:inherit;border-color:#3a3f4b}}
</style></head><body><main>${inner}</main></body></html>`);
  }

  function parseAuthorizeParams(params) {
    const client = verify(params.get("client_id"), "client");
    if (!client) return { error: "Unknown client. Remove and re-add the connector." };
    const redirectUri = params.get("redirect_uri") || "";
    if (!client.redirect_uris.includes(redirectUri)) return { error: "redirect_uri is not registered for this client." };
    if (params.get("response_type") !== "code") return { error: "response_type must be code." };
    const challenge = params.get("code_challenge") || "";
    if (!challenge || (params.get("code_challenge_method") || "plain") !== "S256") return { error: "PKCE with S256 is required." };
    return { client, redirectUri, challenge, state: params.get("state") || "", clientId: params.get("client_id") };
  }

  function renderConsent(res, status, parsed, message) {
    const hidden = Object.entries({
      client_id: parsed.clientId,
      redirect_uri: parsed.redirectUri,
      response_type: "code",
      code_challenge: parsed.challenge,
      code_challenge_method: "S256",
      state: parsed.state,
    }).map(([k, v]) => `<input type="hidden" name="${k}" value="${escapeHtml(v)}">`).join("");
    page(res, status, `<h1>Connect to YNAB MCP</h1>
<p><strong>${escapeHtml(parsed.client.client_name || "An application")}</strong> wants access to this server. It will return to <code>${escapeHtml(new URL(parsed.redirectUri).origin)}</code>.</p>
${message ? `<p class="err">${escapeHtml(message)}</p>` : ""}
<form method="post" action="/authorize">${hidden}
<label for="s">Server secret (MCP_AUTH_TOKEN)</label>
<input id="s" type="password" name="secret" autocomplete="off" autofocus required>
<button type="submit">Allow access</button></form>`);
  }

  function issueTokens(res, clientId) {
    const t = now();
    json(res, 200, {
      access_token: sign({ typ: "at", cid: clientId, exp: t + ACCESS_TTL_S, jti: randomUUID() }),
      token_type: "Bearer",
      expires_in: ACCESS_TTL_S,
      refresh_token: sign({ typ: "rt", cid: clientId, exp: t + REFRESH_TTL_S, jti: randomUUID() }),
    });
  }

  async function handleRegister(req, res) {
    let body;
    try {
      body = JSON.parse(await readBody(req));
    } catch {
      return oauthError(res, 400, "invalid_client_metadata", "Body must be JSON.");
    }
    const uris = body?.redirect_uris;
    if (!Array.isArray(uris) || uris.length === 0 || uris.length > 10 || !uris.every((u) => typeof u === "string" && isAllowedRedirectUri(u))) {
      return oauthError(res, 400, "invalid_redirect_uri", "redirect_uris must be https or localhost URLs.");
    }
    const clientName = typeof body.client_name === "string" ? body.client_name.slice(0, 100) : undefined;
    const issuedAt = now();
    json(res, 201, {
      client_id: sign({ typ: "client", redirect_uris: uris, client_name: clientName, iat: issuedAt }),
      client_id_issued_at: issuedAt,
      client_name: clientName,
      redirect_uris: uris,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    });
  }

  async function handleAuthorize(req, res, url) {
    if (req.method === "GET") {
      const parsed = parseAuthorizeParams(url.searchParams);
      if (parsed.error) return page(res, 400, `<h1>Cannot authorize</h1><p class="err">${escapeHtml(parsed.error)}</p>`);
      return renderConsent(res, 200, parsed);
    }
    if (req.method !== "POST") return res.writeHead(405, { allow: "GET, POST" }).end();

    let form;
    try {
      form = new URLSearchParams(await readBody(req));
    } catch {
      return page(res, 400, `<h1>Cannot authorize</h1><p class="err">Invalid form.</p>`);
    }
    const parsed = parseAuthorizeParams(form);
    if (parsed.error) return page(res, 400, `<h1>Cannot authorize</h1><p class="err">${escapeHtml(parsed.error)}</p>`);

    failures = failures.filter((t) => t > Date.now() - FAILURE_WINDOW_MS);
    if (failures.length >= MAX_FAILURES) {
      return page(res, 429, `<h1>Too many attempts</h1><p class="err">Sign-in is locked for a few minutes.</p>`);
    }
    if (!safeEqual(form.get("secret") || "", secret)) {
      failures.push(Date.now());
      return renderConsent(res, 401, parsed, "That secret is not correct.");
    }

    const code = sign({ typ: "code", cid: parsed.clientId, ru: parsed.redirectUri, cc: parsed.challenge, exp: now() + CODE_TTL_S, jti: randomUUID() });
    const target = new URL(parsed.redirectUri);
    target.searchParams.set("code", code);
    if (parsed.state) target.searchParams.set("state", parsed.state);
    res.writeHead(302, { location: target.toString(), "cache-control": "no-store" }).end();
  }

  async function handleToken(req, res) {
    let form;
    try {
      form = new URLSearchParams(await readBody(req));
    } catch {
      return oauthError(res, 400, "invalid_request", "Invalid body.");
    }
    const clientId = form.get("client_id") || "";
    if (!verify(clientId, "client")) return oauthError(res, 401, "invalid_client", "Unknown client.");

    const grant = form.get("grant_type");
    if (grant === "authorization_code") {
      const code = verify(form.get("code"), "code");
      if (!code || code.cid !== clientId || code.ru !== (form.get("redirect_uri") || code.ru)) {
        return oauthError(res, 400, "invalid_grant", "Code is invalid or expired.");
      }
      const challenge = b64u(createHash("sha256").update(form.get("code_verifier") || "").digest());
      if (!safeEqual(challenge, code.cc)) return oauthError(res, 400, "invalid_grant", "PKCE verification failed.");
      for (const [jti, exp] of usedCodes) if (exp < now()) usedCodes.delete(jti);
      if (usedCodes.has(code.jti)) return oauthError(res, 400, "invalid_grant", "Code was already used.");
      usedCodes.set(code.jti, code.exp);
      return issueTokens(res, clientId);
    }
    if (grant === "refresh_token") {
      const refresh = verify(form.get("refresh_token"), "rt");
      if (!refresh || refresh.cid !== clientId) return oauthError(res, 400, "invalid_grant", "Refresh token is invalid or expired.");
      return issueTokens(res, clientId);
    }
    return oauthError(res, 400, "unsupported_grant_type", "Use authorization_code or refresh_token.");
  }

  const metadata = {
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/authorize`,
    token_endpoint: `${baseUrl}/token`,
    registration_endpoint: `${baseUrl}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
  };
  const resourceMetadata = {
    resource: `${baseUrl}/mcp`,
    authorization_servers: [baseUrl],
    bearer_methods_supported: ["header"],
  };

  return {
    challengeHeader: `Bearer resource_metadata="${baseUrl}/.well-known/oauth-protected-resource"`,
    isValidAccessToken: (token) => !!verify(token, "at"),
    // Returns true when the request was an OAuth route and has been answered.
    async handle(req, res, url) {
      const p = url.pathname;
      if (p === "/.well-known/oauth-authorization-server") return json(res, 200, metadata), true;
      if (p === "/.well-known/oauth-protected-resource" || p === "/.well-known/oauth-protected-resource/mcp") return json(res, 200, resourceMetadata), true;
      if (p === "/register" && req.method === "POST") return await handleRegister(req, res), true;
      if (p === "/authorize") return await handleAuthorize(req, res, url), true;
      if (p === "/token" && req.method === "POST") return await handleToken(req, res), true;
      return false;
    },
  };
}
