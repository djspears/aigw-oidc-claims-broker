"use strict";
// HTTP front end. Endpoints:
//   POST /token/exchange              Authorization: Bearer <IdP access token>  -> {access_token, expires_in, ...}
//   GET  /.well-known/jwks.json       broker public keys (configure this URL in the AI Gateway JWKS list)
//   GET  /.well-known/openid-configuration   issuer + jwks_uri
//   GET  /healthz
const http = require("node:http");
const { OidcProvider } = require("./oidc");
const { loadKeys } = require("./keys");
const { loadConfig } = require("./config");
const { exchange, BrokerError } = require("./broker");

function send(res, status, body, headers = {}) {
  const raw = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(raw),
    "X-Content-Type-Options": "nosniff", ...headers });
  res.end(raw);
}

function createHandler(deps) {
  const base = deps.cfg.brokerIssuer.replace(/\/+$/, "");
  return async (req, res) => {
    const path = new URL(req.url || "/", "http://localhost").pathname;
    try {
      if (path === "/healthz") return send(res, 200, { status: "ok" });
      if (path === "/.well-known/jwks.json") {
        if (req.method !== "GET") return send(res, 405, { error: "method_not_allowed" });
        return send(res, 200, deps.keys.jwks(), { "Cache-Control": "public, max-age=300" });
      }
      if (path === "/.well-known/openid-configuration") {
        return send(res, 200, { issuer: deps.cfg.brokerIssuer, jwks_uri: `${base}/.well-known/jwks.json`,
          token_endpoint: `${base}/token/exchange`, id_token_signing_alg_values_supported: [deps.keys.active.alg] });
      }
      if (path === "/token/exchange") {
        if (req.method !== "POST") return send(res, 405, { error: "method_not_allowed" });
        req.resume();                                                      // body is ignored
        const auth = req.headers.authorization || "";
        if (!/^bearer\s+/i.test(auth)) return send(res, 401, { error: "missing_bearer_token" }, { "WWW-Authenticate": "Bearer" });
        const { response, audit } = await exchange(auth.replace(/^bearer\s+/i, "").trim(), deps);
        console.log(JSON.stringify({ event: "exchange", ...audit }));           // never logs tokens
        return send(res, 200, response, { "Cache-Control": "no-store", Pragma: "no-cache" });
      }
      return send(res, 404, { error: "not_found" });
    } catch (e) {
      if (e instanceof BrokerError) {
        console.warn(JSON.stringify({ event: "exchange_refused", error: e.code, detail: e.detail }));
        return send(res, e.status, { error: e.code, ...(e.code === "missing_required_claims" ? { missing: e.detail } : {}) });
      }
      console.error("internal error", e);
      return send(res, 500, { error: "internal_error" });
    }
  };
}

function buildDeps(env = process.env) {
  const cfg = loadConfig(env);
  const keys = loadKeys({ dir: env.SIGNING_KEY_DIR, pem: env.SIGNING_KEY_PEM, activeKid: env.ACTIVE_KID });
  const provider = new OidcProvider({ issuer: cfg.issuer });
  return { cfg, keys, provider };
}

if (require.main === module) {
  const deps = buildDeps();
  const port = Number(process.env.PORT || 8080);
  const server = http.createServer(createHandler(deps));
  server.headersTimeout = 15000;
  server.requestTimeout = 30000;
  server.listen(port, () => console.log(JSON.stringify({ event: "listening", port, idp: deps.cfg.issuer,
    issuer: deps.cfg.brokerIssuer, kid: deps.keys.active.kid, copy: Object.keys(deps.cfg.copyClaims), required: deps.cfg.requiredClaims })));
  process.on("SIGTERM", () => server.close(() => process.exit(0)));
}

module.exports = { createHandler, buildDeps };
