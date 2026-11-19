"use strict";
// Broker configuration: a JSON policy (BROKER_CONFIG_FILE or BROKER_CONFIG_JSON) plus a few env settings.
const fs = require("node:fs");

const RESERVED = new Set(["iss", "sub", "aud", "exp", "iat", "nbf", "jti"]);

function parseConfig(text) {
  const c = JSON.parse(text);
  const fail = (m) => { throw new Error(`broker config: ${m}`); };
  if (!c.issuer || !/^https?:\/\//.test(c.issuer)) fail("`issuer` (the IdP issuer URL) is required");
  const out = {
    issuer: c.issuer,
    audience: c.audience ? [].concat(c.audience) : [],
    allowedClients: c.allowed_clients ? [].concat(c.allowed_clients) : [],
    algorithms: c.algorithms ? [].concat(c.algorithms) : ["RS256", "ES256"],
    useUserinfo: c.userinfo !== false,
    // output claim name -> source claim name (looked up in userinfo first, then in the access token)
    copyClaims: c.copy_claims || {},
    requiredClaims: c.required_claims || [],
    identityClaims: c.identity_claims || ["email", "preferred_username", "upn"],
    staticClaims: c.static_claims || {},
    ttlSeconds: Number(c.token_ttl_seconds || 3600),
    capToUpstreamExp: c.cap_to_upstream_exp !== false,
  };
  if (typeof out.copyClaims !== "object" || Array.isArray(out.copyClaims)) fail("`copy_claims` must be an object {output: source}");
  for (const k of [...Object.keys(out.copyClaims), ...Object.keys(out.staticClaims)]) {
    if (RESERVED.has(k)) fail(`claim \`${k}\` is set by the broker and can't be configured`);
  }
  for (const r of out.requiredClaims) if (!(r in out.copyClaims)) fail(`required claim \`${r}\` must also be in copy_claims`);
  if (!(out.ttlSeconds >= 60 && out.ttlSeconds <= 86400)) fail("`token_ttl_seconds` must be 60..86400");
  if ("scope" in out.staticClaims) fail("use `scopes` (array), not `scope`: the gateway reads `scope` first and an OIDC-style `scope` hides `scopes`");
  return out;
}

function loadConfig(env = process.env) {
  const text = env.BROKER_CONFIG_FILE ? fs.readFileSync(env.BROKER_CONFIG_FILE, "utf8") : env.BROKER_CONFIG_JSON;
  if (!text) throw new Error("set BROKER_CONFIG_FILE or BROKER_CONFIG_JSON");
  const cfg = parseConfig(text);
  cfg.brokerIssuer = env.BROKER_ISSUER || "";
  cfg.brokerAudience = env.BROKER_AUDIENCE || "aigw";
  if (!cfg.brokerIssuer) throw new Error("set BROKER_ISSUER (this broker's public base URL, used as the `iss` of minted tokens)");
  return cfg;
}

module.exports = { parseConfig, loadConfig };
