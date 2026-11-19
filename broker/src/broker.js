"use strict";
// Token exchange: verified IdP access token + the IdP's /userinfo  ->  short-lived gateway JWT with flat claims.
const crypto = require("node:crypto");
const { VerifyError } = require("./oidc");

class BrokerError extends Error {
  constructor(status, code, detail) { super(code); this.status = status; this.code = code; this.detail = detail; }
}

const b64url = (s) => Buffer.from(s).toString("base64url");

// deps: { provider (OidcProvider), keys (loadKeys result), cfg (loadConfig result), now? }
async function exchange(idpToken, deps) {
  const { provider, keys, cfg } = deps;
  const nowMs = (deps.now || Date.now)();
  let upstream;
  try {
    upstream = await provider.verify(idpToken, { algorithms: cfg.algorithms, audience: cfg.audience, allowedClients: cfg.allowedClients });
  } catch (e) {
    if (e instanceof VerifyError) throw new BrokerError(e.code === "forbidden_client" ? 403 : 401, e.code, e.message);
    throw new BrokerError(502, "idp_unavailable", e.message);
  }

  let info = {};
  if (cfg.useUserinfo) {
    try {
      info = await provider.userinfo(idpToken, [upstream.sub, upstream.uid, upstream.oid]);
    } catch (e) {
      if (e instanceof VerifyError) throw new BrokerError(401, e.code, e.message);
      throw new BrokerError(502, "userinfo_unavailable", e.message);
    }
  }

  const lookup = (name) => (info[name] !== undefined && info[name] !== null && info[name] !== "" ? info[name] : upstream[name]);
  const copied = {};
  for (const [out, src] of Object.entries(cfg.copyClaims)) {
    const v = lookup(src);
    if (v !== undefined && v !== null && v !== "") copied[out] = v;
  }
  const missing = cfg.requiredClaims.filter((r) => copied[r] === undefined);
  // Refuse instead of minting a token that would silently lose the attributes (and the budget/guardrail decisions).
  if (missing.length) throw new BrokerError(403, "missing_required_claims", missing);

  const identity = cfg.identityClaims.map(lookup).find((v) => typeof v === "string" && v.includes("@"));
  const iat = Math.floor(nowMs / 1000);
  let exp = iat + cfg.ttlSeconds;
  if (cfg.capToUpstreamExp && typeof upstream.exp === "number") exp = Math.min(exp, upstream.exp);
  if (exp <= iat) throw new BrokerError(401, "invalid_token", "upstream token expires now");

  const claims = {
    ...cfg.staticClaims,
    ...copied,
    ...(identity ? { email_id: identity } : {}),
    iss: cfg.brokerIssuer,
    aud: cfg.brokerAudience,
    sub: upstream.sub,
    iat,
    exp,
    jti: crypto.randomUUID(),
    idp_iss: upstream.iss,
  };
  const header = { alg: keys.active.alg, typ: "JWT", kid: keys.active.kid };
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  return {
    response: { access_token: `${input}.${keys.sign(input)}`, token_type: "Bearer", expires_in: exp - iat,
      issued_token_type: "urn:ietf:params:oauth:token-type:jwt" },
    audit: { sub: upstream.sub, client: upstream.azp || upstream.client_id || upstream.cid, claims: Object.keys(copied), exp },
  };
}

module.exports = { exchange, BrokerError };
