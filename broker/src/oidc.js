"use strict";
// OIDC client side of the broker: discovery, JWKS, access-token verification and /userinfo.
// Node's built-in crypto only (no dependencies).
const crypto = require("node:crypto");

const ALGS = {
  RS256: { hash: "sha256" }, RS384: { hash: "sha384" }, RS512: { hash: "sha512" },
  PS256: { hash: "sha256", pss: 32 }, PS384: { hash: "sha384", pss: 48 }, PS512: { hash: "sha512", pss: 64 },
  ES256: { hash: "sha256", ec: true }, ES384: { hash: "sha384", ec: true }, ES512: { hash: "sha512", ec: true },
};

class VerifyError extends Error {
  constructor(code, message) { super(message || code); this.code = code; }
}

const b64urlJson = (part) => JSON.parse(Buffer.from(part, "base64url").toString("utf8"));

async function getJson(url, { headers = {}, timeoutMs = 10000, fetchImpl = fetch } = {}) {
  const res = await fetchImpl(url, { headers: { Accept: "application/json", ...headers }, signal: AbortSignal.timeout(timeoutMs) });
  const text = await res.text();
  let body;
  try { body = text ? JSON.parse(text) : null; } catch { body = null; }
  return { status: res.status, body, contentType: res.headers.get("content-type") || "" };
}

class OidcProvider {
  // opts: { issuer, fetchImpl, discoveryTtlMs, jwksTtlMs, now }
  constructor(opts) {
    this.issuer = opts.issuer.replace(/\/+$/, "");
    this.fetchImpl = opts.fetchImpl || fetch;
    this.discoveryTtlMs = opts.discoveryTtlMs ?? 3600_000;
    this.jwksTtlMs = opts.jwksTtlMs ?? 600_000;
    this.now = opts.now || (() => Date.now());
    this.discovery = null;
    this.jwks = null;
    this.lastForcedJwksFetch = 0;
  }

  async metadata() {
    if (this.discovery && this.now() - this.discovery.at < this.discoveryTtlMs) return this.discovery.doc;
    const { status, body } = await getJson(`${this.issuer}/.well-known/openid-configuration`, { fetchImpl: this.fetchImpl });
    if (status !== 200 || !body || !body.jwks_uri) throw new Error(`OIDC discovery failed for ${this.issuer} (HTTP ${status})`);
    // The configured issuer is the trust anchor: the discovery document must agree with it.
    if (String(body.issuer).replace(/\/+$/, "") !== this.issuer) {
      throw new Error(`discovery issuer mismatch: configured ${this.issuer}, document says ${body.issuer}`);
    }
    this.discovery = { at: this.now(), doc: body };
    return body;
  }

  async keys(force = false) {
    if (!force && this.jwks && this.now() - this.jwks.at < this.jwksTtlMs) return this.jwks.keys;
    const { jwks_uri } = await this.metadata();
    const { status, body } = await getJson(jwks_uri, { fetchImpl: this.fetchImpl });
    if (status !== 200 || !body || !Array.isArray(body.keys)) throw new Error(`JWKS fetch failed (HTTP ${status})`);
    this.jwks = { at: this.now(), keys: body.keys };
    return body.keys;
  }

  async findKey(kid, alg) {
    const pick = (keys) => keys.find((k) => (kid ? k.kid === kid : true) && (!k.use || k.use === "sig") && (!k.alg || k.alg === alg));
    let key = pick(await this.keys());
    // Unknown kid: the IdP may have rotated keys. Refetch at most once a minute.
    if (!key && this.now() - this.lastForcedJwksFetch > 60_000) {
      this.lastForcedJwksFetch = this.now();
      key = pick(await this.keys(true));
    }
    return key;
  }

  // Verifies signature, iss, exp/nbf, optional aud and client allow-list. Returns the payload.
  async verify(token, { algorithms, audience, allowedClients, leewaySec = 30 }) {
    const parts = String(token).split(".");
    if (parts.length !== 3) throw new VerifyError("invalid_token", "not a JWT");
    let header, payload;
    try { header = b64urlJson(parts[0]); payload = b64urlJson(parts[1]); } catch { throw new VerifyError("invalid_token", "malformed JWT"); }
    const alg = header.alg;
    if (!ALGS[alg] || !algorithms.includes(alg)) throw new VerifyError("invalid_token", `algorithm not allowed: ${alg}`);
    const jwk = await this.findKey(header.kid, alg);
    if (!jwk) throw new VerifyError("invalid_token", "no matching signing key");
    const spec = ALGS[alg];
    const keyObj = crypto.createPublicKey({ key: jwk, format: "jwk" });
    const verifyKey = spec.pss ? { key: keyObj, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: spec.pss }
      : spec.ec ? { key: keyObj, dsaEncoding: "ieee-p1363" } : keyObj;
    const ok = crypto.verify(spec.hash, Buffer.from(`${parts[0]}.${parts[1]}`), verifyKey, Buffer.from(parts[2], "base64url"));
    if (!ok) throw new VerifyError("invalid_token", "bad signature");

    const now = Math.floor(this.now() / 1000);
    if (String(payload.iss || "").replace(/\/+$/, "") !== this.issuer) throw new VerifyError("invalid_token", "issuer mismatch");
    if (typeof payload.exp !== "number" || payload.exp + leewaySec < now) throw new VerifyError("invalid_token", "token expired");
    if (typeof payload.nbf === "number" && payload.nbf - leewaySec > now) throw new VerifyError("invalid_token", "token not yet valid");
    if (audience && audience.length) {
      const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!aud.some((a) => audience.includes(a))) throw new VerifyError("invalid_token", "audience mismatch");
    }
    if (allowedClients && allowedClients.length) {
      const client = payload.azp || payload.client_id || payload.cid;
      if (!allowedClients.includes(client)) throw new VerifyError("forbidden_client", "client not allowed");
    }
    return payload;
  }

  // Calls the IdP's userinfo endpoint with the (already verified) access token.
  // expectedSub: a list of acceptable subjects (token sub plus IdP user-id claims such as Okta `uid` or Entra `oid`).
  async userinfo(token, expectedSub) {
    const { userinfo_endpoint } = await this.metadata();
    if (!userinfo_endpoint) throw new Error("IdP does not advertise a userinfo_endpoint");
    const { status, body, contentType } = await getJson(userinfo_endpoint, { headers: { Authorization: `Bearer ${token}` }, fetchImpl: this.fetchImpl });
    if (status === 401 || status === 403) throw new VerifyError("userinfo_denied", `userinfo returned ${status}`);
    if (status !== 200 || !body || typeof body !== "object") {
      throw new Error(`userinfo failed (HTTP ${status}, ${contentType.split(";")[0] || "no content type"}); signed/encrypted userinfo is not supported`);
    }
    // OIDC Core 5.3.2: the userinfo sub must match the token's sub.
    const accepted = (Array.isArray(expectedSub) ? expectedSub : [expectedSub]).filter(Boolean);
    if (accepted.length && body.sub && !accepted.includes(body.sub)) throw new VerifyError("invalid_token", "userinfo sub mismatch");
    return body;
  }
}

module.exports = { OidcProvider, VerifyError, ALGS };
