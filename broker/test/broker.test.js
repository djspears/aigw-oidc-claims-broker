"use strict";
const test = require("node:test");
const assert = require("node:assert");
const http = require("node:http");
const crypto = require("node:crypto");
const { createHandler } = require("../src/server");
const { OidcProvider } = require("../src/oidc");
const { loadKeys } = require("../src/keys");
const { parseConfig } = require("../src/config");

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const decode = (t) => JSON.parse(Buffer.from(t.split(".")[1], "base64url").toString());

function listen(handler) {
  return new Promise((resolve) => {
    const s = http.createServer(handler);
    s.listen(0, "127.0.0.1", () => resolve({ server: s, url: `http://127.0.0.1:${s.address().port}` }));
  });
}

// --- stub IdP: discovery, JWKS, userinfo (claims per subject) -------------------------------------------------
const idpKey = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const idpJwk = { ...idpKey.publicKey.export({ format: "jwk" }), kid: "idp-1", alg: "RS256", use: "sig" };
const otherKey = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const userinfoBySub = {
  "u-1": { sub: "u-1", email: "pat@example.com", tier: "t1", bu: "ops", product: "eo", component: "ai" },
  "u-2": { sub: "u-2", email: "lee@example.com" },                               // no tier
};
let idp;
let userinfoCalls = 0;

function idpToken(claims, { key = idpKey.privateKey, kid = "idp-1", alg = "RS256" } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const payload = { iss: idp.url, aud: "api://aigw", azp: "cli-app", iat: now, exp: now + 600, scope: "openid email profile", ...claims };
  const input = `${b64({ alg, kid, typ: "JWT" })}.${b64(payload)}`;
  return `${input}.${crypto.sign("sha256", Buffer.from(input), key).toString("base64url")}`;
}

// --- broker under test -----------------------------------------------------------------------------------------
let broker;
const brokerKeyPem = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs8", format: "pem" });

function makeConfig(overrides = {}) {
  const cfg = parseConfig(JSON.stringify({
    issuer: idp.url,
    audience: ["api://aigw"],
    allowed_clients: ["cli-app"],
    copy_claims: { tier: "tier", bu: "bu", product: "product", component: "component" },
    required_claims: ["tier"],
    static_claims: { scopes: ["completions.write", "mcp.invoke"] },
    token_ttl_seconds: 3600,
    ...overrides,
  }));
  cfg.brokerIssuer = broker ? broker.url : "http://broker.invalid";
  cfg.brokerAudience = "aigw";
  return cfg;
}

async function exchangeVia(token, cfgOverrides) {
  const deps = { cfg: makeConfig(cfgOverrides), keys: loadKeys({ pem: brokerKeyPem }), provider: new OidcProvider({ issuer: idp.url }) };
  const handler = createHandler(deps);
  const srv = await listen(handler);
  try {
    const r = await fetch(`${srv.url}/token/exchange`, { method: "POST", headers: token ? { Authorization: `Bearer ${token}` } : {} });
    return { status: r.status, body: await r.json(), deps, url: srv.url };
  } finally { srv.server.close(); }
}

test.before(async () => {
  idp = await listen((req, res) => {
    const p = new URL(req.url, "http://x").pathname;
    const json = (s, b) => { res.writeHead(s, { "Content-Type": "application/json" }); res.end(JSON.stringify(b)); };
    if (p === "/.well-known/openid-configuration") return json(200, { issuer: idp.url, jwks_uri: `${idp.url}/keys`, userinfo_endpoint: `${idp.url}/userinfo` });
    if (p === "/keys") return json(200, { keys: [idpJwk] });
    if (p === "/userinfo") {
      userinfoCalls++;
      const tok = (req.headers.authorization || "").replace(/^Bearer /, "");
      try { return json(200, userinfoBySub[decode(tok).sub] || { sub: decode(tok).sub }); } catch { return json(401, { error: "invalid_token" }); }
    }
    json(404, {});
  });
  broker = await listen((req, res) => res.end());   // placeholder URL for brokerIssuer
});
test.after(() => { idp.server.close(); broker.server.close(); });

test("exchanges a valid token and copies userinfo claims into a flat gateway JWT", async () => {
  const r = await exchangeVia(idpToken({ sub: "u-1" }));
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const c = decode(r.body.access_token);
  assert.deepEqual([c.tier, c.bu, c.product, c.component], ["t1", "ops", "eo", "ai"]);
  assert.equal(c.email_id, "pat@example.com");
  assert.deepEqual(c.scopes, ["completions.write", "mcp.invoke"]);
  assert.equal(c.scope, undefined, "no OIDC-style scope claim (it would hide scopes at the gateway)");
  assert.equal(c.sub, "u-1");
  assert.equal(c.iss, broker.url);
  assert.equal(c.aud, "aigw");
  assert.ok(c.exp - c.iat <= 600, "capped at the upstream token's exp");
});

test("minted token verifies against the broker's own JWKS", async () => {
  const r = await exchangeVia(idpToken({ sub: "u-1" }));
  const jwks = r.deps.keys.jwks();
  const [h, p, s] = r.body.access_token.split(".");
  const header = JSON.parse(Buffer.from(h, "base64url"));
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  assert.ok(jwk, "kid published");
  assert.ok(crypto.verify("sha256", Buffer.from(`${h}.${p}`), crypto.createPublicKey({ key: jwk, format: "jwk" }), Buffer.from(s, "base64url")));
  assert.equal(jwk.d, undefined, "no private material in JWKS");
});

test("refuses when a required claim is missing (no claimless token is ever minted)", async () => {
  const r = await exchangeVia(idpToken({ sub: "u-2" }));
  assert.equal(r.status, 403);
  assert.deepEqual(r.body, { error: "missing_required_claims", missing: ["tier"] });
});

test("rejects a token signed by another key", async () => {
  const r = await exchangeVia(idpToken({ sub: "u-1" }, { key: otherKey.privateKey }));
  assert.equal(r.status, 401);
});

test("rejects expired, wrong-issuer, wrong-audience and alg-none tokens", async () => {
  const now = Math.floor(Date.now() / 1000);
  assert.equal((await exchangeVia(idpToken({ sub: "u-1", exp: now - 120 }))).status, 401);
  assert.equal((await exchangeVia(idpToken({ sub: "u-1", iss: "https://evil.example" }))).status, 401);
  assert.equal((await exchangeVia(idpToken({ sub: "u-1", aud: "someone-else" }))).status, 401);
  const none = `${b64({ alg: "none" })}.${b64({ iss: idp.url, sub: "u-1", exp: now + 600 })}.`;
  assert.equal((await exchangeVia(none)).status, 401);
});

test("enforces the client allow-list", async () => {
  const r = await exchangeVia(idpToken({ sub: "u-1", azp: "other-app" }));
  assert.equal(r.status, 403);
  assert.equal(r.body.error, "forbidden_client");
});

test("missing bearer token -> 401", async () => {
  const r = await exchangeVia(null);
  assert.equal(r.status, 401);
});

test("claims can be renamed and read from the access token when userinfo is off", async () => {
  const r = await exchangeVia(idpToken({ sub: "u-9", user_tier: "gold", email: "x@example.com" }),
    { userinfo: false, copy_claims: { tier: "user_tier" }, required_claims: ["tier"] });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(decode(r.body.access_token).tier, "gold");
});

test("config validation", () => {
  assert.throws(() => parseConfig(JSON.stringify({ issuer: "https://i", static_claims: { scope: "x" } })), /scopes/);
  assert.throws(() => parseConfig(JSON.stringify({ issuer: "https://i", copy_claims: { sub: "x" } })), /set by the broker/);
  assert.throws(() => parseConfig(JSON.stringify({ issuer: "https://i", required_claims: ["tier"] })), /copy_claims/);
  assert.throws(() => parseConfig(JSON.stringify({})), /issuer/);
});

test("JWKS and discovery endpoints", async () => {
  const deps = { cfg: makeConfig(), keys: loadKeys({ pem: brokerKeyPem }), provider: new OidcProvider({ issuer: idp.url }) };
  const srv = await listen(createHandler(deps));
  try {
    const jwks = await (await fetch(`${srv.url}/.well-known/jwks.json`)).json();
    assert.equal(jwks.keys.length, 1);
    assert.equal(jwks.keys[0].kty, "RSA");
    const disc = await (await fetch(`${srv.url}/.well-known/openid-configuration`)).json();
    assert.equal(disc.jwks_uri, `${broker.url}/.well-known/jwks.json`);
    assert.equal((await fetch(`${srv.url}/healthz`)).status, 200);
  } finally { srv.server.close(); }
});
