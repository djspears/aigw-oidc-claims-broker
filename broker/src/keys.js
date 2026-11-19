"use strict";
// Broker signing keys: PEM private keys (RSA or EC P-256) loaded from a directory or one env var.
// kid = RFC 7638 JWK thumbprint, so a new key gets a new kid. Every loaded key is published in the JWKS;
// the newest file (or ACTIVE_KID) signs. Keep the old key file for one token lifetime when rotating.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

function thumbprint(jwk) {
  const members = jwk.kty === "RSA" ? { e: jwk.e, kty: jwk.kty, n: jwk.n } : { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  return crypto.createHash("sha256").update(JSON.stringify(members)).digest("base64url");
}

function keyFromPem(pem, mtimeMs = 0) {
  const priv = crypto.createPrivateKey(pem);
  const pub = crypto.createPublicKey(priv).export({ format: "jwk" });
  let alg;
  if (pub.kty === "RSA") alg = "RS256";
  else if (pub.kty === "EC" && pub.crv === "P-256") alg = "ES256";
  else throw new Error(`unsupported signing key type ${pub.kty}/${pub.crv || ""} (use RSA 2048+ or EC P-256)`);
  if (pub.kty === "RSA" && Buffer.from(pub.n, "base64url").length * 8 < 2048) throw new Error("RSA signing key must be at least 2048 bits");
  const kid = thumbprint(pub);
  return { kid, alg, priv, mtimeMs, jwk: { ...pub, kid, alg, use: "sig" } };
}

function loadKeys({ dir, pem, activeKid } = {}) {
  const keys = [];
  if (pem) keys.push(keyFromPem(pem));
  if (dir) {
    for (const f of fs.readdirSync(dir).filter((n) => !n.startsWith(".")).sort()) {
      const p = path.join(dir, f);
      if (!fs.statSync(p).isFile()) continue;
      const text = fs.readFileSync(p, "utf8");
      if (!text.includes("PRIVATE KEY")) continue;
      keys.push(keyFromPem(text, fs.statSync(p).mtimeMs));
    }
  }
  if (!keys.length) throw new Error("no signing key: set SIGNING_KEY_DIR or SIGNING_KEY_PEM");
  const active = activeKid ? keys.find((k) => k.kid === activeKid) : [...keys].sort((a, b) => b.mtimeMs - a.mtimeMs)[0];
  if (!active) throw new Error(`ACTIVE_KID ${activeKid} not found among loaded keys`);
  return {
    active,
    jwks: () => ({ keys: keys.map((k) => k.jwk) }),
    sign(input) {
      const sig = active.alg === "ES256"
        ? crypto.sign("sha256", Buffer.from(input), { key: active.priv, dsaEncoding: "ieee-p1363" })
        : crypto.sign("sha256", Buffer.from(input), active.priv);
      return sig.toString("base64url");
    },
  };
}

module.exports = { loadKeys, keyFromPem, thumbprint };
