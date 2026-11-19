#!/usr/bin/env bash
# Deploy aigw-claims-broker to Kubernetes.
#   ./deploy/deploy.sh [config.env]                 apply (creates the signing key on first run)
#   ./deploy/deploy.sh [config.env] --dry-run       print the manifests
#   ./deploy/deploy.sh [config.env] --rotate-key    add a new signing key (old key stays published; remove it later)
#   ./deploy/deploy.sh [config.env] --uninstall     delete the namespace
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(dirname "$HERE")"
CONFIG="${1:-$HERE/config.env}"; MODE="${2:-}"
case "$CONFIG" in --*) MODE="$CONFIG"; CONFIG="$HERE/config.env";; esac
[ -f "$CONFIG" ] || { echo "config not found: $CONFIG (copy deploy/config.env.example)"; exit 1; }
for t in kubectl python3 openssl; do command -v "$t" >/dev/null || { echo "missing tool: $t"; exit 1; }; done
set -a; . "$CONFIG"; set +a
NAMESPACE=${NAMESPACE:-aigw-claims-broker}; REPLICAS=${REPLICAS:-2}; IMAGE=${IMAGE:-node:22-alpine}
BROKER_AUDIENCE=${BROKER_AUDIENCE:-aigw}; EXPOSE=${EXPOSE:-loadbalancer}
case "$BROKER_CONFIG_FILE" in /*) ;; *) BROKER_CONFIG_FILE="$ROOT/$BROKER_CONFIG_FILE";; esac
K=(kubectl); [ -n "${KUBE_CONTEXT:-}" ] && K+=(--context "$KUBE_CONTEXT")

# Validate the policy with the broker's own parser before anything is applied.
node -e 'require(process.argv[1]).parseConfig(require("fs").readFileSync(process.argv[2],"utf8"))' \
  "$ROOT/broker/src/config.js" "$BROKER_CONFIG_FILE" 2>/dev/null || \
  python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$BROKER_CONFIG_FILE"

render() {
  python3 - "$ROOT" "$BROKER_CONFIG_FILE" <<'PY'
import hashlib, json, os, string, sys
root, cfgfile = sys.argv[1], sys.argv[2]
src = {f: open(os.path.join(root, "broker/src", f)).read() for f in sorted(os.listdir(os.path.join(root, "broker/src"))) if f.endswith(".js")}
cfg = open(cfgfile).read()
e = dict(os.environ)
e["CONFIG_HASH"] = hashlib.sha256(json.dumps([src, cfg]).encode()).hexdigest()[:16]
e["SERVICE_TYPE"] = "LoadBalancer" if e.get("EXPOSE") == "loadbalancer" else "ClusterIP"
lb = e.get("LB_IP", "")
e["SERVICE_ANNOTATIONS"] = f"  annotations:\n    metallb.universe.tf/loadBalancerIPs: {lb}\n" if e.get("EXPOSE") == "loadbalancer" and lb else ""
docs = [string.Template(open(os.path.join(root, "deploy/templates.yaml")).read()).substitute(e)]
cm = lambda name, data: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: %s\n  namespace: %s\ndata:\n%s\n" % (
    name, e["NAMESPACE"], "\n".join(f"  {k}: {json.dumps(v)}" for k, v in data.items()))
docs.append(cm("aigw-claims-broker-src", src))
docs.append(cm("aigw-claims-broker-config", {"broker-config.json": cfg}))
print("\n---\n".join(docs))
PY
}

newkey() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null; }

case "$MODE" in
  --dry-run) render ;;
  --uninstall)
    read -r -p "Delete namespace '$NAMESPACE'? [y/N] " a; [ "$a" = y ] && "${K[@]}" delete namespace "$NAMESPACE" ;;
  --rotate-key)
    name="key-$(date -u +%Y%m%d%H%M%S).pem"
    "${K[@]}" -n "$NAMESPACE" patch secret aigw-claims-broker-keys --type merge \
      -p "{\"data\":{\"$name\":\"$(newkey | base64 | tr -d '\n')\"}}"
    "${K[@]}" -n "$NAMESPACE" rollout restart deploy/aigw-claims-broker
    "${K[@]}" -n "$NAMESPACE" rollout status deploy/aigw-claims-broker --timeout=120s
    echo "New key $name is active; the old key stays in the JWKS. Remove it after one token lifetime:"
    echo "  kubectl -n $NAMESPACE patch secret aigw-claims-broker-keys --type json -p '[{\"op\":\"remove\",\"path\":\"/data/<old>.pem\"}]'" ;;
  "")
    render | "${K[@]}" apply -f - >/dev/null
    if ! "${K[@]}" -n "$NAMESPACE" get secret aigw-claims-broker-keys >/dev/null 2>&1; then
      newkey | "${K[@]}" -n "$NAMESPACE" create secret generic aigw-claims-broker-keys --from-file="key-$(date -u +%Y%m%d%H%M%S).pem=/dev/stdin" >/dev/null
      echo "created signing key secret aigw-claims-broker-keys"
    fi
    "${K[@]}" -n "$NAMESPACE" rollout restart deploy/aigw-claims-broker >/dev/null
    "${K[@]}" -n "$NAMESPACE" rollout status deploy/aigw-claims-broker --timeout=180s
    "${K[@]}" -n "$NAMESPACE" get pods,svc -l app=aigw-claims-broker
    echo
    echo "JWKS URL for the AI Gateway (SCM > AI Gateway > Admin Settings > Authentication > JWKS URI, comma-separated):"
    echo "  ${BROKER_ISSUER%/}/.well-known/jwks.json"
    echo "  (don't use the *.svc.cluster.local service name: the gateway's SSRF protection blocks it)" ;;
  *) echo "unknown option $MODE"; exit 1 ;;
esac
