#!/usr/bin/env bash
# Lab: create a Keycloak client whose custom claims (tier, bu) appear ONLY in the ID token and /userinfo, never in
# the access token. That reproduces IdPs (like the one this broker was built for) that can't put custom claims in
# access tokens. Runs kcadm inside the Keycloak pod.
#
# Usage: KC_CTX=<kube-context> KC_NS=keycloak REALM=<realm> CLIENT=aigw-broker-test ./examples/keycloak-lab-setup.sh
#   Users need attributes `user_tier` and `department` (mapped to `tier` and `bu`).
set -euo pipefail
KC_CTX=${KC_CTX:-}; KC_NS=${KC_NS:-keycloak}; REALM=${REALM:?set REALM}; CLIENT=${CLIENT:-aigw-broker-test}
K=(kubectl); [ -n "$KC_CTX" ] && K+=(--context "$KC_CTX")
"${K[@]}" -n "$KC_NS" exec -i deploy/keycloak -- env REALM="$REALM" CLIENT="$CLIENT" bash -s <<'EOS'
set -e
K=/opt/keycloak/bin/kcadm.sh; C=/tmp/kc-$$.cfg
trap 'rm -f $C' EXIT
$K config credentials --server http://localhost:8080 --realm master --user "$KEYCLOAK_ADMIN" --password "$KEYCLOAK_ADMIN_PASSWORD" --config $C >/dev/null
ID=$($K get clients -r "$REALM" -q clientId="$CLIENT" --fields id --format csv --noquotes --config $C)
if [ -z "$ID" ]; then
  $K create clients -r "$REALM" --config $C -s clientId="$CLIENT" -s enabled=true -s protocol=openid-connect \
    -s publicClient=false -s standardFlowEnabled=false -s directAccessGrantsEnabled=true -s serviceAccountsEnabled=false >/dev/null
  ID=$($K get clients -r "$REALM" -q clientId="$CLIENT" --fields id --format csv --noquotes --config $C)
  echo "created client $CLIENT"
else
  echo "client $CLIENT exists"
fi
for pair in "user_tier:tier" "department:bu"; do
  attr=${pair%%:*}; claim=${pair##*:}
  if ! $K get clients/$ID/protocol-mappers/models -r "$REALM" --config $C --fields name --format csv --noquotes | grep -qx "$claim-idtoken-only"; then
    $K create clients/$ID/protocol-mappers/models -r "$REALM" --config $C -s name="$claim-idtoken-only" \
      -s protocol=openid-connect -s protocolMapper=oidc-usermodel-attribute-mapper \
      -s "config.\"user.attribute\"=$attr" -s "config.\"claim.name\"=$claim" -s 'config."jsonType.label"=String' \
      -s 'config."id.token.claim"=true' -s 'config."userinfo.token.claim"=true' \
      -s 'config."access.token.claim"=false' -s 'config."introspection.token.claim"=false' >/dev/null
    echo "mapper $attr -> $claim (ID token + userinfo only)"
  fi
done
EOS
