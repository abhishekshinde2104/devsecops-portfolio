#!/usr/bin/env bash
# Drive attack traffic at the Invoice API so the detections fire, for a live
# demo / dashboard screenshots. Everything here is benign load against the
# local lab API; it triggers the app's own security counters.
#
#   scripts/generate-attacks.sh [all|bruteforce|bola|ssrf|privesc|recon|tokens]
#
# Watch it land:  Grafana "Invoice API - Security Overview", or
#   kubectl -n monitoring port-forward svc/alert-sink 18080:8080
#   curl -s localhost:18080/alerts | python -m json.tool
source "$(dirname "$0")/lib.sh"

what="${1:-all}"
api=http://127.0.0.1:18000
trap stop_port_forwards EXIT
port_forward invoice-api svc/invoice-api 18000:80

json='Content-Type: application/json'
post() { curl -s -o /dev/null -w '%{http_code}' -X POST "$api$1" -H "$json" ${3:+-H "$3"} -d "$2"; }
get()  { curl -s -o /dev/null -w '%{http_code}' "$api$1" ${2:+-H "$2"}; }

# A legitimate account, to obtain a valid token for the authenticated attacks.
email="attacker-$RANDOM@example.com"; pw="$("$PY" -c 'import secrets;print(secrets.token_urlsafe(16))')"
post /auth/register "{\"email\":\"$email\",\"full_name\":\"A\",\"password\":\"$pw\"}" >/dev/null
token="$(curl -s -X POST "$api/auth/login" -H "$json" -d "{\"email\":\"$email\",\"password\":\"$pw\"}" | "$PY" -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))')"
authz="Authorization: Bearer $token"

bruteforce() {
  step "Brute force: 60 failed logins for one account"
  for i in $(seq 1 60); do post /auth/login "{\"email\":\"victim@example.com\",\"password\":\"guess-$i\"}" >/dev/null; done
}
tokens() {
  step "Token tampering: 30 forged/garbage bearer tokens"
  for i in $(seq 1 30); do get /users/me "Authorization: Bearer forged.$i.$(printf 'x%.0s' {1..20})" >/dev/null; done
}
bola() {
  step "BOLA probing: 30 cross-tenant invoice IDs"
  for i in $(seq 1 30); do get "/invoices/00000000-0000-0000-0000-0000000000$(printf '%02d' "$i")" "$authz" >/dev/null; done
}
privesc() {
  step "Privilege escalation: 15 hits on admin endpoints as a normal user"
  for _ in $(seq 1 15); do get /admin/users "$authz" >/dev/null; done
}
ssrf() {
  step "SSRF: 15 URL-preview requests at internal/metadata targets"
  for u in http://169.254.169.254/latest/meta-data/ http://127.0.0.1:8000/ http://10.0.0.1/ http://localhost/ file:///etc/passwd; do
    for _ in 1 2 3; do post /integrations/url-preview "{\"url\":\"$u\"}" "" "$authz" >/dev/null; done
  done
}
recon() {
  step "Recon: 60 requests to non-existent paths (404 enumeration)"
  for i in $(seq 1 60); do get "/wp-admin-$i" >/dev/null; get "/.env.$i" >/dev/null; done
}

case "$what" in
  all) bruteforce; tokens; bola; privesc; ssrf; recon ;;
  bruteforce|tokens|bola|privesc|ssrf|recon) "$what" ;;
  *) echo "usage: generate-attacks.sh [all|bruteforce|tokens|bola|privesc|ssrf|recon]" >&2; exit 2 ;;
esac

step "Done. Detections evaluate on ~5m windows; watch Grafana or the alert sink."
