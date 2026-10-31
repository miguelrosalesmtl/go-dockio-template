#!/usr/bin/env bash
# Drives a running server over real HTTP, with no døckio anywhere: what an
# installation looks like on day one, before anybody has clicked Quick connect.
#
# The døckio round trips themselves are covered by the Go tests against the fake
# station (internal/dockio/dockiotest); an end-to-end run against a REAL døckio
# needs one reachable from the server, which CI does not have.
#
# Environment:
#   API_BASE    the server, e.g. http://localhost:8080
#   SERVER_CMD  how to run the binary, e.g. ./bin/server (for create-superuser)
set -euo pipefail

API_BASE=${API_BASE:-http://localhost:8080}
SERVER_CMD=${SERVER_CMD:-./bin/server}
EMAIL=root@example.com
PASSWORD=e2e-superuser-password-long-enough
JAR=$(mktemp)
trap 'rm -f "$JAR"' EXIT

pass() { echo "  ok  $*"; }
fail() { echo "  FAIL $*" >&2; exit 1; }

# status METHOD PATH [curl args...] -> prints the HTTP status
status() {
	local method=$1 path=$2
	shift 2
	curl -s -o /tmp/e2e_body -w '%{http_code}' -X "$method" "$API_BASE$path" "$@"
}

echo "--- day one: no connection"
[ "$(curl -sf "$API_BASE/api/v1/auth/config" | jq -r .signin_available)" = false ] \
	&& pass "the login page is told sign-in is unavailable" || fail "auth/config"
loc=$(curl -s -o /dev/null -w '%{redirect_url}' "$API_BASE/api/v1/auth/oidc/login")
[[ "$loc" == *"/login?error=signin_unavailable" ]] && pass "Continue with døckio lands on the login page with a code" \
	|| fail "login start redirected to $loc"
[ "$(curl -sf "$API_BASE/api/v1/dockio/manifest" | jq -r .dockio_manifest)" = 1 ] && pass "the manifest is served" \
	|| fail "manifest"

echo "--- the emergency superuser"
SUPERUSER_PASSWORD=$PASSWORD $SERVER_CMD create-superuser "$EMAIL" >/dev/null
[ "$(status POST /api/v1/auth/admin-login -H 'Content-Type: application/json' \
	-d "{\"email\":\"$EMAIL\",\"password\":\"wrong-wrong-wrong-wrong\"}")" = 401 ] && pass "a wrong password is 401" \
	|| fail "wrong password"
code=$(status POST /api/v1/auth/admin-login -c "$JAR" -H 'Content-Type: application/json' \
	-d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
[ "$code" = 200 ] && pass "the superuser signs in" || fail "admin login: $code"
TOKEN=$(jq -r .token /tmp/e2e_body)

echo "--- CSRF"
[ "$(status POST /api/v1/system/organizations -b "$JAR" -H 'Content-Type: application/json' \
	-d '{"slug":"shop","name":"Shop"}')" = 403 ] && pass "a cookie without the CSRF header changes nothing" \
	|| fail "csrf"
for slug in shop bakery; do
	code=$(status POST /api/v1/system/organizations -b "$JAR" -H 'X-CSRF-Protection: 1' \
		-H 'Content-Type: application/json' -d "{\"slug\":\"$slug\",\"name\":\"$slug\"}")
	[ "$code" = 201 ] || fail "create $slug: $code $(cat /tmp/e2e_body)"
done
pass "organizations created from the system surface"

echo "--- the sign-in page with no connection"
[ "$(status GET /api/v1/system/signin/ -H "Authorization: Bearer $TOKEN")" = 200 ] \
	&& [ "$(jq -r .status /tmp/e2e_body)" = none ] && pass "the connection status is none" || fail "signin status"

echo "--- API keys stay in their organization"
code=$(status POST /api/v1/organizations/shop/api-keys -H "Authorization: Bearer $TOKEN" \
	-H 'Content-Type: application/json' -d '{"name":"reports","permissions":["audit.read"]}')
[ "$code" = 201 ] || fail "create key: $code $(cat /tmp/e2e_body)"
KEY=$(jq -r .token /tmp/e2e_body)
[ "$(status GET /api/v1/organizations/shop/audit -H "Authorization: Bearer $KEY")" = 200 ] \
	&& pass "the key reads its own organization's audit log" || fail "own org"
[ "$(status GET /api/v1/organizations/bakery/audit -H "Authorization: Bearer $KEY")" = 404 ] \
	&& pass "the key cannot see another organization" || fail "other org"
[ "$(status GET /api/v1/system/signin/ -H "Authorization: Bearer $KEY")" = 403 ] \
	&& pass "the key cannot reach the system surface" || fail "system with a key"

echo "--- døckio notices without a connection"
[ "$(status POST /api/v1/dockio/connection-revoked -d token=forged)" = 400 ] \
	&& pass "a forged revocation notice is 400" || fail "revocation"
[ "$(status POST /api/v1/auth/oidc/backchannel-logout -d logout_token=forged)" = 400 ] \
	&& pass "a forged logout token is 400" || fail "backchannel"

echo "--- sign out"
[ "$(status POST /api/v1/auth/logout -b "$JAR" -H 'X-CSRF-Protection: 1')" = 200 ] || fail "logout"
[ "$(status GET /api/v1/auth/me -b "$JAR")" = 401 ] && pass "the session is gone" || fail "after logout"
