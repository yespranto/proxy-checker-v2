#!/bin/sh
set -eu

BASE=${1:-http://localhost:8080}
ADMIN_USER=${ADMIN_USER:-admin}
ADMIN_PASSWORD=${ADMIN_PASSWORD:-change-me-dev-only}
ECHO_TOKEN=${ECHO_TOKEN:-change-me-echo-token}
COOKIE_JAR=$(mktemp)
trap 'rm -f "$COOKIE_JAR"' EXIT

echo "1. Checking /health.php..."
curl -fsS "$BASE/health.php" | grep -q '"ok":true'

echo "2. Checking /echo.php auth..."
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/echo.php")
[ "$CODE" = "403" ]
curl -fsS "$BASE/echo.php?t=$ECHO_TOKEN" | grep -q '"ip":'

echo "3. Fetching CSRF token and logging in..."
AUTH_JSON=$(curl -fsS -c "$COOKIE_JAR" "$BASE/api/auth.php")
CSRF=$(printf '%s' "$AUTH_JSON" | sed -n 's/.*"csrf_token":"\([^"]*\)".*/\1/p')
[ -n "$CSRF" ]

LOGIN_RES=$(curl -fsS -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF" \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASSWORD\",\"_csrf\":\"$CSRF\"}" \
  "$BASE/api/auth.php?action=login")
printf '%s' "$LOGIN_RES" | grep -q '"ok":true'
CSRF=$(printf '%s' "$LOGIN_RES" | sed -n 's/.*"csrf_token":"\([^"]*\)".*/\1/p')

echo "4. Importing fixtures..."
IMPORT_RES=$(curl -fsS -b "$COOKIE_JAR" \
  -H "X-CSRF-Token: $CSRF" \
  -F "file=@tests/fixtures/proxies.txt" \
  "$BASE/api/proxies.php?action=import")
printf '%s' "$IMPORT_RES" | grep -q '"ok":true'
if printf '%s' "$IMPORT_RES" | grep -q 'p@ssword'; then
  echo "ERROR: password leaked in import response!" >&2
  exit 1
fi

echo "5. Listing proxies and ensuring credentials are masked..."
LIST_RES=$(curl -fsS -b "$COOKIE_JAR" "$BASE/api/proxies.php")
printf '%s' "$LIST_RES" | grep -q '"ok":true'
if printf '%s' "$LIST_RES" | grep -qE 'p@ssword|s3cr3t|password_enc'; then
  echo "ERROR: credential leaked in list response!" >&2
  exit 1
fi

echo "6. Creating job and polling until complete..."
JOB_RES=$(curl -fsS -b "$COOKIE_JAR" \
  -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF" \
  -d '{"all":true,"timeout":3,"retries":0}' \
  "$BASE/api/jobs.php")
JOB_ID=$(printf '%s' "$JOB_RES" | sed -n 's/.*"job_id":\([0-9]*\).*/\1/p')
[ -n "$JOB_ID" ]

i=0
while [ "$i" -lt 60 ]; do
  POLL=$(curl -fsS -b "$COOKIE_JAR" "$BASE/api/jobs.php?id=$JOB_ID")
  if printf '%s' "$POLL" | grep -q '"status":"done"'; then
    break
  fi
  i=$((i + 1))
  sleep 1
done
printf '%s' "$POLL" | grep -q '"status":"done"'

echo "7. Exporting TXT and checking no credentials appear..."
EXPORT_TXT=$(curl -fsS -b "$COOKIE_JAR" "$BASE/api/proxies.php?action=export&format=txt")
if printf '%s' "$EXPORT_TXT" | grep -qE 'p@ssword|s3cr3t'; then
  echo "ERROR: credential leaked in export!" >&2
  exit 1
fi

echo "All smoke checks passed."
