#!/bin/bash

CAM_URL="http://localhost:9000"
CAG_URL="http://localhost:8000"

function login() {
  USER=$1
  PASS=$2

  echo "===> Logging in as $USER"
  RES=$(curl -s -X POST "$CAM_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}")

  TOKEN=$(echo $RES | jq -r '.access_token')

  if [ "$TOKEN" == "null" ] || [ -z "$TOKEN" ]; then
    echo "❌ Login failed!"
    echo "$RES"
    exit 1
  fi

  echo "✓ Login success"
}

function call_get() {
  URL=$1
  DESC=$2

  echo ""
  echo "👉 $DESC"
  RES=$(curl -s -w "\nHTTP_CODE:%{http_code}\n" -H "Authorization: Bearer $TOKEN" "$URL")

  echo "$RES"

  CODE=$(echo "$RES" | grep HTTP_CODE | cut -d':' -f2)

  if [ "$CODE" == "200" ]; then
    echo "✓ SUCCESS"
  else
    echo "⚠️ FAILED ($CODE)"
  fi
}

function call_post() {
  URL=$1
  BODY=$2
  DESC=$3

  echo ""
  echo "👉 $DESC"
  RES=$(curl -s -w "\nHTTP_CODE:%{http_code}\n" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$BODY" \
    "$URL")

  echo "$RES"

  CODE=$(echo "$RES" | grep HTTP_CODE | cut -d':' -f2)

  if [ "$CODE" == "200" ]; then
    echo "✓ SUCCESS"
  else
    echo "⚠️ FAILED ($CODE)"
  fi
}

########################
# Alice 测试
########################
login "alice" "123456"

call_get "$CAG_URL/nodes/node-1/status"  "Alice → node-1 status"
call_post "$CAG_URL/nodes/node-1/exec" '{"cmd":"echo hello"}' "Alice → node-1 exec"
call_get "$CAG_URL/nodes/node-2/status"  "Alice → node-2 status"


########################
# Bob 测试
########################
login "bob" "123456"

call_get "$CAG_URL/nodes/node-1/status"  "Bob → node-1 status (should fail)"
call_post "$CAG_URL/nodes/node-1/exec" '{"cmd":"echo hello"}' "Bob → node-1 exec (fail)"
call_get "$CAG_URL/nodes/node-2/status"  "Bob → node-2 status (should pass)"
