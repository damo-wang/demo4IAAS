#!/usr/bin/env bash

set -euo pipefail

BASE_URL="http://localhost:8080"

# ---------- Color ----------
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
GRAY="\033[90m"
RESET="\033[0m"

line() {
  echo -e "${GRAY}------------------------------------------------------------${RESET}"
}

check_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    echo -e "${RED}ERROR:${RESET} jq not found. Please install jq (e.g. sudo apt install jq)"
    exit 1
  fi
}

print_result() {
  local status="$1"
  local body="$2"

  if [[ "$status" == "200" ]]; then
    echo -e "HTTP Status: ${GREEN}${status}${RESET}"
  elif [[ "$status" == "401" || "$status" == "403" ]]; then
    echo -e "HTTP Status: ${RED}${status}${RESET}"
  else
    echo -e "HTTP Status: ${YELLOW}${status}${RESET}"
  fi

  echo -e "${GRAY}Response:${RESET}"
  # 尝试用 jq 美化，如果不是合法 JSON 就原样输出
  echo "${body}" | jq . 2>/dev/null || echo "${body}"
}

# ---------- Login ----------
login() {
  local user="$1"
  local pass="$2"

  # 日志走 stderr（>&2）
  echo -e "${BLUE}===> Login as ${user}${RESET}" >&2

  local resp
  resp=$(curl -s -w "\nHTTP_STATUS:%{http_code}\n" \
    -X POST "${BASE_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${user}\",\"password\":\"${pass}\"}")

  local status
  status=$(echo "$resp" | grep HTTP_STATUS | cut -d':' -f2)
  local body
  body=$(echo "$resp" | sed '/HTTP_STATUS/d')

  # 这里仍然彩色输出，但走 stderr
  print_result "$status" "$body" >&2

  if [[ "$status" != "200" ]]; then
    echo -e "${RED}LOGIN FAILED for ${user}${RESET}" >&2
    exit 1
  fi

  local token
  token=$(echo "${body}" | jq -r '.access_token // empty')

  if [[ -z "${token}" || "${token}" == "null" ]]; then
    echo -e "${RED}ERROR:${RESET} access_token not found in login response for ${user}" >&2
    exit 1
  fi

  # ---------------------------
  # 只有这一行走 stdout
  # ---------------------------
  echo "${token}"
}

# ---------- GET / POST 封装 ----------
call_get() {
  local user="$1"
  local token="$2"
  local path="$3"

  line
  echo -e "User:   ${BLUE}${user}${RESET}"
  echo -e "Method: GET"
  echo -e "URL:    ${BASE_URL}${path}"

  local resp
  resp=$(curl -s -w "\nHTTP_STATUS:%{http_code}\n" \
    -H "Authorization: Bearer ${token}" \
    "${BASE_URL}${path}")

  local status
  status=$(echo "$resp" | grep HTTP_STATUS | cut -d':' -f2)
  local body
  body=$(echo "$resp" | sed '/HTTP_STATUS/d')

  print_result "$status" "$body"
}

call_post_json() {
  local user="$1"
  local token="$2"
  local path="$3"
  local body_json="$4"

  line
  echo -e "User:   ${BLUE}${user}${RESET}"
  echo -e "Method: POST"
  echo -e "URL:    ${BASE_URL}${path}"
  echo -e "${GRAY}Request body:${RESET} ${body_json}"

  local resp
  resp=$(curl -s -w "\nHTTP_STATUS:%{http_code}\n" \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    -d "${body_json}" \
    -X POST \
    "${BASE_URL}${path}")

  local status
  status=$(echo "$resp" | grep HTTP_STATUS | cut -d':' -f2)
  local body
  body=$(echo "$resp" | sed '/HTTP_STATUS/d')

  print_result "$status" "$body"
}

# ---------- Flow Per User ----------
run_tests_for_user() {
  local user="$1"
  local pass="$2"

  local token
  token=$(login "${user}" "${pass}")
  # node-1 status
  call_get "${user}" "${token}" "/nodes/node-1/status"

  # node-1 exec
  call_post_json "${user}" "${token}" "/nodes/node-1/exec" \
    "{\"cmd\":\"echo test from ${user}\"}"

  # node-2 status
  call_get "${user}" "${token}" "/nodes/node-2/status"
}

# ---------- Main ----------
main() {
  check_jq

  echo -e "${BLUE}===== Testing via nginx gateway: ${BASE_URL} =====${RESET}"
  echo -n "Health check: "
  curl -s "${BASE_URL}/healthz" || true
  echo
  echo

  echo -e "${YELLOW}############## Tests for alice (ops) ##############${RESET}"
  run_tests_for_user "alice" "123456"

  echo
  echo -e "${YELLOW}############## Tests for bob (viewer) ##############${RESET}"
  run_tests_for_user "bob" "123456"

  echo
  echo -e "${GREEN}===== All tests finished =====${RESET}"
}

main "$@"
