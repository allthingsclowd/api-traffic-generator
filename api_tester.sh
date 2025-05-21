#!/usr/bin/env bash

# Author: Graham Land & AI Assistant
# Version: 3.2.0 # Increment version for payload updates
# Purpose: Simulate diverse API traffic for SALT Security testing, including valid requests,
#          governance policy violations, OWASP Top 10 patterns, shadow, and zombie APIs.
# Usage: ./api-tester.sh [http(s)://your-haproxy-host:port]

# See https://raw.githubusercontent.com/allthingsclowd/api-traffic-generator/refs/heads/grazzer/api_tester.sh for the original version that's actually used in the repo.

# --- Configuration ---
set -euo pipefail # Exit on error, undefined variable, or pipe failure

echo "DEBUG: api_tester.sh started. set -euo pipefail executed." >&2

# Target Host: Default to http://localhost if no argument is provided
# Enhanced Target Host Handling
if [[ $# -eq 2 ]]; then
  CUSTOM_HOST_HEADER="$1"
  HOST="$2"
else
  HOST=${1:-http://localhost}
  CUSTOM_HOST_HEADER=""
fi

echo "DEBUG: HOST is '$HOST', CUSTOM_HOST_HEADER is '$CUSTOM_HOST_HEADER'. About to define LOG." >&2

# Explicitly test the date command
echo "DEBUG: Testing 'date' command availability and execution..." >&2
if command -v date >/dev/null 2>&1; then
  echo "DEBUG: 'date' command found in PATH." >&2
  DATE_OUTPUT=$(date '+%Y-%m-%d_%H-%M-%S')
  DATE_EXIT_CODE=$?
  echo "DEBUG: 'date' command executed. Exit code: $DATE_EXIT_CODE. Output: '$DATE_OUTPUT'" >&2
else
  echo "ERROR: 'date' command NOT found in PATH. This is unexpected." >&2
fi

# Log File: Timestamped log file in /tmp
LOG=/tmp/api_tester_$(date '+%Y-%m-%d_%H-%M-%S').log
# Duration: How long the script should run in seconds
DURATION_SECONDS=180

# --- API Endpoint Definitions ---
# (Endpoint definitions remain the same as version 3.0.0)
# Regular Endpoints (Used for Valid Traffic)
ESHOP_API_ENDPOINTS=(
  "/products" "/orders" "/users" "/addresses" "/payments" "/cart" "/wishlist" "/notifications"
  "/products/{id}" "/orders/{id}" "/users/{id}" "/wishlist/{id}" "/payments/{id}"
)
HR_API_ENDPOINTS=(
  "/employees" "/departments" "/titles" "/managers" "/locations" "/contracts" "/payroll"
  "/reviews" "/benefits" "/employees/{id}" "/departments/{id}" "/contracts/{id}" "/reviews/{id}" "/payroll/{id}"
)
FINANCE_API_ENDPOINTS=(
  "/transactions" "/invoices" "/budgets" "/forecasts" "/payments" "/tax-reports"
  "/audit-logs" "/journals" "/transactions/{id}" "/invoices/{id}" "/payments/{id}" "/tax-reports/{id}"
  "/audit-logs/{id}"
)
PRODUCTS_API_ENDPOINTS=(
  "/catalog" "/inventory" "/pricing" "/offers" "/ratings" "/tags" "/categories"
  "/features" "/catalog/{id}" "/inventory/{id}" "/offers/{id}" "/ratings/{id}" "/features/{id}"
)
BANKING_API_ENDPOINTS=(
  "/accounts" "/transfers" "/loans" "/mortgages" "/cards" "/statements" "/customers"
  "/verifications" "/accounts/{id}" "/transfers/{id}" "/loans/{id}" "/cards/{id}" "/statements/{id}"
)
# Governance Violation Targets (/posture/)
GOVERNANCE_ENDPOINTS=(
  "/eshop/posture/open-registration" "/eshop/posture/insecure-cookies"
  "/eshop/posture/open-registration/{id}" "/eshop/posture/insecure-cookies/{id}"
  "/hr/posture/headers" "/hr/posture/methods" "/hr/posture/headers/{id}" "/hr/posture/methods/{id}"
  "/finance/posture/leaky-headers" "/finance/posture/missing-auth"
  "/finance/posture/leaky-headers/{id}" "/finance/posture/missing-auth/{id}"
  "/products/posture/unencrypted-endpoint" "/products/posture/missing-csp"
  "/products/posture/unencrypted-endpoint/{id}" "/products/posture/missing-csp/{id}"
  "/banking/posture/cleartext-auth" "/banking/posture/missing-headers"
  "/banking/posture/cleartext-auth/{id}" "/banking/posture/missing-headers/{id}"
)
# OWASP Attack Targets (/OWASPX/)
OWASP_ENDPOINTS=(
  "/eshop/OWASP4/resource-exhaustion/{id}" "/eshop/OWASP9/shadow-api/{id}" "/eshop/OWASP10/malformed-input/{id}"
  "/hr/OWASP1/insufficient-logging/{id}" "/hr/OWASP5/broken-auth/{id}" "/hr/OWASP9/shadow-api/{id}"
  "/finance/OWASP2/broken-auth/{id}" "/finance/OWASP6/mass-assignment/{id}" "/finance/OWASP8/injection/{id}"
  "/products/OWASP3/excessive-data/{id}" "/products/OWASP4/lack-of-resources/{id}" "/products/OWASP10/unsafe-consumption/{id}"
  "/banking/OWASP1/insufficient-logging/{id}" "/banking/OWASP5/broken-auth/{id}" "/banking/OWASP7/security-misconfig/{id}"
)
# Shadow & Zombie API Endpoints
SHADOW_ZOMBIE_ENDPOINTS=(
  "/shadow-api/undocumented"           # Example of an unknown API
  "/zombie-api/v1/resource"            # Example of an old, supposedly decommissioned API
  "/api/v1/users/legacy"              # Another potential zombie
  "/internal/v1/debug/status"        # Potential shadow internal API
)

# --- Simulation Parameters ---
USERS=("alice" "bob" "carol" "eve" "guest" "attacker")
ROLES=("user" "admin" "auditor" "guest" "anonymous")
PROTOCOLS=("HTTP" "HTTPS")
METHODS=("GET" "POST" "PUT" "DELETE" "PATCH" "OPTIONS" "HEAD")

# Sensitive data examples for testing governance policies
PII_DATA=(
  "password=Str0ngP@ssw0rd!"
  "email=sensitive.user@example.com"
  "credit_card=4111222233334444"
  "ssn=000-00-0000"
  "auth_token=insecure-bearer-token-123"
  "session_cookie=plain-text-session-id"
)

# Malformed/Injection payloads for testing OWASP API10 / API8
MALICIOUS_PAYLOADS=(
  "' OR 1=1 -- "
  "<script>alert('XSS')</script>"
  "../../../../etc/passwd"
  '{"key": "value" invalid json'
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><data>&xxe;</data>'
  '{"$ne": null}'
  '{"isAdmin": true, "userId": "admin"}'
  "$(head -c 1024 /dev/urandom | base64)"
)

# --- Helper Functions ---

# Function to choose a random element from an array
rand_elem() {
  local arr=("$@")
  local index=$((RANDOM % ${#arr[@]}))
  echo "${arr[$index]}"
}

# Function to generate a random UUID
generate_uuid() {
  if command -v uuidgen &> /dev/null; then
    uuidgen
  else
    head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32
  fi
}

# Function to log actions to console and file
log_action() {
  # Debug: Indicate log_action was called
  echo "DEBUG: log_action called with: $1" >&2
  # Use printf for better formatting control and to avoid potential echo interpretation issues
  printf "%s [+] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$1" | tee -a "$LOG"
  # Debug: Indicate log_action finished
  echo "DEBUG: log_action for '$1' completed." >&2
}


# Function to generate realistic-looking JSON payload
get_realistic_payload() {
  local type=${1:-"generic"}
  local uuid=$(generate_uuid)
  local name=$(rand_elem "Widget" "Gadget" "Thingamajig" "Doohickey")
  local email="${uuid:0:8}@example.com"

  case "$type" in
    "user")
      echo "{\"userId\": \"$uuid\", \"username\": \"user_${uuid:0:4}\", \"email\": \"$email\", \"role\": \"$(rand_elem "${ROLES[@]}")\"}"
      ;;
    "product")
      echo "{\"productId\": \"$uuid\", \"name\": \"$name-$((RANDOM % 100))\", \"price\": $((RANDOM % 100 + 1)).99, \"inStock\": $((RANDOM % 2))}"
      ;;
    "order")
       echo "{\"orderId\": \"$uuid\", \"customerId\": \"cust_${uuid:0:6}\", \"items\": [{\"productId\": \"prod_${uuid:6:6}\", \"quantity\": $((RANDOM % 5 + 1))}], \"total\": $((RANDOM % 500 + 50)).00}"
      ;;
    *)
      echo "{\"id\": \"$uuid\", \"data\": \"Sample data for $uuid\", \"value\": $((RANDOM % 1000))}"
      ;;
  esac
}

# Function to generate intentionally malformed or injectable payloads
get_malicious_payload() {
    local base_payload='{"key": "value"' # Intentionally incomplete JSON
    local injection=$(rand_elem "${MALICIOUS_PAYLOADS[@]}")

    if (( RANDOM % 2 == 0 )); then
        echo "{\"maliciousInput\": \"$injection\", \"id\": \"$(generate_uuid)\"}"
    else
        if (( RANDOM % 2 == 0 )); then
            echo "$injection"
        else
            echo "$base_payload"
        fi
    fi
}

# Function to build curl header arguments (outputs one argument per line)
build_headers_args_list() {
  local user=$1
  local role=$2
  local proto_header=$3
  local omit_auth=${4:-false}
  local add_pii_header=${5:-false}
  local content_type=${6:-"application/json"} # Default Content-Type

  # Output arguments one per line for mapfile
  echo "-H"
  echo "Content-Type: $content_type"
  echo "-H"
  echo "Accept: application/json, */*"
  echo "-H"
  echo "X-Request-ID: $(generate_uuid)"
  echo "-H"
  echo "User-Agent: APITrafficGenerator/3.2.0"
  echo "-H"
  echo "X-Forwarded-For: 192.168.$((RANDOM % 256)).$((RANDOM % 256))"
  echo "-H"
  echo "Protocol: $proto_header"
  echo "-H"
  echo "X-Role: $role"

  if [[ "$omit_auth" == "false" ]]; then
    echo "-H"
    if [[ "$user" == "attacker" || "$role" == "anonymous" ]]; then
       echo "Authorization: Bearer invalid-token-$(generate_uuid)"
    else
       echo "Authorization: Bearer valid-token-for-$user-$(generate_uuid)"
    fi
    echo "-H"
    echo "X-API-Key: demo-key-for-$user"
  fi

  if [[ "$add_pii_header" == "true" ]]; then
    local pii_header_val=$(rand_elem "${PII_DATA[@]}")
    pii_header_val=${pii_header_val//\"/\\\"}
    echo "-H"
    echo "X-Leaked-Data: $pii_header_val"
  fi
}

# Function to send API requests with specific content types
send_api_with_payload() {
    local method="$1"
    local url="$2"
    local note="$3"
    local body="$4"
    local content_type="$5"

    hit_api "$method" "$url" "$note" "$body" false false "" "$content_type"
}
# --- Core API Interaction Function ---
# Executes a curl request, logs details, handles headers and output parsing.
# Usage: hit_api method url note [body] [omit_auth] [add_pii_header] [force_protocol] [content_type]
hit_api() {
    local method=$1
    local url=$2
    local note=$3
    local body=${4:-""}
    local omit_auth=${5:-false}
    local add_pii_header=${6:-false}
    local force_protocol=${7:-""}
    local content_type_override=${8:-""}

    local user=$(rand_elem "${USERS[@]}")
    local role=$(rand_elem "${ROLES[@]}")
    local proto_header=$(rand_elem "${PROTOCOLS[@]}")
    if [[ -n "$force_protocol" ]]; then
        proto_header="$force_protocol"
    fi
    local content_type=${content_type_override:-"application/json"}

    log_action "Attempting [$note] | Method: $method | URL: $url | User: $user | Role: $role | Protocol: $proto_header"
    if [[ "$omit_auth" == "true" ]]; then log_action "  (Flag: Omitting Auth)"; fi
    if [[ "$add_pii_header" == "true" ]]; then log_action "  (Flag: Adding PII Header)"; fi
    if [[ "$content_type" != "application/json" ]]; then log_action "  (Flag: Content-Type: $content_type)"; fi

    local curl_args=(-s -i -k -X "$method")

    local header_args=()
    mapfile -t header_args < <(build_headers_args_list "$user" "$role" "$proto_header" "$omit_auth" "$add_pii_header" "$content_type")

    if [[ -n "$CUSTOM_HOST_HEADER" ]]; then
        header_args+=("-H")
        header_args+=("Host: $CUSTOM_HOST_HEADER")
    fi

    curl_args+=("${header_args[@]}")

    if [[ -n "$body" ]]; then
        curl_args+=(-d "$body")
        log_action "  Request Body: $body"
    fi

    curl_args+=("$url")
    curl_args+=(-w "%{http_code}")

    printf -v cmd_str_log "curl %q " "${curl_args[@]}"

    local raw_output exit_code
    raw_output=$(curl "${curl_args[@]}" 2>&1)
    exit_code=$?

    if [[ $exit_code -ne 0 && $exit_code -ne 22 ]]; then
        log_action "  ERROR: curl command failed with exit code $exit_code for $method $url."
        log_action "  Executed command approx: $cmd_str_log"
        log_action "  Curl output (if any): $raw_output"
        return 1
    fi

    local response_headers=""
    local response_body=""
    local status_code=""
    local headers_done=false
    local line_num=0
    local http_status_line=""

    while IFS= read -r line; do
        ((line_num++))
        line=${line%$'\r'}

        if [[ "$line" =~ [^0-9]*([0-9]+)[^0-9]*$ ]]; then
            status_code="${BASH_REMATCH[1]}"
            continue
        fi

        if [[ "$headers_done" == false ]]; then
            if [[ $line_num -eq 1 && "$line" =~ ^HTTP/[0-9.]+ ]]; then
                http_status_line="$line"
                continue
            fi
            if [[ -z "$line" ]]; then
                headers_done=true
            else
                response_headers+="$line"$'\n'
            fi
        else
            response_body+="$line"$'\n'
        fi
    done <<< "$raw_output"

    if ! [[ "$status_code" =~ ^[0-9]+$ ]]; then
        if [[ -n "$http_status_line" && "$http_status_line" =~ ^HTTP/[0-9.]+[[:space:]]+([0-9]{3}) ]]; then
            status_code="${BASH_REMATCH[1]}"
            log_action "  WARNING: Used fallback status code ($status_code) from HTTP status line."
        else
            log_action "  ERROR: Failed to parse valid HTTP status code from curl output."
            log_action "  Curl exit code was $exit_code."
            log_action "  Raw Output was:\n$raw_output"
            return 1
        fi
    fi

    response_body=${response_body%$'\n'}

    log_action "  Request Headers Args Used:\n${header_args[*]}"
    log_action "  Response Status: $status_code"
    printf "  Response Headers:\n%s" "$response_headers" | tee -a "$LOG"
    log_action ""
    log_action "  Response Body:\n${response_body}"
    echo "" | tee -a "$LOG"
}
