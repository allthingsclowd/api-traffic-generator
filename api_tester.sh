#!/usr/bin/env bash

# Author: Graham Land & AI Assistant
# Version: 3.2.0 # Increment version for payload updates
# Purpose: Simulate diverse API traffic for SALT Security testing, including valid requests,
#          governance policy violations, OWASP Top 10 patterns, shadow, and zombie APIs.
# Usage: ./api-tester.sh [http(s)://your-haproxy-host:port]

# See https://raw.githubusercontent.com/allthingsclowd/api-traffic-generator/refs/heads/grazzer/api_tester.sh for the original version that's actually used in the repo.

# --- Configuration ---
set -euo pipefail # Exit on error, undefined variable, or pipe failure

# Target Host: Default to http://localhost if no argument is provided
# Enhanced Target Host Handling
if [[ $# -eq 2 ]]; then
  CUSTOM_HOST_HEADER="$1"
  HOST="$2"
else
  HOST=${1:-http://localhost}
  CUSTOM_HOST_HEADER=""
fi

if command -v date >/dev/null 2>&1; then
  DATE_OUTPUT=$(date '+%Y-%m-%d_%H-%M-%S')
  DATE_EXIT_CODE=$?
else
  echo "ERROR: 'date' command NOT found in PATH. This is unexpected." >&2
fi

DATE_FOR_LOG=$(date '+%Y-%m-%d_%H-%M-%S')
DATE_FOR_LOG_EXIT_CODE=$?

if [[ $DATE_FOR_LOG_EXIT_CODE -ne 0 ]]; then
  echo "ERROR: 'date' command failed with exit code $DATE_FOR_LOG_EXIT_CODE when generating timestamp for LOG variable. Output: '$DATE_FOR_LOG'. Exiting." >&2
  exit 1
fi

# Log File: Timestamped log file in /tmp
LOG="/tmp/api_tester_${DATE_FOR_LOG}.log"
# Duration: How long the script should run in seconds
DURATION_SECONDS=180

# --- API Endpoint Definitions ---
echo "DEBUG: API Endpoint Definitions arrays defined." >&2
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
  "/eshop/catalog/products-beta"       # Explicitly test the drifted API endpoint
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
echo "DEBUG: Entering Helper Functions definitions section." >&2

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
echo "DEBUG: All Helper Functions defined." >&2
# --- Core API Interaction Function ---
# Executes a curl request, logs details, handles headers and output parsing.
# Usage: hit_api method url note [body] [omit_auth] [add_pii_header] [force_protocol] [content_type]
function hit_api { # NOSONAR
    echo "DEBUG: Entered hit_api function." >&2
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

    local curl_args=(-s -i -k --max-time 15 -X "$method") # Added --max-time 15

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
    curl_args+=(-w "\nHTTP_STATUS_CODE:%{http_code}") # Append status code to output, separated by newline

    # Correctly build the command string for logging
    local cmd_str_log_array=("curl")
    for arg in "${curl_args[@]}"; do
        cmd_str_log_array+=("$(printf '%q' "$arg")")
    done
    local cmd_str_log="${cmd_str_log_array[*]}"

    local raw_output exit_code
    echo "DEBUG: Executing curl command: $cmd_str_log" >&2

    # Temporarily disable exit on error for the curl command to handle its exit code
    local prev_set_e_state=""
    if [[ $- == *e* ]]; then prev_set_e_state="enabled"; fi
    set +e

    raw_output=$(curl "${curl_args[@]}" 2>&1)
    exit_code=$?

    if [[ "$prev_set_e_state" == "enabled" ]]; then set -e; fi # Restore set -e

    echo "DEBUG: curl command finished. Exit code: $exit_code" >&2
    
    # Use printf for safer output of raw_output and check its exit code
    printf "DEBUG: Raw curl output:\n%s\n" "$raw_output" >&2
    local printf_exit_code=$?
    echo "DEBUG: printf for raw_output finished. Exit code: $printf_exit_code" >&2
    if [[ $printf_exit_code -ne 0 ]]; then
        echo "ERROR: printf command failed with exit code $printf_exit_code while printing raw_output. This is highly unusual." >&2
        # Depending on the severity, you might choose to exit or try to continue
        # For now, let's log and attempt to continue with parsing if raw_output might still be usable
    fi

    echo "DEBUG: Attempting to proceed past printf." >&2

    # Parse headers, body, and status code from raw_output
    local response_headers="" # UNCOMMENTED
    local response_body=""    # UNCOMMENTED
    local status_code=""      # UNCOMMENTED
    local headers_done=false  # UNCOMMENTED
    local line_num=0          # UNCOMMENTED
    local http_status_line="" # UNCOMMENTED

    if [[ -n "$raw_output" ]]; then # UNCOMMENTED
        echo "DEBUG PARSING: Entered 'if -n raw_output' block." >&2
        # local status_code="XXX" # Placeholder - REMOVE THIS LINE

        # Read line by line, handling CR characters
        while IFS= read -r line; do
            echo "DEBUG PARSING: Top of while loop. line_num='$line_num'" >&2
            line=${line%$'\r'} # Remove trailing CR if present
            echo "DEBUG PARSING: About to increment line_num. Current value: '$line_num'. Line content: '${line}'" >&2
            ((line_num++)) || true # Ensure set -e doesn't trip on ((0)) returning 1
            echo "DEBUG PARSING: Incremented line_num to '$line_num'." >&2

            if [[ "$line" =~ ^HTTP_STATUS_CODE:([0-9]{3})$ ]]; then # Check for our appended status code
                if [[ -n "${BASH_REMATCH[1]}" ]]; then
                    status_code="${BASH_REMATCH[1]}"
                fi
                continue
            fi
            echo "DEBUG PARSING: Past HTTP_STATUS_CODE check." >&2

            if [[ "$headers_done" == false ]]; then
                echo "DEBUG PARSING: In headers_done==false block." >&2
                if [[ $line_num -eq 1 && "$line" =~ ^HTTP/[0-9.]+ ]]; then
                    echo "DEBUG PARSING: Matched HTTP status line (line_num 1)." >&2
                    http_status_line="$line"
                    if [[ -z "$status_code" && "$http_status_line" =~ ^HTTP/[0-9.]+[[:space:]]+([0-9]{3}) ]]; then
                        status_code="${BASH_REMATCH[1]}"
                    fi
                elif [[ -z "$line" ]]; then
                    headers_done=true
                    echo "DEBUG PARSING: Empty line found, headers_done set to true." >&2
                else
                    response_headers+="$line"$'\n'
                fi
            else
                response_body+="$line"$'\n'
            fi
        done <<< "$raw_output" # Using here-string
        echo "DEBUG PARSING: Exited while loop." >&2

        # Final check for status_code if not found via -w (should be rare now)
        if [[ -z "$status_code" && -n "$http_status_line" && "$http_status_line" =~ ^HTTP/[0-9.]+[[:space:]]+([0-9]{3}) ]]; then
            status_code="${BASH_REMATCH[1]}"
            log_action "  WARNING: Used fallback status code ($status_code) from HTTP status line. -w output might have been missing."
        elif [[ -z "$status_code" ]]; then
            log_action "  ERROR: Failed to parse HTTP status code from curl output (loop processed). Raw output was:\n$raw_output"
            status_code="000" # Assign a non-standard code to indicate parsing failure
        fi
        response_body=${response_body%$'\n'} # Remove last newline from body if present - UNCOMMENTED
    else # UNCOMMENTED
        log_action "  WARNING: Raw curl output was empty. Skipping parsing." # UNCOMMENTED
        status_code="000" # Indicate an issue # UNCOMMENTED
    fi # UNCOMMENTED

    log_action "  Response Status: $status_code"
    # Log headers if any were captured
    if [[ -n "$response_headers" ]]; then
      printf "  Response Headers:\n%s" "$response_headers" | tee -a "$LOG"
      log_action "" # Add a blank line after headers in the log
    else
      log_action "  Response Headers: (None captured or empty)"
    fi
    log_action "  Response Body:\n${response_body}" # Log body even if empty
    echo "" | tee -a "$LOG" # Ensure a blank line after body in the main log
}

# --- Simulation Functions ---
echo "DEBUG: Defining Simulation Functions." >&2

# Simulate valid user traffic
simulate_valid_traffic() {
  local api_group_name=$1
  shift
  local endpoints_array_name="$1[@]"
  local endpoints=("${!endpoints_array_name}")
  local endpoint_template=$(rand_elem "${endpoints[@]}")
  local endpoint=${endpoint_template/\{id\}/$(generate_uuid)}
  local method=$(rand_elem "GET" "POST" "PUT" "DELETE") # Common methods for valid traffic
  local payload=""
  if [[ "$method" == "POST" || "$method" == "PUT" ]]; then
    payload=$(get_realistic_payload "$api_group_name")
  fi
  hit_api "$method" "$HOST$endpoint" "Valid $api_group_name Traffic" "$payload"
}
echo "DEBUG: simulate_valid_traffic function defined." >&2

# Simulate governance policy violations
simulate_governance_violation() {
  local endpoint_template=$(rand_elem "${GOVERNANCE_ENDPOINTS[@]}")
  local endpoint=${endpoint_template/\{id\}/$(generate_uuid)}
  local method=$(rand_elem "${METHODS[@]}")
  local note="Governance Violation"
  local add_pii=false
  local omit_auth_flag=false
  local force_proto=""
  local content_type_override=""

  # Specific violation scenarios
  if [[ "$endpoint" == *"/open-registration"* ]]; then
    note="Open Registration Attempt"
  elif [[ "$endpoint" == *"/insecure-cookies"* ]]; then
    note="Testing Insecure Cookies (no specific client action, server-side check)"
  elif [[ "$endpoint" == *"/hr/posture/headers"* ]]; then
    note="HR Missing Security Headers (server-side check)"
  elif [[ "$endpoint" == *"/hr/posture/methods"* ]]; then
    note="HR Unrestricted HTTP Methods"
    method=$(rand_elem "TRACE" "CONNECT" "TRACK")
  elif [[ "$endpoint" == *"/finance/posture/leaky-headers"* ]]; then
    note="Finance Leaky Headers (server-side check)"
    add_pii=true
  elif [[ "$endpoint" == *"/finance/posture/missing-auth"* ]]; then
    note="Finance Missing Auth"
    omit_auth_flag=true
  elif [[ "$endpoint" == *"/products/posture/unencrypted-endpoint"* ]]; then
    note="Products Unencrypted Endpoint"
    force_proto="HTTP"
  elif [[ "$endpoint" == *"/products/posture/missing-csp"* ]]; then
    note="Products Missing CSP (server-side check)"
  elif [[ "$endpoint" == *"/banking/posture/cleartext-auth"* ]]; then
    note="Banking Cleartext Auth"
  elif [[ "$endpoint" == *"/banking/posture/missing-headers"* ]]; then
    note="Banking Missing Security Headers (server-side check)"
  fi

  hit_api "$method" "$HOST$endpoint" "$note" "" "$omit_auth_flag" "$add_pii" "$force_proto" "$content_type_override"
}
echo "DEBUG: simulate_governance_violation function defined." >&2

# Simulate OWASP API Top 10 patterns
simulate_owasp_attack() {
  local endpoint_template=$(rand_elem "${OWASP_ENDPOINTS[@]}")
  local endpoint=${endpoint_template/\{id\}/$(generate_uuid)}
  local method=$(rand_elem "${METHODS[@]}")
  local payload=""
  local note="OWASP Attack"
  local content_type_override=""

  if [[ "$endpoint" == *"/OWASP1/"* ]]; then note="OWASP1 Broken Object Level Auth"; fi
  if [[ "$endpoint" == *"/OWASP2/"* ]]; then note="OWASP2 Broken Authentication"; fi
  if [[ "$endpoint" == *"/OWASP3/"* ]]; then note="OWASP3 Excessive Data Exposure"; fi
  if [[ "$endpoint" == *"/OWASP4/"* ]]; then note="OWASP4 Lack of Resources & Rate Limiting"; fi
  if [[ "$endpoint" == *"/OWASP5/"* ]]; then note="OWASP5 Broken Function Level Auth"; fi
  if [[ "$endpoint" == *"/OWASP6/"* ]]; then note="OWASP6 Mass Assignment"; payload='{"isAdmin":true,"userId":"attacker"}'; fi
  if [[ "$endpoint" == *"/OWASP7/"* ]]; then note="OWASP7 Security Misconfiguration"; fi
  if [[ "$endpoint" == *"/OWASP8/"* || "$endpoint" == *"/OWASP10/"* ]]; then
    note="OWASP8 Injection / OWASP10 Unsafe Consumption"
    payload=$(get_malicious_payload)
    if (( RANDOM % 3 == 0 )); then content_type_override="application/xml"; fi
    if (( RANDOM % 3 == 1 )); then content_type_override="text/plain"; fi
  fi
  if [[ "$endpoint" == *"/OWASP9/"* ]]; then note="OWASP9 Improper Assets Management (Shadow API)"; fi


  hit_api "$method" "$HOST$endpoint" "$note" "$payload" false false "" "$content_type_override"
}
echo "DEBUG: simulate_owasp_attack function defined." >&2

# Simulate Shadow/Zombie API traffic
simulate_shadow_zombie_traffic() {
  local endpoint=$(rand_elem "${SHADOW_ZOMBIE_ENDPOINTS[@]}")
  local method=$(rand_elem "${METHODS[@]}")
  local payload=""
  if [[ "$method" == "POST" || "$method" == "PUT" ]]; then
    payload=$(get_realistic_payload "generic")
  fi
  hit_api "$method" "$HOST$endpoint" "Shadow/Zombie API Traffic" "$payload"
}
echo "DEBUG: simulate_shadow_zombie_traffic function defined." >&2
echo "DEBUG: All Simulation Functions defined." >&2

# --- Main Simulation Loop ---
echo "DEBUG: Script has reached the Main Simulation Loop section." >&2
START_TIME=$(date +%s)
echo "DEBUG: START_TIME set to $START_TIME" >&2
echo "DEBUG: LOG file path is $LOG" >&2

# Ensure log file is writable, create if not exists (tee -a will do this, but good to be explicit for first log)
echo "DEBUG: Attempting to touch log file: $LOG" >&2
touch "$LOG" || { echo "ERROR: Cannot create or touch log file $LOG. Exiting." >&2; exit 1; }
echo "DEBUG: Log file touched successfully (or already existed)." >&2

log_action "Starting API traffic generation for $DURATION_SECONDS seconds. Target: http://localhost:80. Log file: $LOG"
if [[ -n "$CUSTOM_HOST_HEADER" ]]; then
  log_action "Using custom Host header: $CUSTOM_HOST_HEADER"
fi

# Counter for requests
echo "DEBUG: Initializing REQUEST_COUNT." >&2
REQUEST_COUNT=0

while true; do
  echo "DEBUG: Top of main while loop. REQUEST_COUNT: $REQUEST_COUNT" >&2
  CURRENT_TIME=$(date +%s)
  ELAPSED_TIME=$((CURRENT_TIME - START_TIME))

  if [[ $ELAPSED_TIME -ge $DURATION_SECONDS ]]; then
    log_action "Duration of $DURATION_SECONDS seconds reached. Exiting."
    break
  fi

  # Randomly select a simulation type
  SIM_TYPE=$((RANDOM % 100))
  echo "DEBUG: SIM_TYPE is $SIM_TYPE" >&2

  if [[ $SIM_TYPE -lt 50 ]]; then # 50% Valid Traffic
    API_GROUP_CHOICE=$((RANDOM % 5))
    case $API_GROUP_CHOICE in
      0) simulate_valid_traffic "eshop" ESHOP_API_ENDPOINTS ;;
      1) simulate_valid_traffic "hr" HR_API_ENDPOINTS ;;
      2) simulate_valid_traffic "finance" FINANCE_API_ENDPOINTS ;;
      3) simulate_valid_traffic "products" PRODUCTS_API_ENDPOINTS ;;
      4) simulate_valid_traffic "banking" BANKING_API_ENDPOINTS ;;
    esac
  elif [[ $SIM_TYPE -lt 70 ]]; then # 20% Governance Violations
    simulate_governance_violation
  elif [[ $SIM_TYPE -lt 90 ]]; then # 20% OWASP Attacks
    simulate_owasp_attack
  else # 10% Shadow/Zombie API Traffic
    simulate_shadow_zombie_traffic
  fi

  REQUEST_COUNT=$((REQUEST_COUNT + 1))
  echo "DEBUG: REQUEST_COUNT is now $REQUEST_COUNT." >&2


  # Random delay between requests (e.g., 0.1 to 1 second)
  echo "DEBUG: About to calculate DELAY using awk." >&2
  if command -v awk >/dev/null 2>&1; then
    echo "DEBUG: 'awk' command found in PATH." >&2
    DELAY_VALUE=$(awk -v min=0.1 -v max=1.0 'BEGIN{srand(); print min+rand()*(max-min)}')
    AWK_EXIT_CODE=$?
    echo "DEBUG: 'awk' command executed. Exit code: $AWK_EXIT_CODE. Output: '$DELAY_VALUE'" >&2
    if [[ $AWK_EXIT_CODE -ne 0 ]]; then
      echo "ERROR: awk command failed with exit code $AWK_EXIT_CODE. Using default delay 0.5s." >&2
      DELAY_VALUE="0.5"
    elif [[ -z "$DELAY_VALUE" ]]; then
      echo "ERROR: awk command produced empty output. Using default delay 0.5s." >&2
      DELAY_VALUE="0.5"
    fi
  else
    echo "ERROR: 'awk' command NOT found in PATH. Using default delay 0.5s." >&2
    DELAY_VALUE="0.5"
  fi

  if sleep "$DELAY_VALUE"; then
    : # Do nothing on successful sleep
  else
    SLEEP_EXIT_CODE=$?
    echo "ERROR: sleep command failed with exit code $SLEEP_EXIT_CODE for delay '$DELAY_VALUE'. Continuing." >&2
  fi
done

log_action "API traffic generation finished. Total requests: $REQUEST_COUNT."
echo "DEBUG: Script finished successfully." >&2
