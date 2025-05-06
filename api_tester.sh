#!/usr/bin/env bash
# Author: Graham Land & AI Assistant
# Version: 3.1.0
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
  # Use printf for better formatting control and to avoid potential echo interpretation issues
  printf "%s [+] %s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$1" | tee -a "$LOG"
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
  echo "User-Agent: APITrafficGenerator/3.1.3" # Version Bump
  echo "-H"
  echo "X-Forwarded-For: 192.168.$((RANDOM % 256)).$((RANDOM % 256))"
  echo "-H"
  echo "Protocol: $proto_header"
  echo "-H"
  echo "X-Role: $role"

  # Authentication Header (Conditional)
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

  # Add PII Header (For Governance Tests)
  if [[ "$add_pii_header" == "true" ]]; then
    local pii_header_val=$(rand_elem "${PII_DATA[@]}")
    # Basic escaping for quotes within the header value itself if necessary
    # Although not strictly needed here as it's a separate array element now
    pii_header_val=${pii_header_val//\"/\\\"}
    echo "-H"
    echo "X-Leaked-Data: $pii_header_val"
  fi
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

    # --- Build curl arguments array ---
    # Start with base options
    local curl_args=(-s -i -k -X "$method") # Use -i, add method

    # Add headers using mapfile/readarray
    local header_args=()
    mapfile -t header_args < <(build_headers_args_list "$user" "$role" "$proto_header" "$omit_auth" "$add_pii_header" "$content_type")
    
    # Inject Host header override if provided
    if [[ -n "$CUSTOM_HOST_HEADER" ]]; then
    header_args+=("-H")
    header_args+=("Host: $CUSTOM_HOST_HEADER")
    fi

    curl_args+=("${header_args[@]}") # Append header arguments

    # Add data payload if body is not empty
    if [[ -n "$body" ]]; then
        # No extra escaping needed for -d when passed as separate array element
        curl_args+=(-d "$body")
        log_action "  Request Body: $body"
    fi

    # Add URL
    curl_args+=("$url")

    # Add write-out for status code (NO newlines)
    curl_args+=(-w "%{http_code}")

    # --- Execute curl (NO eval needed) ---
    printf -v cmd_str_log "curl %q " "${curl_args[@]}" # For logging purposes
    # log_action "  Executing approx: $cmd_str_log" # Uncomment for deep debug

    local raw_output exit_code
    # Execute directly using the array. Capture stdout and stderr.
    raw_output=$(curl "${curl_args[@]}" 2>&1)
    exit_code=$?

    # --- DEBUGGING ---
    # log_action "  DEBUG: curl exit code: $exit_code"
    # log_action "  DEBUG: Raw curl output:\n$raw_output"
    # --- END DEBUGGING ---

    if [[ $exit_code -ne 0 && $exit_code -ne 22 ]]; then # Ignore exit code 22 (common for 4xx/5xx errors with -i/-w)
        log_action "  ERROR: curl command failed with exit code $exit_code for $method $url."
        log_action "  Executed command approx: $cmd_str_log"
        log_action "  Curl output (if any): $raw_output"
        return 1
    fi

    # --- Parsing Logic (v3.1.3) ---
    local response_headers=""
    local response_body=""
    local status_code=""
    local headers_done=false
    local line_num=0
    local http_status_line="" # Store the HTTP/1.1 line

    # Read line by line from raw_output
    while IFS= read -r line; do
        ((line_num++))
        line=${line%$'\r'} # Trim trailing CR

        # Check for the numeric status code line added by -w (at the very end)
        # Use improved regex to extract digits even if surrounded by junk
        if [[ "$line" =~ [^0-9]*([0-9]+)[^0-9]*$ ]]; then
            # Check if this is the *last* line of output
            # A simple way is to check if status_code is already found; -w puts it last.
            # But easier: just capture the *last* match.
            status_code="${BASH_REMATCH[1]}"
            # log_action "  DEBUG: Found potential status code line: $line -> $status_code"
            continue # Don't add this line to headers or body
        fi

        # Store or process other lines
        if [[ "$headers_done" == false ]]; then
            if [[ $line_num -eq 1 && "$line" =~ ^HTTP/[0-9.]+ ]]; then
                 http_status_line="$line" # Store the HTTP status line
                 # log_action "  DEBUG: Stored HTTP status line: $line"
                 continue # Don't add to headers variable
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

    # --- Validation ---
    if ! [[ "$status_code" =~ ^[0-9]+$ ]]; then
       # Fallback: Try to extract status from the HTTP/1.1 line if -w failed
       if [[ -n "$http_status_line" && "$http_status_line" =~ ^HTTP/[0-9.]+[[:space:]]+([0-9]{3}) ]]; then
            status_code="${BASH_REMATCH[1]}"
            log_action "  WARNING: Used fallback status code ($status_code) from HTTP status line."
       else
           log_action "  ERROR: Failed to parse valid HTTP status code from curl output (checked -w line and HTTP status line)."
           log_action "  Curl exit code was $exit_code."
           log_action "  Raw Output was:\n$raw_output" # Log the whole thing
           return 1
       fi
    fi

    # Trim potential trailing newline from body
    response_body=${response_body%$'\n'}

    # --- Logging Results ---
    # Log the header arguments used (more reliable than reconstructing the command)
    log_action "  Request Headers Args Used:\n${header_args[*]}" # Log the array elements
    log_action "  Response Status: $status_code"
    printf "  Response Headers:\n%s" "$response_headers" | tee -a "$LOG"
    log_action "" # Add newline after headers
    log_action "  Response Body:\n${response_body}"
    echo "" | tee -a "$LOG" # Add a blank line for readability
}

# --- Rest of the script (Traffic Generation Functions, Main Loop) ---
# ... (No changes needed in the rest of the script v3.1.0 - just update version number below) ...

# --- Update Version Number in Main Loop Logging ---
# Find the log_action lines in the main execution section and update to v3.1.3
# Example: log_action "Starting diverse API traffic generation for $HOST (v3.1.3)"


# --- Traffic Generation Functions ---

# 1. Generate Valid Traffic
generate_valid_traffic() {
    local api_group=$(rand_elem "eshop" "hr" "finance" "products" "banking")
    local endpoints_ref="${api_group^^}_API_ENDPOINTS[@]"
    local endpoint=$(rand_elem "${!endpoints_ref}")
    local path="$HOST/$api_group$endpoint"
    local note="Valid Traffic - ${api_group^} API"
    local method=""
    local body=""
    local payload_type="generic"

    if [[ "$path" == *"{id}"* ]]; then
        method=$(rand_elem "GET" "PUT" "PATCH" "DELETE")
        path=${path/\{id\}/$((RANDOM % 1000 + 1))}
        payload_type=${api_group%s}
    else
        method=$(rand_elem "GET" "POST")
        payload_type=${api_group%s}
    fi

    if [[ "$method" == "POST" || "$method" == "PUT" || "$method" == "PATCH" ]]; then
        body=$(get_realistic_payload "$payload_type")
    fi

    # Call hit_api without any special flags
    hit_api "$method" "$path" "$note" "$body"
}

# 2. Generate Governance Policy Violation Traffic
generate_governance_violation() {
    local endpoint=$(rand_elem "${GOVERNANCE_ENDPOINTS[@]}")
    local path="$HOST$endpoint"
    local note="Governance Violation Test"
    local method=$(rand_elem "GET" "POST" "PUT")
    local body=""
    # Flags for hit_api
    local omit_auth_flag=false
    local add_pii_header_flag=false
    local force_protocol_flag="HTTP" # FORCE HTTP
    local pii_location=$((RANDOM % 3)) # 0: body, 1: query param, 2: header

    log_action "Preparing Governance Violation for: $path"

    if [[ "$path" == *"{id}"* ]]; then
      path=${path/\{id\}/$((RANDOM % 1000 + 1))}
    fi

    local pii_item=$(rand_elem "${PII_DATA[@]}")

    case "$pii_location" in
      0) # PII in Body
        if [[ "$method" == "POST" || "$method" == "PUT" ]]; then
          local key=$(echo "$pii_item" | cut -d= -f1)
          local value=$(echo "$pii_item" | cut -d= -f2-)
          value=${value//\"/\\\"}
          body="{\"sensitiveField\": \"$value\", \"context\": \"governance-test\", \"original_key\": \"$key\"}"
          note+=": PII in Body over $force_protocol_flag"
        else
           method="POST" # Force POST if we wanted body PII but got GET
           local key=$(echo "$pii_item" | cut -d= -f1)
           local value=$(echo "$pii_item" | cut -d= -f2-)
           value=${value//\"/\\\"}
           body="{\"sensitiveField\": \"$value\", \"context\": \"governance-test\", \"original_key\": \"$key\"}"
           note+=": PII in Body over $force_protocol_flag (Forced POST)"
        fi
        ;;
      1) # PII in Query Parameter
         local pii_encoded=${pii_item// /%20} # Basic encoding
         pii_encoded=${pii_encoded//@/%40}
         pii_encoded=${pii_encoded/!/%21}
         path+="?$pii_encoded"
         note+=": PII in Query Param over $force_protocol_flag"
         if [[ "$method" != "GET" ]]; then method="GET"; fi # Force GET for query param
        ;;
      2) # PII in Header
         add_pii_header_flag=true # Set flag for hit_api
         note+=": PII in Custom Header over $force_protocol_flag"
        ;;
    esac

    # Randomly add Missing Auth violation
    if (( RANDOM % 4 == 0 )); then
        omit_auth_flag=true
        note+=", Missing Auth"
    fi

    # Make the API call passing the flags
    hit_api "$method" "$path" "$note" "$body" "$omit_auth_flag" "$add_pii_header_flag" "$force_protocol_flag"
}


# 3. Generate OWASP API Top 10 Attack Traffic
generate_owasp_attack() {
    local endpoint=$(rand_elem "${OWASP_ENDPOINTS[@]}")
    local path="$HOST$endpoint"
    local note="OWASP Attack Simulation"
    local method=""
    local body=""
    # Flags for hit_api
    local omit_auth_flag=false
    local add_pii_header_flag=false # Usually false for OWASP unless testing leaky headers
    local force_protocol_flag=""    # Default unless testing misconfig
    local content_type_override=""  # Default unless testing injection/content-type

    log_action "Preparing OWASP Attack for: $path"

    if [[ "$path" == *"{id}"* ]]; then
      local target_id=$((RANDOM % 1000 + 500))
      path=${path/\{id\}/$target_id}
      note+=": TargetID=$target_id"
    fi

    local attack_type=$((RANDOM % 6))

    # Tailor attack based on endpoint name if possible (optional enhancement)
    # ... (logic to set attack_type based on path can be added here) ...
    note+=" Type=$attack_type" # Log the chosen attack type number

    case "$attack_type" in
      0) # API1/API5 - BOLA/BFLA
        note+="/API1/5(AuthZ)"
        # Use attacker/guest role - handled by hit_api default randomization, can be forced if needed
        if [[ "$path" != *"{id}"* && "$path" == *"/users"* ]]; then
             method="DELETE" # Try forbidden method
        else
             method="GET"
        fi
        # No special flags needed, rely on random user/role in hit_api
        ;;
      1) # API2/API5 - Broken Authentication
        note+="/API2/5(AuthN)"
        method="GET"
        omit_auth_flag=true # Force missing auth
        if (( RANDOM % 2 == 0 )); then method="POST"; body=$(get_realistic_payload); fi # Maybe try POST/PUT too
         ;;
      2) # API6 - Mass Assignment
         note+="/API6(MassAssign)"
         method=$(rand_elem "POST" "PUT")
         local base_payload=$(get_realistic_payload "user")
         body=$(echo "$base_payload" | sed 's/}$/, "isAdmin": true, "unexpectedField": "injected"}/')
         ;;
      3) # API8/API7 - Security Misconfiguration
         note+="/API8/7(Misconfig)"
         method="GET"
         force_protocol_flag="HTTP" # Force HTTP
         ;;
      4) # API8/API10 - Injection / Malformed Data
         note+="/API8/10(Inject/Malformed)"
         method=$(rand_elem "GET" "POST" "PUT")
         if (( RANDOM % 2 == 0 )) && [[ "$method" != "GET" ]]; then
             body=$(get_malicious_payload)
             note+="-Body"
             if (( RANDOM % 3 == 0 )); then content_type_override="application/xml"; note+="-XMLContentType"; fi
         else
             local malicious_param=$(rand_elem "${MALICIOUS_PAYLOADS[@]}")
             malicious_param=${malicious_param// /%20}; malicious_param=${malicious_param//\"/%22}; malicious_param=${malicious_param//\'/%27}
             path+="?param=$malicious_param"
             note+="-QueryParam"
             method="GET" # Force GET for query param attack
         fi
         ;;
       5) # API4 - Lack of Resources (Large Payload)
          note+="/API4(Resource)"
          method=$(rand_elem "GET" "POST")
          if [[ "$method" == "POST" ]]; then
              if (( RANDOM % 2 == 0 )); then
                 body=$(echo "{\"largeData\": \"$(head -c 2048 /dev/urandom | base64)\"}")
                 note+="-LargeBody"
              else
                 body=$(get_realistic_payload)
              fi
          fi
          ;;
      *) # Default fallback
        note+=" (Fallback)"
        method="GET"
        ;;
    esac

    # Make the API call passing calculated flags
    hit_api "$method" "$path" "$note" "$body" "$omit_auth_flag" "$add_pii_header_flag" "$force_protocol_flag" "$content_type_override"
}

# 4. Generate Shadow & Zombie API Traffic
generate_shadow_zombie_traffic() {
    local endpoint=$(rand_elem "${SHADOW_ZOMBIE_ENDPOINTS[@]}")
    local path="$HOST$endpoint"
    local note=""
    local method="GET" # Typically discovered via GET

    if [[ "$path" == *"/shadow-api/"* ]]; then
        note="Shadow API Call"
    elif [[ "$path" == *"/zombie-api/"* || "$path" == *"/legacy"* || "$path" == *"/v1/"* ]]; then
        note="Zombie API Call"
    else
        note="Undocumented Endpoint Call"
    fi

    # Call hit_api without any special flags
    hit_api "$method" "$path" "$note"
}


# --- Main Execution Loop ---
log_action "Starting diverse API traffic generation for $HOST (v3.1.0)"
log_action "Target duration: $DURATION_SECONDS seconds. Logging to $LOG"
log_action "--- Using HAProxy backend for simulated responses ---"
echo "--- Script Start: $(date) ---" >> "$LOG"

start_time=$(date +%s)
while (( $(date +%s) - start_time < $DURATION_SECONDS )); do

    traffic_type_roll=$((RANDOM % 100))

    if (( traffic_type_roll < 60 )); then
        log_action "---> Generating Valid Traffic <---"
        generate_valid_traffic || log_action "ERROR in generate_valid_traffic"
    elif (( traffic_type_roll < 75 )); then
        log_action "---> Generating Governance Violation <---"
        generate_governance_violation || log_action "ERROR in generate_governance_violation"
    elif (( traffic_type_roll < 90 )); then
        log_action "---> Generating OWASP Attack <---"
        generate_owasp_attack || log_action "ERROR in generate_owasp_attack"
    else
        log_action "---> Generating Shadow/Zombie Traffic <---"
        generate_shadow_zombie_traffic || log_action "ERROR in generate_shadow_zombie_traffic"
    fi

    # Add || true to the function calls above if you want the script to continue even if a function fails internally
    # e.g., generate_valid_traffic || true

    sleep_duration=$((RANDOM % 4 + 1))
    log_action "Sleeping for $sleep_duration seconds..."
    sleep "$sleep_duration"

done

log_action "Traffic generation complete after running for $DURATION_SECONDS seconds."
log_action "Detailed logs are available in: $LOG"
echo "--- Script End: $(date) ---" >> "$LOG"
