# Future Enhancement: Enabling TLS for API Traffic Generator

This document outlines the steps required to enable TLS (Transport Layer Security) for the `api-traffic-generator` setup. This would involve configuring HAProxy to serve traffic over HTTPS and updating the `api_tester.sh` script to communicate securely.

**Note:** These changes are for a future enhancement and are not currently implemented in the main script.

## Overview of Changes

1.  **Generate SSL/TLS Certificates:** Create a server certificate and private key for HAProxy. For a demo/testing environment, self-signed certificates are sufficient.
2.  **Modify HAProxy Configuration (`haproxy.cfg`):** Configure HAProxy to listen on an HTTPS port (typically 443) and use the generated certificates.
3.  **Modify Client Script (`api_tester.sh`):** Update the script to send requests to the HTTPS endpoint and handle certificate validation.
4.  **Automate Certificate Generation (Optional but Recommended):** Implement a workflow to generate these certificates ephemerally at deployment time.

---

## Step 1: Generating Self-Signed SSL/TLS Certificates (using OpenSSL)

For a demo environment, we can create our own simple Certificate Authority (CA) and use it to sign a server certificate for HAProxy.

1.  **Create a directory for certificates:**
    Assuming your `haproxy.cfg` is in a directory like `haproxy_files` (as per the main `README.md`), create a `certs` subdirectory:
    ```bash
    mkdir -p /path/to/your/api-traffic-generator/haproxy_files/certs
    cd /path/to/your/api-traffic-generator/haproxy_files/certs
    ```

2.  **Generate CA Private Key and Certificate:**
    ```bash
    # Generate CA private key
    openssl genpkey -algorithm RSA -out ca.key -pkeyopt rsa_keygen_bits:2048

    # Generate CA certificate (self-signed)
    openssl req -new -x509 -key ca.key -out ca.crt -days 365 -subj "/CN=MyDemoCA"
    ```
    *   `ca.key`: Private key for your CA.
    *   `ca.crt`: Public certificate for your CA.

3.  **Generate Server Private Key and Certificate Signing Request (CSR):**
    ```bash
    # Generate server private key
    openssl genpkey -algorithm RSA -out server.key -pkeyopt rsa_keygen_bits:2048

    # Generate CSR for the server (use 'localhost' or the actual HAProxy hostname/IP as CN)
    openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
    ```
    *   `server.key`: Private key for your HAProxy server.
    *   `server.csr`: Certificate Signing Request.

4.  **Sign the Server Certificate with Your CA:**
    ```bash
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256 \
      -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")
    ```
    *   `server.crt`: Server's public certificate, signed by your CA.
    *   Adjust `DNS:localhost,IP:127.0.0.1` if HAProxy will be accessed via other names/IPs.

5.  **Create a `.pem` file for HAProxy:**
    HAProxy typically expects the server certificate and private key in a single `.pem` file.
    ```bash
    cat server.crt server.key > server.pem
    ```
    *   `server.pem`: This file will be used by HAProxy.

---

## Step 2: Modifying HAProxy Configuration (`haproxy.cfg`) for TLS

HAProxy needs to be configured to listen on port 443 for HTTPS and use the `server.pem` file. The `server.pem` file should be placed at `/usr/local/etc/haproxy/certs/server.pem` inside the HAProxy container (assuming `haproxy_files/certs/` on the host is mounted to `/usr/local/etc/haproxy/certs/` in the container).

```diff
--- a/.github/haproxy_files/haproxy.cfg
+++ b/.github/haproxy_files/haproxy.cfg
@@ -14,12 +14,20 @@
     timeout client 50000ms
     timeout server 50000ms
 
-frontend http_frontend
-    bind *:80
+# Frontend to redirect HTTP to HTTPS
+frontend http_redirect_frontend
     bind *:80
+    mode http
+    # Redirect all HTTP requests to HTTPS
+    http-request redirect scheme https code 301 if !{ ssl_fc }
+
+# Main HTTPS frontend
+frontend https_frontend
+    bind *:443 ssl crt /usr/local/etc/haproxy/certs/server.pem alpn h2,http/1.1
     mode http
 
     # Capture the original protocol
-    http-request set-header X-Client-Protocol req_proto
+    http-request set-header X-Client-Protocol %[req.proto]
     # Capture the Authorization header if present
     http-request set-header X-Client-Authorization %[req.hdr(Authorization)]
 
@@ -27,7 +35,7 @@
     acl is_favicon path /favicon.ico
     http-request return status 200 content-type "image/png" file /usr/local/etc/haproxy/icons/favicon32tp.png if is_favicon
     http-response set-header Protocol "%[hdr(X-Client-Protocol)]"
-
+    
     # --- Shadow API ---
     acl is_shadow_api path_beg /shadow-api /internal/v1/debug/status # Added /internal path
 
```

**Key `haproxy.cfg` changes:**
*   A new `http_redirect_frontend` is added to redirect HTTP (`*:80`) to HTTPS.
*   The main frontend (renamed to `https_frontend`) binds to `*:443 ssl` and specifies the certificate path (`crt /usr/local/etc/haproxy/certs/server.pem`).
*   `alpn h2,http/1.1` is added for HTTP/2 negotiation.
*   `X-Client-Protocol` capture is updated to `%{+Qreq.proto}` or `req.proto`.

---

## Step 3: Modifying Client Script (`api_tester.sh`)

The `api_tester.sh` script needs to target the HTTPS endpoint and handle the self-signed certificate.

```diff
--- a/api_tester.sh
+++ b/api_tester.sh
@@ -11,7 +11,7 @@
   CUSTOM_HOST_HEADER="$1"
   HOST="$2"
 else
-  HOST=${1:-http://localhost}
+  HOST=${1:-https://localhost:443} # Default to HTTPS on port 443
   CUSTOM_HOST_HEADER=""
 fi
 
@@ -254,7 +254,7 @@
     if [[ "$content_type" != "application/json" ]]; then log_action "  (Flag: Content-Type: $content_type)"; fi
 
-    local curl_args=(-s -i -k --max-time 15 -X "$method") # Added --max-time 15
+    local curl_args=(-s -i --max-time 15 -X "$method" --insecure) # Added --insecure for self-signed certs
 
     local header_args=()
     mapfile -t header_args < <(build_headers_args_list "$user" "$role" "$proto_header" "$omit_auth" "$add_pii_header" "$content_type")

```

**Key `api_tester.sh` changes:**
*   The default `HOST` is changed to `https://localhost:443`.
*   The `--insecure` (or `-k`) flag is added to `curl` to skip certificate validation for self-signed certificates.

**Alternative to `--insecure` (More Secure Demo):**
To avoid `--insecure`, `curl` can be told to trust your specific self-signed CA:
1.  Make `ca.crt` (generated in Step 1) available to the `api_tester.sh` environment.
2.  Change the `curl_args` line to:
    ```bash
    local curl_args=(-s -i --max-time 15 -X "$method" --cacert /path/to/your/haproxy_files/certs/ca.crt)
    ```
    Replace `/path/to/your/haproxy_files/certs/ca.crt` with the actual path.

---

## Step 4: Automating Ephemeral Certificate Generation

Generating certificates at deployment time ensures they are fresh and avoids committing them to the repository.

### Option A: Using a Shell Script

Create a `generate_certs.sh` script to run the OpenSSL commands from Step 1.

```bash
#!/usr/bin/env bash
set -e # Exit on error

CERT_DIR_PARAM=${1:-"./haproxy_files/certs"} # Default path, can be overridden

CERT_DIR=$(realpath "$CERT_DIR_PARAM")
DAYS_VALID=365
CA_SUBJ="/CN=MyDemoCA"
SERVER_SUBJ="/CN=localhost" # IMPORTANT: Match how HAProxy will be accessed
SERVER_SANS="DNS:localhost,IP:127.0.0.1" # Add other DNS names or IPs if needed

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo "Generating CA key and certificate in $CERT_DIR..."
openssl genpkey -algorithm RSA -out ca.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -x509 -key ca.key -out ca.crt -days "$DAYS_VALID" -subj "$CA_SUBJ"

echo "Generating server key and CSR..."
openssl genpkey -algorithm RSA -out server.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -key server.key -out server.csr -subj "$SERVER_SUBJ"

echo "Signing server certificate with CA..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt \
  -days "$DAYS_VALID" -sha256 \
  -extfile <(printf "subjectAltName=%s" "$SERVER_SANS")

echo "Creating server.pem for HAProxy..."
cat server.crt server.key > server.pem

echo "Certificates generated in $CERT_DIR:"
ls -l ca.crt server.crt server.pem

cd - > /dev/null
echo "Certificate generation complete."
```
Make this script executable (`chmod +x generate_certs.sh`) and run it before starting HAProxy.

### Option B: Using Terraform with the `tls` Provider

If using Terraform, the `hashicorp/tls` provider can generate self-signed certificates.

```terraform
terraform {
  required_providers {
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    local = {
      source = "hashicorp/local"
      version = "~> 2.1"
    }
  }
}

# Generate a private key for the server
resource "tls_private_key" "server_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

# Generate a self-signed certificate for the server
resource "tls_self_signed_cert" "server_cert" {
  private_key_pem = tls_private_key.server_key.private_key_pem

  subject {
    common_name  = "localhost" # Or your target hostname for HAProxy
    organization = "Demo Org"
  }

  dns_names    = ["localhost"]
  ip_addresses = ["127.0.0.1"]

  validity_period_hours = 24 * 30 # Valid for 30 days

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

# Combine certificate and key into a PEM bundle for HAProxy
locals {
  server_pem_content = "${tls_self_signed_cert.server_cert.cert_pem}${tls_private_key.server_key.private_key_pem}"
}

# Save the server.pem file
resource "local_file" "server_pem_file" {
  content  = local.server_pem_content
  # Adjust filename path as needed, e.g., relative to your Terraform execution
  filename = "./haproxy_files/certs/server.pem"
}
```
This Terraform configuration will generate `server.pem` in `./haproxy_files/certs/server.pem` (relative to where Terraform is run) each time `terraform apply` is executed.

---

By following these steps, TLS can be enabled for the HAProxy instance, allowing the `api_tester.sh` script to communicate with it securely over HTTPS.