# api-traffic-generator

[![Test Traffic Generator](https://github.com/allthingsclowd/api-traffic-generator/actions/workflows/test_traffic_generator.yml/badge.svg)](https://github.com/allthingsclowd/api-traffic-generator/actions/workflows/test_traffic_generator.yml)

This repository contains a sophisticated API traffic generator script (`api_tester.sh`) designed to simulate diverse API interactions. It's primarily used for testing API security postures, including policy enforcement, and the detection capabilities of API security solutions.

The original motivation for this repository was to provide a reliable way to fetch the `api_tester.sh` script and its associated `haproxy.cfg` to a build server, especially when direct inclusion (e.g., in cloud-init user data) became problematic due to size constraints.

## Future Enhancement: TLS Enablement

This project currently simulates HTTP traffic. For instructions on how to enable TLS/HTTPS for a more comprehensive testing scenario, including generating self-signed certificates and configuring HAProxy and the client script accordingly, please refer to the following document:

*   FutureTLSEnhancement.md

This outlines the steps for a potential future update.
## What it Does

The `api_tester.sh` script generates a variety of HTTP requests to a target API endpoint (configurable, defaults to `http://localhost`). It aims to mimic real-world API traffic, including:

*   **Valid User Traffic:** Simulates legitimate requests to various API endpoints across different service categories (e.g., eShop, HR, Finance, Products, Banking).
*   **Governance Policy Violations:** Sends requests designed to trigger API governance policies, such as:
    *   Open registration attempts.
    *   Tests for insecure cookie configurations.
    *   Missing security headers.
    *   Unrestricted HTTP methods.
    *   Leaky headers containing PII.
    *   Requests missing authentication.
    *   Access to unencrypted endpoints.
    *   Endpoints missing Content Security Policy (CSP).
    *   Cleartext authentication attempts.
*   **OWASP API Security Top 10 Patterns:** Generates traffic patterns that align with common API vulnerabilities, including:
    *   Broken Object Level Authorization (BOLA)
    *   Broken Authentication
    *   Excessive Data Exposure
    *   Lack of Resources & Rate Limiting
    *   Broken Function Level Authorization (BFLA)
    *   Mass Assignment
    *   Security Misconfiguration
    *   Injection (SQLi, XSS, XML, NoSQL)
    *   Improper Assets Management (e.g., hitting shadow/zombie APIs)
    *   Unsafe Consumption of APIs (e.g., malformed JSON/XML)
*   **Shadow & Zombie API Traffic:** Targets undocumented or supposedly decommissioned API endpoints to test for their presence and behavior.
*   **Drifted API Traffic:** Hits API endpoints that might exist but are not part of the formal API specification (e.g., beta or internal versions).

## How it Works

### `api_tester.sh` Script Logic:

1.  **Configuration:**
    *   Sets a target host (defaults to `http://localhost`).
    *   Defines arrays of API endpoints for different categories (regular, governance, OWASP, shadow/zombie, drifted).
    *   Specifies user personas, roles, HTTP methods, and various malicious/PII payloads.
2.  **Request Generation:**
    *   Runs in a loop for a configurable duration (default: 180 seconds).
    *   In each iteration, it randomly selects a simulation type (valid traffic, governance violation, OWASP attack, or shadow/zombie/drifted API traffic).
    *   Based on the simulation type, it randomly chooses:
        *   An API endpoint from the relevant list.
        *   An HTTP method.
        *   A user and role (which influences headers like `Authorization` and `X-API-Key`).
        *   A payload (realistic JSON for POST/PUT, or malicious payloads for attack simulations).
        *   Specific headers to simulate different conditions (e.g., PII in headers, custom `Content-Type`).
3.  **API Interaction:**
    *   Uses `curl` to send the constructed HTTP request.
    *   Includes various headers like `User-Agent`, `X-Request-ID`, `X-Forwarded-For`, `Protocol`, and `X-Role`.
4.  **Response Parsing & Logging:**
    *   Includes various headers like `X-Request-ID`, `Protocol`, and `X-Role`.
    *   Sets the `User-Agent` header by randomly selecting from a diverse list of common browser, mobile, bot, and API client User-Agents, and appends `APITrafficGenerator/3.2.0` to the end for identification.
    *   Generates a more realistic `X-Forwarded-For` header containing a chain of three random IP addresses.
    *   Adds a simulated `X-JA3-Fingerprint` header with a randomly selected JA3 hash to mimic different client TLS fingerprints.
    *   Parses these components.
    *   Logs detailed information about each request and its corresponding response to a timestamped log file in `/tmp/` and also to standard output (which is then captured by the GitHub Actions workflow).

### HAProxy Configuration (`haproxy.cfg`):

The `haproxy.cfg` file included in this repository is crucial for the testing setup. It configures HAProxy to act as a reverse proxy and, more importantly, to **simulate/stub backend API services**.

1.  **Frontend (`http_frontend`):**
    *   Listens on port 80.
    *   Uses Access Control Lists (ACLs) based on request paths to identify different types of API traffic (e.g., `/hr/*`, `/finance/*`, `/shadow-api/*`, `/eshop/catalog/products-beta`).
    *   Contains `use_backend` directives to route requests to the appropriate backend based on these ACLs.
    *   Sets some common response headers.

2.  **Backends (e.g., `hr_backend`, `finance_backend`, `shadow_api_backend`, `drifted_api_backend`):**
    *   Each backend is responsible for a specific API service or category.
    *   Instead of forwarding requests to real backend servers, these backends use HAProxy's `http-request return` directive.
    *   This directive allows HAProxy to immediately return a predefined HTTP response, including:
        *   A specific status code (e.g., 200, 201, 202).
        *   A `Content-Type` (typically `application/json`).
        *   A JSON string body containing a simulated response message. These messages often include unique identifiers (e.g., "SIMULATED-HR-123", "Drifted API Response: BETA-001") that the test workflow checks for.
    *   They also set specific response headers relevant to the simulated service (e.g., `X-Backend-Service`, `X-Request-ID`).
    *   Each mock backend includes a `server dummy 127.0.0.1:1 check disabled` line. This provides HAProxy with a nominal server entry, which, even though disabled, can prevent HAProxy from immediately concluding "no server is available" and allows the `http-request return` rules to be processed correctly.

## Testing Methodology

The functionality of the `api_tester.sh` script and the HAProxy setup is validated through a GitHub Actions workflow defined in `.github/workflows/test_traffic_generator.yml`. Here's how it works:

1.  **Setup Environment:**
    *   Checks out the repository code.
    *   Creates a local directory for HAProxy configuration files.
    *   Copies the `haproxy.cfg` and any necessary icon files (like `favicon32tp.png`) into this local directory.
2.  **Start HAProxy:**
    *   Runs HAProxy as a Docker container, mounting the local configuration directory.
    *   Waits for HAProxy to become ready by periodically checking a known endpoint (e.g., `/favicon.ico`).
3.  **Run Traffic Generator:**
    *   Makes the `api_tester.sh` script executable.
    *   Executes `api_tester.sh`, directing it to send traffic to `http://localhost:80` (where HAProxy is listening).
    *   The script's standard output (which includes detailed logging of requests and responses) is tee'd to a file in the workspace (`api_tester_console_output.log`). The script also generates its own primary log file in `/tmp/` (e.g., `/tmp/api_tester_YYYY-MM-DD_HH-MM-SS.log`).
4.  **Verify Results:**
    *   A subsequent step in the workflow (`Check log file for expected patterns`) examines the content of the `api_tester_console_output.log` file.
    *   It searches for specific string patterns that are expected to be present in the responses from the HAProxy-simulated backends (e.g., "SIMULATED-HR-123", "Drifted API Response: BETA-001").
    *   If all expected patterns are found, the test passes. If any are missing, the test fails.
5.  **Cleanup:**
    *   Stops and removes the HAProxy Docker container.
    *   Uploads the generated log files as artifacts for inspection.

This testing process ensures that the traffic generator is correctly interacting with the HAProxy setup and that HAProxy is returning the expected simulated responses for various API paths.
