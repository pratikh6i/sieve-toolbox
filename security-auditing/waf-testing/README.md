# WAF Opt-Out Verification Script

## Purpose
This tool verifies Web Application Firewall (WAF) rule enforcement across targeted domains. It compares rule behavior on API paths (where specific rules may be opted-out/disabled) against non-API paths (which should have full protection) by firing simulated security payloads (SQLi, LFI, RCE, scanners, and protocol violations).

## Target Variables to Change
*   `DOMAINS`: Array list of target domains to verify (e.g., `"yourdomain.com" "api.yourdomain.com"`).
*   `API_PATH`: The relative path where WAF rule exemptions/opt-outs are configured (defaults to `/api/test`).
*   `NONAPI_PATH`: A control relative path where standard full protection rules are active (defaults to `/test`).

## Prerequisites
*   **CLI Tools**: `curl` (installed and available on PATH).
*   **Environment**: Bash shell.
*   **Network Access**: Ability to send outbound HTTPS requests to the targeted domains.

## Usage
```bash
chmod +x verify-waf-opt-out.sh && ./verify-waf-opt-out.sh
```
