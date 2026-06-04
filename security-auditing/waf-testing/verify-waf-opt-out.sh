#!/bin/bash
# WAF Opt-Out Verification — Fire all payloads at both branches, both domains.
# Purpose: Verify WAF rule enforcement on API paths (opted-out) vs non-API paths (full protection)

DOMAINS=("YOUR_DOMAIN_1" "YOUR_DOMAIN_2")

# Path that MATCHES the rule (opt-out active) vs path that does NOT (full protection)
API_PATH="/api/test"
NONAPI_PATH="/test"

# Function to send HTTP request and capture status code
hit() {
  local label="$1"
  local url="$2"
  shift 2
  
  printf "%-45s -> " "$label"
  curl -s -o /dev/null -w "%{http_code}\n" "$@" "$url"
  sleep 1  # spacing so log timestamps are easy to separate
}

# Iterate through domains and fire payloads
for D in "${DOMAINS[@]}"; do
  echo "==================== $D ===================="
  
  # ---- SQLi 942100 (libinjection) ----
  hit "SQLi 942100 [API/opted-out]" "https://$D$API_PATH?id=1'%20OR%20'1'='1"
  hit "SQLi 942100 [non-API/full]" "https://$D$NONAPI_PATH?id=1'%20OR%20'1'='1"
  
  # ---- SQLi 942190 (MSSQL/info-gathering) ----
  hit "SQLi 942190 [API/opted-out]" "https://$D$API_PATH?id=1;WAITFOR%20DELAY%20'0:0:5'--"
  hit "SQLi 942190 [non-API/full]" "https://$D$NONAPI_PATH?id=1;WAITFOR%20DELAY%20'0:0:5'--"
  
  # ---- LFI 930110 (path traversal ../) ----
  hit "LFI 930110 [API/opted-out]" "https://$D$API_PATH?file=../../../../etc/passwd"
  hit "LFI 930110 [non-API/full]" "https://$D$NONAPI_PATH?file=../../../../etc/passwd"
  
  # ---- LFI 930130 (restricted file access) ----
  hit "LFI 930130 [API/opted-out]" "https://$D$API_PATH?file=/etc/passwd"
  hit "LFI 930130 [non-API/full]" "https://$D$NONAPI_PATH?file=/etc/passwd"
  
  # ---- RCE 932190 (wildcard bypass) ----
  hit "RCE 932190 [API/opted-out]" "https://$D$API_PATH?cmd=/bin/c?t%20/etc/passwd"
  hit "RCE 932190 [non-API/full]" "https://$D$NONAPI_PATH?cmd=/bin/c?t%20/etc/passwd"
  
  # ---- RCE 932200 (Unix shell expression) ----
  # NOTE: 932200 is opted out on BOTH branches (API rule + old rule 103), so it should be absent everywhere
  hit "RCE 932200 [API/opted-out]" "https://$D$API_PATH?cmd=\${IFS}cat\${IFS}/etc/passwd"
  hit "RCE 932200 [non-API/full]" "https://$D$NONAPI_PATH?cmd=\${IFS}cat\${IFS}/etc/passwd"
  
  # ---- Scanner 913100 (known scanner UA) ----
  hit "SCAN 913100 [API/opted-out]" "https://$D$API_PATH" -A "sqlmap/1.5.2"
  hit "SCAN 913100 [non-API/full]" "https://$D$NONAPI_PATH" -A "sqlmap/1.5.2"
  
  # ---- Scanner 913101 (scripting/generic client UA) ----
  hit "SCAN 913101 [API/opted-out]" "https://$D$API_PATH" -A "python-requests/2.31.0"
  hit "SCAN 913101 [non-API/full]" "https://$D$NONAPI_PATH" -A "python-requests/2.31.0"
  
  # ---- Scanner 913102 (crawler/bot UA) ----
  hit "SCAN 913102 [API/opted-out]" "https://$D$API_PATH" -A "Googlebot-Image/1.0"
  hit "SCAN 913102 [non-API/full]" "https://$D$NONAPI_PATH" -A "Googlebot-Image/1.0"
  
  # ---- Protocol 921150 (CRLF / header injection) ----
  hit "PROTO 921150 [API/opted-out]" "https://$D$API_PATH?x=%0d%0aSet-Cookie:test=1"
  hit "PROTO 921150 [non-API/full]" "https://$D$NONAPI_PATH?x=%0d%0aSet-Cookie:test=1"
  
done

echo "Done"
