#!/bin/bash

# ==============================================================================
# GCP Compute Instance Security Audit Script (Optimized & Interactive)
#
# Gathers Shielded VM, API scope, public IP, and OS Config data per instance.
# Interactive prompts are printed to the console (stderr), while CSV data is
# printed to standard output, allowing for clean file redirection.
#
# Requirements:
# - gcloud CLI authenticated
# - jq installed
# - IAM: Compute Viewer + Service Usage Viewer
#
# Usage:
#   chmod +x audit-vm-security-profile.sh
#   ./audit-vm-security-profile.sh > vm_security_report.csv
# ==============================================================================

# Define the default list of projects
# !!! IMPORTANT: Replace placeholder values with your actual GCP project IDs.
PROJECT_IDS_LIST=(
  "YOUR_PROJECT_ID_1"
  "YOUR_PROJECT_ID_2"
  "YOUR_PROJECT_ID_3"
  "YOUR_PROJECT_ID_4"
)

# Make a copy to be used by the loop
PROJECT_IDS=("${PROJECT_IDS_LIST[@]}")

# --- Interactive Project Selection (Prints to Console/stderr) ---
echo "How do you want to select projects to scan?" >&2
echo "  1) Enter a single custom Project ID" >&2
echo "  2) Use the pre-defined project list from the script" >&2
read -p "Enter your choice (1 or 2): " choice

case $choice in
  1)
    read -p "Please enter the GCP Project ID to scan: " CUSTOM_PROJECT_ID
    if [[ -z "$CUSTOM_PROJECT_ID" ]]; then
        echo "❌ Error: Project ID cannot be empty. Exiting." >&2
        exit 1
    fi
    PROJECT_IDS=("$CUSTOM_PROJECT_ID")
    ;;
  2)
    echo "✅ Proceeding with the pre-defined project list..." >&2
    ;;
  *)
    echo "❌ Error: Invalid choice. Please run the script again and enter 1 or 2." >&2
    exit 1
    ;;
esac
# --- End of Interactive Section ---


# CSV Header (Prints to stdout, will go into the file)
echo "Project ID,Instance Name,Zone,Service Account,Has Public IP,Public IP Address,API Scopes,OS Config,Confidential Compute,Secure Boot,vTPM,Integrity Monitoring,Serial Port,Patch Manager Status,Recommendation"

# A function to build recommendation text
build_recommendations() {
  local sa="$1" default_sa="$2" api_scopes="$3" has_public_ip="$4" secure_boot="$5" vtpm="$6" integrity_monitoring="$7"
  declare -a rec_parts
  if [[ "$sa" == "$default_sa" && "$api_scopes" == "cloud-platform (Full API Access)" ]]; then
    rec_parts+=("Instance uses the default SA with full API access. Create a dedicated SA with least-privilege roles.")
  fi
  if [[ "$has_public_ip" == "Yes" ]]; then
    rec_parts+=("Review the need for its public IP.")
  fi
  if [[ "$secure_boot" == "FALSE" ]]; then
    rec_parts+=("Enable Secure Boot.")
  fi
  if [[ "$vtpm" == "FALSE" ]]; then
    rec_parts+=("Enable vTPM.")
  fi
  if [[ "$integrity_monitoring" == "FALSE" ]]; then
    rec_parts+=("Enable Integrity Monitoring.")
  fi
  (IFS=' '; echo "${rec_parts[*]}")
}

for PROJECT_ID in "${PROJECT_IDS[@]}"; do
  # Progress messages go to the console (stderr)
  echo "⚙️  Processing project: ${PROJECT_ID}..." >&2

  gcloud config set project "$PROJECT_ID" >/dev/null 2>&1
  PROJECT_NUM=$(gcloud projects describe "$PROJECT_ID" --format="value(projectNumber)" 2>/dev/null)
  if [[ -z "$PROJECT_NUM" ]]; then
      echo "⚠️  Could not find project ${PROJECT_ID} or you may not have permissions. Skipping." >&2
      continue
  fi
  DEFAULT_SA="${PROJECT_NUM}-compute@developer.gserviceaccount.com"

  # gcloud and jq processing...
  gcloud compute instances list --format="json" --project="$PROJECT_ID" 2>/dev/null | jq -r --arg default_sa "$DEFAULT_SA" '
    .[] |
    [
      .name,
      (.zone | split("/")[-1]),
      (.serviceAccounts[0].email // "N/A"),
      (if (.serviceAccounts[0].scopes | index("https://www.googleapis.com/auth/cloud-platform")) then "cloud-platform (Full API Access)" else "[" + ((.serviceAccounts[0].scopes // []) | map(gsub("https://www.googleapis.com/auth/"; "")) | join("; ")) + "]" end),
      (.networkInterfaces[0].accessConfigs[0].natIP // "N/A"),
      ((.metadata.items[]? | select(.key == "enable-osconfig") | .value) // "false" | ascii_upcase),
      (.confidentialInstanceConfig.enableConfidentialCompute // "false" | tostring | ascii_upcase),
      (.shieldedInstanceConfig.enableSecureBoot // "false" | tostring | ascii_upcase),
      (.shieldedInstanceConfig.enableVtpm // "false" | tostring | ascii_upcase),
      (.shieldedInstanceConfig.enableIntegrityMonitoring // "false" | tostring | ascii_upcase),
      ((.metadata.items[]? | select(.key == "serial-port-enable") | .value) // "false")
    ] | @tsv
  ' | while IFS=$'\t' read -r NAME ZONE SA API_SCOPES PUBLIC_IP OS_CONFIG CONFIDENTIAL_COMPUTE SECURE_BOOT VTPM INTEGRITY_MONITORING SERIAL_ENABLED; do

    [[ "$PUBLIC_IP" == "N/A" ]] && HAS_PUBLIC_IP="No" || HAS_PUBLIC_IP="Yes"
    [[ "$SERIAL_ENABLED" == "true" ]] && SERIAL_PORT="Enabled" || SERIAL_PORT="Disabled"
    PATCH_STATUS="-"
    RECOMMENDATION=$(build_recommendations "$SA" "$DEFAULT_SA" "$API_SCOPES" "$HAS_PUBLIC_IP" "$SECURE_BOOT" "$VTPM" "$INTEGRITY_MONITORING")

    # CSV data rows (Print to stdout, will go into the file)
    printf "%s,%s,%s,%s,%s,%s,\"%s\",%s,%s,%s,%s,%s,%s,%s,\"%s\"\n" \
      "$PROJECT_ID" "$NAME" "$ZONE" "$SA" "$HAS_PUBLIC_IP" "$PUBLIC_IP" "$API_SCOPES" \
      "$OS_CONFIG" "$CONFIDENTIAL_COMPUTE" "$SECURE_BOOT" "$VTPM" "$INTEGRITY_MONITORING" \
      "$SERIAL_PORT" "$PATCH_STATUS" "$RECOMMENDATION"
  done
done

echo "✅ Done. Output saved to your file." >&2
