#!/bin/bash
# ==============================================================================
# GCP Compute Instance Security Audit Script (Optimized & Interactive v4)
# Gathers data, including instance status, IAM roles, and hardening settings,
# and generates recommendations. Interactive prompts are printed
# to the console (stderr), while CSV data is printed to standard output,
# allowing for clean file redirection.
#
# Requirements:
# - gcloud CLI authenticated
# - jq installed
# - IAM: Compute Viewer, Service Usage Viewer, Project IAM Viewer
#
# Author: Gemini (Based on user request)
# ==============================================================================

# Define the default list of projects
PROJECT_IDS_LIST=(
  "pickme-production-210708"
  "pickme-dataprod"
  "webcrm-246408"
  "navision-2021"
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
echo "Project ID,Instance Name,Zone,Instance Status,Public IP Type,Public IP Address,Service Account,Service Account Roles,API Scopes,Deletion Protection,Project-Wide SSH Keys Blocked,OS Config,Confidential Compute,Secure Boot,vTPM,Integrity Monitoring,Serial Port,Patch Manager Status,Recommendation"

# A function to build recommendation text
build_recommendations() {
  local sa="$1" default_sa="$2" api_scopes="$3" ip_type="$4" secure_boot="$5" vtpm="$6" integrity_monitoring="$7"
  local deletion_status="$8" ssh_key_status="$9" sa_roles="${10}"
  declare -a rec_parts

  if [[ "$sa" == "$default_sa" && "$api_scopes" == "cloud-platform (Full API Access)" ]]; then
    rec_parts+=("Instance uses the default SA with full API access. Create a dedicated SA with least-privilege roles.")
  fi
  if [[ "$ip_type" != "None" ]]; then
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
  if [[ "$deletion_status" == "Disabled" ]]; then
      rec_parts+=("Enable Deletion Protection for critical instances.")
  fi
  if [[ "$ssh_key_status" != "Blocked" ]]; then
      rec_parts+=("Block project-wide SSH keys at the instance or project level.")
  fi
  if [[ "$sa_roles" == *"roles/editor"* || "$sa_roles" == *"roles/owner"* ]]; then
      rec_parts+=("SA has a primitive role (Owner/Editor). Use more granular predefined or custom roles following the principle of least privilege.")
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

  # Fetch the IAM policy for the entire project once to avoid repeated API calls.
  IAM_POLICY_JSON=$(gcloud projects get-iam-policy "$PROJECT_ID" --format="json" 2>/dev/null)
  if [[ -z "$IAM_POLICY_JSON" ]]; then
      echo "⚠️  Could not fetch IAM policy for ${PROJECT_ID}. Role information will be unavailable." >&2
  fi

  DEFAULT_SA="${PROJECT_NUM}-compute@developer.gserviceaccount.com"

  # gcloud and jq processing...
  gcloud compute instances list --format="json" --project="$PROJECT_ID" 2>/dev/null | jq -r --arg default_sa "$DEFAULT_SA" '
    .[] |
    [
      .name,
      (.zone | split("/")[-1]),
      .status,
      (.serviceAccounts[0].email // "N/A"),
      (if (.serviceAccounts[0].scopes | index("https://www.googleapis.com/auth/cloud-platform")) then "cloud-platform (Full API Access)" else "[" + ((.serviceAccounts[0].scopes // []) | map(gsub("https://www.googleapis.com/auth/"; "")) | join("; ")) + "]" end),
      (.networkInterfaces[0].accessConfigs[0].natIP // "N/A"),
      ((.networkInterfaces[0].accessConfigs | length > 0) // "false" | tostring),
      (.deletionProtection | tostring | ascii_upcase),
      ((.metadata.items[]? | select(.key == "block-project-ssh-keys") | .value) // "false" | tostring | ascii_upcase),
      ((.metadata.items[]? | select(.key == "enable-osconfig") | .value) // "false" | ascii_upcase),
      (.confidentialInstanceConfig.enableConfidentialCompute // "false" | tostring | ascii_upcase),
      (.shieldedInstanceConfig.enableSecureBoot // "false" | tostring | ascii_upcase),
      (.shieldedInstanceConfig.enableVtpm // "false" | tostring | ascii_upcase),
      (.shieldedInstanceConfig.enableIntegrityMonitoring // "false" | tostring | ascii_upcase),
      ((.metadata.items[]? | select(.key == "serial-port-enable") | .value) // "false")
    ] | @tsv
  ' | while IFS=$'\t' read -r NAME ZONE STATUS SA API_SCOPES CURRENT_PUBLIC_IP HAS_ACCESS_CONFIG DELETION_PROTECTION BLOCK_SSH_KEYS OS_CONFIG CONFIDENTIAL_COMPUTE SECURE_BOOT VTPM INTEGRITY_MONITORING SERIAL_ENABLED; do

    # --- IP Address Logic ---
    IP_TYPE="None"
    IP_ADDRESS="N/A"
    if [[ "$HAS_ACCESS_CONFIG" == "true" ]]; then
        if [[ "$STATUS" == "RUNNING" ]]; then
            IP_TYPE="Ephemeral or Static"
            IP_ADDRESS="$CURRENT_PUBLIC_IP"
        else # TERMINATED, STAGING, etc.
            if [[ "$CURRENT_PUBLIC_IP" != "N/A" ]]; then
                IP_TYPE="Static"
                IP_ADDRESS="$CURRENT_PUBLIC_IP"
            else
                IP_TYPE="Ephemeral"
                IP_ADDRESS="N/A (Assigned on Start)"
            fi
        fi
    fi

    # --- Deletion Protection & SSH Key Logic ---
    [[ "$DELETION_PROTECTION" == "TRUE" ]] && DELETION_STATUS="Enabled" || DELETION_STATUS="Disabled"
    [[ "$BLOCK_SSH_KEYS" == "TRUE" ]] && SSH_KEY_STATUS="Blocked" || SSH_KEY_STATUS="Allowed / Not Set"

    # --- Service Account Role Logic ---
    SA_ROLES="N/A"
    if [[ -n "$IAM_POLICY_JSON" && "$SA" != "N/A" ]]; then
        SA_MEMBER="serviceAccount:$SA"
        ROLES_FOUND=$(echo "$IAM_POLICY_JSON" | jq -r --arg sa_member "$SA_MEMBER" '
            .bindings[] | select(.members[] | contains($sa_member)) | .role
        ' | paste -sd '; ' -)

        if [[ -n "$ROLES_FOUND" ]]; then
            SA_ROLES="$ROLES_FOUND"
        else
            SA_ROLES="No project-level roles found"
        fi
    fi

    [[ "$SERIAL_ENABLED" == "true" ]] && SERIAL_PORT="Enabled" || SERIAL_PORT="Disabled"
    PATCH_STATUS="-"

    RECOMMENDATION=$(build_recommendations "$SA" "$DEFAULT_SA" "$API_SCOPES" "$IP_TYPE" "$SECURE_BOOT" "$VTPM" "$INTEGRITY_MONITORING" "$DELETION_STATUS" "$SSH_KEY_STATUS" "$SA_ROLES")

    # --- CSV Output ---
    printf "%s,%s,%s,%s,%s,%s,%s,\"%s\",\"%s\",%s,%s,%s,%s,%s,%s,%s,%s,%s,\"%s\"\n" \
      "$PROJECT_ID" "$NAME" "$ZONE" "$STATUS" "$IP_TYPE" "$IP_ADDRESS" "$SA" "$SA_ROLES" "$API_SCOPES" \
      "$DELETION_STATUS" "$SSH_KEY_STATUS" \
      "$OS_CONFIG" "$CONFIDENTIAL_COMPUTE" "$SECURE_BOOT" "$VTPM" "$INTEGRITY_MONITORING" \
      "$SERIAL_PORT" "$PATCH_STATUS" "$RECOMMENDATION"

  done
done

echo "✅ Done. Output saved to your file." >&2 
