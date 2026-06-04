#!/bin/bash

# ==============================================================================
# GCP Fast OS Audit (Parallelized, Org-Aware, Read-Only)
#
# Scans all accessible projects in a GCP organization for Compute Engine
# instances and detects their OS type (Windows vs Linux) using license metadata.
#
# Usage:
#   chmod +x audit-vm-os-licensing.sh
#   ./audit-vm-os-licensing.sh > windows_report.csv
#
# Requirements:
#   - gcloud CLI authenticated
#   - jq installed
#   - IAM: Compute Viewer (roles/compute.viewer) on target projects
# ==============================================================================

# --- 1. Interactive Input ---
# We ask for the Org ID to log it, but we scan ALL accessible projects to ensure
# we don't miss projects hidden inside Folders (which require extra APIs to map).
echo "Please enter the GCP Organization ID you wish to audit:" >&2
read -p "Org ID: " TARGET_ORG_ID

if [[ -z "$TARGET_ORG_ID" ]]; then
    echo "❌ Error: Organization ID cannot be empty." >&2
    exit 1
fi

echo "========================================================" >&2
echo "🚀 Starting Audit for Organization: $TARGET_ORG_ID" >&2
echo "ℹ️  Scanning all accessible active projects (skipping 'sys-' prefixes)..." >&2
echo "ℹ️  Mode: Read-Only | Threads: 20 | Target: Windows OS Detection" >&2
echo "========================================================" >&2

# --- 2. Define the Worker Function ---
# This function runs in parallel for each project.
audit_project() {
  local PROJECT_ID="$1"

  # A. Check API Status (Fastest check to fail early)
  local API_STATUS
  API_STATUS=$(gcloud services list --project "$PROJECT_ID" --enabled --filter="config.name:compute.googleapis.com" --format="value(config.name)" 2>/dev/null)

  # If API is not found/enabled, just return silently (skip)
  if [[ -z "$API_STATUS" ]]; then
    return
  fi

  # B. Fetch Instances (Includes RUNNING, STOPPED, SUSPENDED)
  local INSTANCE_DATA
  INSTANCE_DATA=$(gcloud compute instances list --format="json" --project="$PROJECT_ID" 2>/dev/null)

  # If no instances, return
  if [[ "$INSTANCE_DATA" == "[]" ]]; then
      return
  fi

  # C. Parse Data using jq
  echo "$INSTANCE_DATA" | jq -r --arg pid "$PROJECT_ID" '
    .[] |
    [
      $pid,
      .name,
      (.zone | split("/")[-1]),
      .status,
      # License Check (Best way to detect Windows)
      ((.disks[0].licenses // []) | join(",")),
      # Source Image Check (Fallback)
      (.disks[0].initializeParams.sourceImage // "N/A")
    ] | @tsv
  ' | while IFS=$'\t' read -r PID NAME ZONE STATUS LICENSES SOURCE_IMAGE; do

    IS_WINDOWS="No"
    OS_FAMILY="Linux/Other"

    # --- OS Detection Logic ---

    # 1. Check Licenses (Official Google Images)
    if [[ "$LICENSES" == *"windows-cloud"* ]]; then
        IS_WINDOWS="Yes"
        OS_FAMILY="Windows Server"
    elif [[ "$LICENSES" == *"rhel-cloud"* ]]; then
        OS_FAMILY="Red Hat (RHEL)"
    elif [[ "$LICENSES" == *"ubuntu-os-cloud"* ]]; then
        OS_FAMILY="Ubuntu"
    elif [[ "$LICENSES" == *"debian-cloud"* ]]; then
        OS_FAMILY="Debian"
    elif [[ "$LICENSES" == *"centos-cloud"* ]]; then
        OS_FAMILY="CentOS"
    elif [[ "$LICENSES" == *"suse-cloud"* ]]; then
        OS_FAMILY="SUSE"
    fi

    # 2. Fallback: Check Image Name (Custom Images)
    if [[ "$OS_FAMILY" == "Linux/Other" ]]; then
        if [[ "$SOURCE_IMAGE" == *"windows"* ]]; then
            IS_WINDOWS="Yes"
            OS_FAMILY="Windows (Custom Image)"
        fi
    fi

    # Output Row to CSV (Standard Output)
    printf "%s,%s,%s,%s,%s,%s\n" \
      "$PID" "$NAME" "$ZONE" "$STATUS" "$IS_WINDOWS" "$OS_FAMILY"
  done
}

# Export function so xargs can see it
export -f audit_project

# --- 3. Main Execution ---

# Print CSV Header
echo "Project ID,Instance Name,Zone,Status,Is Windows?,Detected OS Family"

# Get List of Projects
# - filter="lifecycleState:ACTIVE": Only active projects
# - grep -v "^sys-": REMOVES any project starting with "sys-"
PROJECT_LIST=$(gcloud projects list --filter="lifecycleState:ACTIVE" --format="value(projectId)" 2>/dev/null | grep -v "^sys-")

COUNT=$(echo "$PROJECT_LIST" | wc -l)
echo "✅ Found $COUNT candidate projects. Processing..." >&2

# Run in Parallel
# -P 20: Run 20 checks simultaneously
# -I {}: Replace {} with the Project ID
echo "$PROJECT_LIST" | xargs -P 20 -I {} bash -c 'audit_project "{}"'

echo "✅ Audit Complete." >&2
