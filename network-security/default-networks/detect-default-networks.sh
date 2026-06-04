#!/bin/bash
# ===================================================================================
# GCP DEFAULT VPC INVENTORY - ACCURATE NETWORK DETECTION
#
# Checks for the presence of default VPC networks across a list of GCP projects
# and inventories resources attached to them (VMs, GKE, LBs, Cloud SQL, etc.)
#
# - Delimiter: PIPE (|) for clean Google Sheets import
# - Internal lists (e.g., multiple VMs) are joined by commas inside the cell
# - Read-only: makes NO changes to your infrastructure
#
# Usage:
#   chmod +x detect-default-networks.sh
#   ./detect-default-networks.sh > default_vpc_report.csv
#   Import to Google Sheets using '|' as the Custom Separator.
# ===================================================================================

set -u

# --- Target Projects ---
# !!! IMPORTANT: Replace placeholder values with your actual GCP project IDs.
PROJECTS=(
  "YOUR_PROJECT_ID_1"
  "YOUR_PROJECT_ID_2"
  "YOUR_PROJECT_ID_3"
  # Add more project IDs as needed...
)

# HEADER: Using Pipe Delimiter
echo "Project ID|Default Network Exists?|Compute VMs|GKE Clusters|Load Balancers|Serverless VPC Connectors|Cloud SQL (Private)|Memorystore Redis|Memorystore Memcached|AlloyDB Clusters|Filestore Instances|PSA Peerings|User VPC Peerings|Cloud NAT|Notes"

safe_run() {
  local cmd="$1"
  local label="$2"
  echo "  Checking $label..." >&2

  local out=$(timeout 15s bash -c "$cmd" 2>&1) || true
  local cleaned=$(echo "$out" | grep -vE "^WARNING:|ERROR:|Usage:|For detailed information|The \[region\]|argument --region|Failed to find attribute" | grep -v "^Listed 0 items\.$")

  if echo "$out" | grep -qiE "not enabled|disabled|has not been used|permission denied|billing|not found"; then
    echo "No resource"
    echo "API disabled/not enabled ($label)" >&2
  elif echo "$out" | grep -qiE "timeout|Error parsing|Must be specified"; then
    echo "No resource"
    echo "Timeout/regional error ($label)" >&2
  elif [[ -z "$cleaned" ]]; then
    echo "No resource"
  else
    echo "$cleaned"
  fi
}

process_project() {
  local pid="$1"
  echo "Scanning $pid" >&2

  local line="$pid"
  local notes=""

  # Robust default network check
  echo "  Checking default network..." >&2
  describe_out=$(gcloud compute networks describe default --project="$pid" --format="value(name)" 2>&1)

  if [[ "$describe_out" == "default" ]]; then
    line="$line|Yes"
    echo "    Found default network" >&2
  else
    # Fallback to list if describe fails
    list_out=$(gcloud compute networks list --project="$pid" --filter="name=default" --format="value(name)" 2>/dev/null)
    if echo "$list_out" | grep -q "default"; then
      line="$line|Yes (describe failed, but list found)"
    else
      line="$line|No (not found or access issue)"
      notes="Check permissions or if default VPC deleted; describe error: $describe_out"
      # Fill empty columns with 'No resource' using PIPE
      line="$line|No resource|No resource|No resource|No resource|No resource|No resource|No resource|No resource|No resource|No resource|No resource|No resource|No resource|$notes"
      echo "$line"
      return
    fi
  fi

  # Helper to append fields with PIPE delimiter
  append_field() {
    local field_out="$1"
    # Replace newlines with commas so multiple resources stay in ONE cell
    local field=$(echo "$field_out" | tr '\n' ',' | sed 's/,$//')
    [[ -z "$field" || "$field" == "No resource" ]] && field="No resource"
    # Append with Pipe
    line="$line|$field"
  }

  # Resources
  append_field "$(safe_run "gcloud compute instances list --project='$pid' --filter='networkInterfaces.network~\"/networks/default$\"' --format='csv[no-heading](name,zone)'" "VMs")"
  append_field "$(safe_run "gcloud container clusters list --project='$pid' --filter='network=default' --format='csv[no-heading](name,location)'" "GKE")"
  append_field "$(safe_run "gcloud compute forwarding-rules list --project='$pid' --filter='network~\"/networks/default$\"' --format='csv[no-heading](name,region)'" "Load Balancers")"
  append_field "$(safe_run "gcloud compute networks vpc-access connectors list --project='$pid' --filter='network=default' --format='csv[no-heading](name,region)'" "VPC Connectors")"
  append_field "$(safe_run "gcloud sql instances list --project='$pid' --format='csv[no-heading](name,region,settings.ipConfiguration.privateNetwork)' | grep -F '/networks/default' | cut -d, -f1,2" "Cloud SQL")"
  append_field "$(safe_run "gcloud redis instances list --project='$pid' --format='csv[no-heading](name,region,authorizedNetwork)' | grep -F '/networks/default' | cut -d, -f1,2" "Redis")"
  append_field "$(safe_run "gcloud memcache instances list --project='$pid' --format='csv[no-heading](name,region,authorizedNetwork)' | grep -F '/networks/default' | cut -d, -f1,2" "Memcached")"
  append_field "$(safe_run "gcloud alloydb clusters list --project='$pid' --format='csv[no-heading](clusterName,location)'" "AlloyDB")"
  append_field "$(safe_run "gcloud filestore instances list --project='$pid' --format='csv[no-heading](name,location,networks.network)' | grep -F 'default' | cut -d, -f1,2" "Filestore")"
  append_field "$(safe_run "gcloud services vpc-peerings list --project='$pid' --network=default --format='csv[no-heading](peering,service)'" "PSA Peerings")"
  append_field "$(safe_run "gcloud compute networks peerings list --project='$pid' --network=default --format='csv[no-heading](name,state,peerNetwork)' | grep -v '^default,'" "User VPC Peerings")"
  append_field "$(safe_run "gcloud compute routers list --project='$pid' --format='csv[no-heading](name,region)'" "Cloud NAT")"

  # Append Notes
  line="$line|$notes"
  echo "$line"
  echo "Finished $pid" >&2
}

for p in "${PROJECTS[@]}"; do
  process_project "$p"
done

echo "Scan complete. Import to Sheets using '|' as Custom Separator." >&2
