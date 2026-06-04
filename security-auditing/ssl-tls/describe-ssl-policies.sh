#!/usr/bin/env bash

###############################################################################
# GCP SSL Policies Inventory Script
#
# Description:
#   This script inventories all SSL policies across a specified list of
#   Google Cloud projects and exports the results into a pipe-delimited CSV file.
#
# Prerequisites:
#   - Google Cloud SDK (`gcloud`) must be installed and authenticated.
#   - `jq` JSON processor must be installed.
#
###############################################################################

# -------------------------
# Configuration: Project IDs
# -------------------------
PROJECT_IDS=(
    "YOUR_PROJECT_ID_1" "YOUR_PROJECT_ID_2" "YOUR_PROJECT_ID_3" "YOUR_PROJECT_ID_4" "YOUR_PROJECT_ID_5"
)

# -------------------------
# Output File Configuration
# -------------------------
OUTPUT_FILE="gcp_ssl_policies_inventory.csv"
DELIMITER="|"

# -------------------------
# Pre-checks for required tools
# -------------------------
if ! command -v gcloud &> /dev/null; then
  echo "❌ Error: 'gcloud' is not installed. Please install the Google Cloud SDK."
  exit 1
fi

if ! command -v jq &> /dev/null; then
  echo "❌ Error: 'jq' is not installed. Please install it to parse JSON."
  exit 1
fi

# -------------------------
# CSV Header
# -------------------------
echo "ProjectID${DELIMITER}PolicyName${DELIMITER}MinTlsVersion${DELIMITER}Profile${DELIMITER}EnabledFeatures${DELIMITER}Description${DELIMITER}CreationTimestamp${DELIMITER}SelfLink" > "$OUTPUT_FILE"

# -------------------------
# Main Processing Loop
# -------------------------
for PROJECT_ID in "${PROJECT_IDS[@]}"; do
  echo "🔍 Processing project: ${PROJECT_ID}..."

  # List SSL policies
  POLICY_NAMES=$(gcloud compute ssl-policies list \
    --project="$PROJECT_ID" \
    --format="value(name)" 2>/dev/null)

  if [ $? -ne 0 ]; then
    echo "⚠️  Warning: Failed to list SSL policies for project '${PROJECT_ID}'. Skipping..."
    continue
  fi

  if [ -z "$POLICY_NAMES" ]; then
    echo "ℹ️  No SSL policies found in project '${PROJECT_ID}'."
    continue
  fi

  # Loop through each policy
  while IFS= read -r POLICY_NAME; do
    echo "   ➤ Describing policy: ${POLICY_NAME}..."

    # Get full JSON details of the policy
    POLICY_JSON=$(gcloud compute ssl-policies describe "$POLICY_NAME" \
      --project="$PROJECT_ID" \
      --format=json 2>/dev/null)

    if [ $? -ne 0 ] || [ -z "$POLICY_JSON" ]; then
      echo "   ⚠️  Warning: Failed to describe policy '${POLICY_NAME}' in project '${PROJECT_ID}'. Skipping..."
      continue
    fi

    # Extract fields using jq
    NAME=$(echo "$POLICY_JSON" | jq -r '.name // "N/A"')
    MIN_TLS_VERSION=$(echo "$POLICY_JSON" | jq -r '.minTlsVersion // "N/A"')
    PROFILE=$(echo "$POLICY_JSON" | jq -r '.profile // "N/A"')
    ENABLED_FEATURES=$(echo "$POLICY_JSON" | jq -r '[.enabledFeatures[]?] | "[" + join(",") + "]"')
    DESCRIPTION=$(echo "$POLICY_JSON" | jq -r '.description // "N/A"' | tr -d '\n' | tr -d '\r')
    CREATION_TIMESTAMP=$(echo "$POLICY_JSON" | jq -r '.creationTimestamp // "N/A"')
    SELF_LINK=$(echo "$POLICY_JSON" | jq -r '.selfLink // "N/A"')

    # Handle empty enabledFeatures explicitly
    if [ "$ENABLED_FEATURES" == "[]" ]; then
      ENABLED_FEATURES="[]"
    fi

    # Output to CSV
    echo "${PROJECT_ID}${DELIMITER}${NAME}${DELIMITER}${MIN_TLS_VERSION}${DELIMITER}${PROFILE}${DELIMITER}${ENABLED_FEATURES}${DELIMITER}${DESCRIPTION}${DELIMITER}${CREATION_TIMESTAMP}${DELIMITER}${SELF_LINK}" >> "$OUTPUT_FILE"

  done <<< "$POLICY_NAMES"
done

# -------------------------
# Completion Message
# -------------------------
echo "✅ Inventory complete. Output saved to: $OUTPUT_FILE"
