#!/usr/bin/env bash

# --- Configuration ---
# *** EDIT THIS LIST WITH THE FEATURES YOU WANT TO DISABLE ***
FEATURES_TO_DISABLE=(
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    "TLS_RSA_WITH_AES_128_CBC_SHA"
    "TLS_RSA_WITH_AES_128_GCM_SHA256"
    "TLS_RSA_WITH_AES_256_CBC_SHA"
    "TLS_RSA_WITH_AES_256_GCM_SHA384"
)

# --- Main Logic ---

echo "--- Interactive SSL Policy Hardening Script ---"

# 1. Ask for the Project ID
read -p "Enter the GCP Project ID: " PROJECT_ID
if [ -z "$PROJECT_ID" ]; then
    echo "ERROR: Project ID cannot be empty. Aborting."
    exit 1
fi

# 2. Ask for the SSL Policy Name
read -p "Enter the SSL Policy Name to modify: " POLICY_NAME
if [ -z "$POLICY_NAME" ]; then
    echo "ERROR: SSL Policy Name cannot be empty. Aborting."
    exit 1
fi

echo "--------------------------------------------------------"
echo "Project: $PROJECT_ID"
echo "Policy:  $POLICY_NAME"
echo "--------------------------------------------------------"
echo "Analyzing..."

# Set the gcloud context.
if ! gcloud config set project "$PROJECT_ID" >/dev/null 2>&1; then
    echo "ERROR: Could not set project to '$PROJECT_ID'. Check if the project exists or you have permission." >&2
    exit 1
fi

# Get policy details, checking global scope first, then regional.
DESCRIBE_JSON=$(gcloud compute ssl-policies describe "$POLICY_NAME" --global --format="json" 2>/dev/null)
REGION_FLAG="--global"
if [ -z "$DESCRIBE_JSON" ]; then
    DESCRIBE_JSON=$(gcloud compute ssl-policies describe "$POLICY_NAME" --format="json" 2>/dev/null)
    if [ -n "$DESCRIBE_JSON" ]; then
       SCOPE=$(echo "$DESCRIBE_JSON" | jq -r '.region | sub(".*/"; "")')
       REGION_FLAG="--region=$SCOPE"
    fi
fi

#
# === SCRIPT GUARDS ===
#
if [ -z "$DESCRIBE_JSON" ]; then
    echo "SKIPPING: Policy '$POLICY_NAME' not found in project '$PROJECT_ID'."
    exit 1
fi

PROFILE_TYPE=$(echo "$DESCRIBE_JSON" | jq -r '.profile // "N/A"')
if [ "$PROFILE_TYPE" != "CUSTOM" ]; then
    echo "SKIPPING: Policy profile is '$PROFILE_TYPE', not 'CUSTOM'. No changes will be made."
    exit 1
fi

#
# === CHECK FOR REQUIRED CHANGES ===
#
MIN_TLS_VERSION=$(echo "$DESCRIBE_JSON" | jq -r '.minTlsVersion // "N/A"')
CURRENT_FEATURES_CSV=$(echo "$DESCRIBE_JSON" | jq -r '.customFeatures // [] | join(",")')

# 1. Check if TLS version needs to be upgraded
tls_needs_upgrade=false
if [[ "$MIN_TLS_VERSION" == "TLS_1_0" || "$MIN_TLS_VERSION" == "TLS_1_1" ]]; then
    tls_needs_upgrade=true
fi

# 2. Check if features need to be removed
new_features_csv="$CURRENT_FEATURES_CSV"
features_changed=false
for feature in "${FEATURES_TO_DISABLE[@]}"; do
    if [[ ",$new_features_csv," == *",$feature,"* ]]; then
        cleared_csv=$(echo ",$new_features_csv," | sed "s/,$feature,/,/g")
        new_features_csv=$(echo "$cleared_csv" | sed 's/^,//;s/,$//')
        features_changed=true
    fi
done

#
# === APPLY CHANGES IF ANY ARE NEEDED ===
#
if [ "$features_changed" = true ] || [ "$tls_needs_upgrade" = true ]; then
    echo "Action: Updating policy..."
    
    TLS_UPDATE_FLAG=()
    if [ "$tls_needs_upgrade" = true ]; then
        echo "  - Setting min TLS version to 1.2"
        TLS_UPDATE_FLAG=(--min-tls-version "1.2")
    fi
    
    if [ "$features_changed" = true ]; then
         echo "  - Removing specified features."
    fi

    gcloud compute ssl-policies update "$POLICY_NAME" \
        $REGION_FLAG \
        "${TLS_UPDATE_FLAG[@]}" \
        --custom-features "$new_features_csv" \
        --quiet

    if [ $? -eq 0 ]; then
        echo "SUCCESS: Policy '$POLICY_NAME' updated."
    else
        echo "ERROR: Failed to update policy '$POLICY_NAME'."
    fi
else
    echo "SKIPPING: Policy is already compliant. No changes needed."
fi

echo "--------------------------------------------------------"
echo "Script completed."
