#!/bin/bash

# Prompt the user for their Google Cloud Project ID
read -p "Please enter your Google Cloud Project ID: " PROJECT_ID

# Check if the project ID is provided
if [ -z "$PROJECT_ID" ]; then
    echo "Project ID is required."
    exit 1
fi

echo "--------------------------------------------------------------------------------"
echo "Scanning instance scopes in project: $PROJECT_ID"
echo "--------------------------------------------------------------------------------"

# Use a single, efficient gcloud call to get all instance data as JSON
gcloud compute instances list --project="$PROJECT_ID" --format="json" | \
# Use jq to stream each instance object
jq -c '.[]' | while read -r instance; do

    INSTANCE_NAME=$(echo "$instance" | jq -r '.name')
    SCOPES=$(echo "$instance" | jq -r '.serviceAccounts[0].scopes[]' 2>/dev/null)

    # If there are no scopes, it's using default access.
    if [ -z "$SCOPES" ]; then
        printf "INFO:    %-40s || Scope: Default Access\n" "$INSTANCE_NAME"
        continue
    fi

    # Count the number of scopes configured for the instance
    SCOPE_COUNT=$(echo "$SCOPES" | wc -l)

    # Check if the 'cloud-platform' scope exists
    HAS_CLOUD_PLATFORM=$(echo "$SCOPES" | grep -c "https://www.googleapis.com/auth/cloud-platform")

    # --- NEW LOGIC ---
    # 1. If 'cloud-platform' exists AND it's the ONLY scope, it's true Full Access.
    if [ "$HAS_CLOUD_PLATFORM" -eq 1 ] && [ "$SCOPE_COUNT" -eq 1 ]; then
        printf "🔴 FULL ACCESS:    %-40s || Configuration: Full Access to all Cloud APIs\n" "$INSTANCE_NAME"

    # 2. If 'cloud-platform' exists but there are OTHER scopes, it's Custom Access.
    elif [ "$HAS_CLOUD_PLATFORM" -eq 1 ]; then
        printf "🟡 CUSTOM ACCESS:  %-40s || Configuration: Includes 'cloud-platform' among %s scopes\n" "$INSTANCE_NAME" "$SCOPE_COUNT"

    # 3. If 'cloud-platform' does not exist, it's a standard custom configuration.
    else
        printf "INFO:    %-40s || Configuration: Custom with %s scopes (no 'cloud-platform')\n" "$INSTANCE_NAME" "$SCOPE_COUNT"
    fi
done

echo "--------------------------------------------------------------------------------"
echo "✅ Scan complete." 
