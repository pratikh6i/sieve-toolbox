#!/bin/bash

PROJECTS_TO_SCAN=(
  "YOUR_PROJECT_ID_1"
  "YOUR_PROJECT_ID_2"
  "YOUR_PROJECT_ID_3"
  "YOUR_PROJECT_ID_4"
)

# output delimiter
SEP='|||'

# Print Header
echo "Project_ID${SEP}Scope${SEP}Policy_Name${SEP}Min_TLS_Version${SEP}Profile${SEP}Enabled_Features${SEP}Custom_Features${SEP}In Use by"

for project_id in "${PROJECTS_TO_SCAN[@]}"; do
    
    # 1. Setup Project
    gcloud config set project "$project_id" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "ERROR: Could not set project to '$project_id'. Skipping." >&2
        continue
    fi

    # 2. Inventory: Get all Proxies (HTTPS and SSL) to map usage
    # ---------------------------------------------------------
    
    # Fetch HTTPS Proxies safely
    RAW_HTTPS=$(gcloud compute target-https-proxies list --format="json" 2>/dev/null)
    if [ -z "$RAW_HTTPS" ]; then RAW_HTTPS="[]"; fi

    # Fetch SSL Proxies safely
    RAW_SSL=$(gcloud compute target-ssl-proxies list --format="json" 2>/dev/null)
    if [ -z "$RAW_SSL" ]; then RAW_SSL="[]"; fi

    # Combine them safely
    PROXY_MAP_JSON=$(echo "$RAW_HTTPS $RAW_SSL" | jq -s '
        add 
        | map({
            name: .name, 
            policy: (if .sslPolicy then (.sslPolicy | split("/") | last) else "GCP_DEFAULT" end)
          }) 
        | group_by(.policy) 
        | map({
            key: .[0].policy, 
            value: (map(.name) | sort | join(", "))
          }) 
        | from_entries' 2>/dev/null)

    # 3. Inventory: Get Defined SSL Policies
    # ---------------------------------------------------------
    ALL_POLICIES_JSON=$(gcloud compute ssl-policies list --format="json" 2>/dev/null)

    # 4. Processing Defined Policies
    # ---------------------------------------------------------
    if [ -n "$ALL_POLICIES_JSON" ] && [ "$(echo "$ALL_POLICIES_JSON" | jq 'length')" -gt 0 ]; then
        
        echo "$ALL_POLICIES_JSON" | jq -c '.[]' | while read -r policy_json; do
            POLICY_NAME=$(echo "$policy_json" | jq -r '.name')
            PROFILE=$(echo "$policy_json" | jq -r '.profile // "N/A"')
            MIN_TLS_VERSION=$(echo "$policy_json" | jq -r '.minTlsVersion // "N/A"')
            
            # Determine Scope
            SCOPE=$(echo "$policy_json" | jq -r 'if .region then (.region | sub(".*/"; "")) else "global" end')
            REGION_FLAG=""
            if [ "$SCOPE" != "global" ]; then
                REGION_FLAG="--region=$SCOPE"
            fi

            ENABLED_FEATURES="N/A"
            CUSTOM_FEATURES="N/A"

            # Logic to get Features (Ciphers) - CHANGED join("\n") to join(", ")
            if [ "$PROFILE" == "CUSTOM" ]; then
                CUSTOM_FEATURES=$(echo "$policy_json" | jq -r 'if (.customFeatures? | length) > 0 then (.customFeatures | join(", ")) else "N/A" end')
            else
                DESCRIBE_JSON=$(gcloud compute ssl-policies describe "$POLICY_NAME" $REGION_FLAG --format="json" 2>/dev/null)
                if [ -n "$DESCRIBE_JSON" ]; then
                    ENABLED_FEATURES=$(echo "$DESCRIBE_JSON" | jq -r 'if (.enabledFeatures? | length) > 0 then (.enabledFeatures | join(", ")) else "N/A" end')
                fi
            fi

            # Check Usage from our Proxy Map
            IN_USE_BY=$(echo "$PROXY_MAP_JSON" | jq -r --arg pol "$POLICY_NAME" '.[$pol] // "N/A"')

            # Output Row
            printf "%s${SEP}%s${SEP}%s${SEP}%s${SEP}%s${SEP}%s${SEP}%s${SEP}%s\n" \
                "$project_id" "$SCOPE" "$POLICY_NAME" "$MIN_TLS_VERSION" "$PROFILE" "$ENABLED_FEATURES" "$CUSTOM_FEATURES" "$IN_USE_BY"
        done
    fi

    # 5. Processing "GCP default" (Proxies with no policy attached)
    # ---------------------------------------------------------
    if [ -n "$PROXY_MAP_JSON" ]; then
        DEFAULT_USAGE=$(echo "$PROXY_MAP_JSON" | jq -r '.["GCP_DEFAULT"] // empty')
        
        if [ -n "$DEFAULT_USAGE" ]; then
            # Get the actual list of features for 'COMPATIBLE' profile
            # CHANGED join("\n") to join(", ")
            DEFAULT_FEATURES=$(gcloud compute ssl-policies list-available-features --profile=COMPATIBLE --format="json" 2>/dev/null | jq -r '. | join(", ")')

            printf "%s${SEP}%s${SEP}%s${SEP}%s${SEP}%s${SEP}%s${SEP}%s${SEP}%s\n" \
                    "$project_id" "Global / Regional" "GCP default" "TLS_1_0" "Compatible" "$DEFAULT_FEATURES" "N/A" "$DEFAULT_USAGE"
        fi
    fi

done

echo "INFO: Script completed." >&2 
