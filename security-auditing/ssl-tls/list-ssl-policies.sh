#!/bin/bash

PROJECTS_TO_SCAN=(
  "YOUR_PROJECT_ID_1"
  "YOUR_PROJECT_ID_2"
  "YOUR_PROJECT_ID_3"
  "YOUR_PROJECT_ID_4"
  )


DELIMITER='||'
echo "Project_ID${DELIMITER}Scope${DELIMITER}Policy_Name${DELIMITER}Min_TLS_Version${DELIMITER}Profile${DELIMITER}Enabled_Features${DELIMITER}Custom_Features"
for project_id in "${PROJECTS_TO_SCAN[@]}"; do
    gcloud config set project "$project_id" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "ERROR: Could not set project to '$project_id'. Skipping." >&2
        continue
    fi

    ALL_POLICIES_JSON=$(gcloud compute ssl-policies list --format="json" 2>/dev/null)

    if [ -z "$ALL_POLICIES_JSON" ] || [ "$(echo "$ALL_POLICIES_JSON" | jq 'length')" -eq 0 ]; then
        continue
    fi

    echo "$ALL_POLICIES_JSON" | jq -c '.[]' | while read -r policy_json; do
        POLICY_NAME=$(echo "$policy_json" | jq -r '.name')
        PROFILE=$(echo "$policy_json" | jq -r '.profile // "N/A"')
        MIN_TLS_VERSION=$(echo "$policy_json" | jq -r '.minTlsVersion // "N/A"')
        
        SCOPE=$(echo "$policy_json" | jq -r 'if .region then (.region | sub(".*/"; "")) else "global" end')
        REGION_FLAG=""
        if [ "$SCOPE" != "global" ]; then
            REGION_FLAG="--region=$SCOPE"
        fi

        ENABLED_FEATURES="None"
        CUSTOM_FEATURES="None"

        if [ "$PROFILE" == "CUSTOM" ]; then
            CUSTOM_FEATURES=$(echo "$policy_json" | jq -r 'if (.customFeatures? | length) > 0 then "\"" + (.customFeatures | join(",")) + "\"" else "None" end')
        else
            DESCRIBE_JSON=$(gcloud compute ssl-policies describe "$POLICY_NAME" $REGION_FLAG --format="json" 2>/dev/null)
            if [ -n "$DESCRIBE_JSON" ]; then
                ENABLED_FEATURES=$(echo "$DESCRIBE_JSON" | jq -r 'if (.enabledFeatures? | length) > 0 then "\"" + (.enabledFeatures | join(",")) + "\"" else "None" end')
            fi
        fi
        ROW_DATA=(
            "$project_id"
            "$SCOPE"
            "$POLICY_NAME"
            "$MIN_TLS_VERSION"
            "$PROFILE"
            "$ENABLED_FEATURES"
            "$CUSTOM_FEATURES"
        )
        (IFS=$DELIMITER; echo "${ROW_DATA[*]}")
    done
done
echo "INFO: Script completed." >&2
 
