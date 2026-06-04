#!/bin/bash

# --- Safety Configuration ---
# This strictly prevents gcloud from asking "Do you want to enable this API?"
# If an API is disabled, the command will simply fail, ensuring NO CHANGES are made.
# Read Only 

export CLOUDSDK_CORE_DISABLE_PROMPTS=1

# --- Configuration ---
PROJECT_LIST=("YOUR_PROJECT_ID_3" "YOUR_PROJECT_ID_1" "YOUR_PROJECT_ID_2" "YOUR_PROJECT_ID_4")

OUTPUT_FILE="cloud_armor_policy_rules_detailed.csv"

# --- Script Body ---

echo "Project Name,Policy Name,Target Count,Target List (Pipe Separated),Adaptive Protection,Log Level,JSON Parsing,Rules active or in preview,Status,Match Expression,Rule Description,Priority" > "$OUTPUT_FILE"
echo "CSV file created: $OUTPUT_FILE"

for project in "${PROJECT_LIST[@]}"; do
    echo "----------------------------------------------------"
    echo "🔍 Processing Project: $project"
    
    # 1. Switch Project context
    # We capture stderr to check if setting the project failed (e.g., access denied)
    if ! gcloud config set project "$project" 2>/dev/null; then
        echo "   ❌ Error: Could not set project. Skipping."
        echo "$project,ACCESS_DENIED_OR_INVALID,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A" >> "$OUTPUT_FILE"
        continue
    fi

    # 2. PROBE: Check if we can list policies. 
    # This verifies if the Compute API is enabled without making changes.
    if ! gcloud compute security-policies list --format="value(name)" >/dev/null 2>&1; then
        echo "   ⚠️  API Disabled or Permission Denied. Logging to CSV."
        echo "$project,API_DISABLED_OR_ERROR,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A" >> "$OUTPUT_FILE"
        continue
    fi

    # --- STEP 3: Build the Backend Map (The "Reverse" Logic) ---
    unset POLICY_MAP
    declare -A POLICY_MAP
    
    echo "   -> Mapping Backend Services to their Security Policies..."
    
    while read -r backend_name policy_url; do
        if [[ -n "$policy_url" ]]; then
            policy_name=$(basename "$policy_url")
            if [ -z "${POLICY_MAP[$policy_name]}" ]; then
                POLICY_MAP[$policy_name]="$backend_name"
            else
                POLICY_MAP[$policy_name]="${POLICY_MAP[$policy_name]} | $backend_name"
            fi
        fi
    done < <(gcloud compute backend-services list --format="value(name,securityPolicy)" 2>/dev/null)


    # --- STEP 4: Iterate Policies and Match ---
    policies=$(gcloud compute security-policies list --format="value(name)")

    if [ -z "$policies" ]; then
        echo "   -> No Cloud Armor policies found. Skipping."
        # Optional: Log empty state to CSV if you want explicit confirmation
        # echo "$project,NO_POLICIES_FOUND,0,None,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A" >> "$OUTPUT_FILE"
        continue
    fi

    for policy_name in $policies; do
        echo "   -> Found Policy: $policy_name."
        
        target_list="${POLICY_MAP[$policy_name]}"
        
        if [ -z "$target_list" ]; then
            target_count=0
            target_list="None"
        else
            target_count=$(echo "$target_list" | awk -F'|' '{print NF}')
        fi

        echo "      -> Targets: $target_count ($target_list)"

        # --- STEP 5: Fetch Rules and Write to CSV ---
        gcloud compute security-policies describe "$policy_name" --format=json | \
        jq -r --arg project "$project" \
              --arg policy "$policy_name" \
              --arg t_count "$target_count" \
              --arg t_list "$target_list" \
              '
            .[] | 
            (.adaptiveProtectionConfig.layer7DdosDefenseConfig.enable // "Disabled") as $ap |
            (.advancedOptionsConfig.logLevel // "Standard") as $log |
            (.advancedOptionsConfig.jsonParsing // "Disabled") as $json |

            .rules[]? | [
                $project,
                $policy,
                $t_count,
                $t_list,
                ($ap | tostring),
                $log,
                $json,
                (if .preview == true then "Preview" else "Active" end),
                .action,
                ((.match.expr.expression // .match.versionedExpr) // "N/A" | gsub("\r|\n"; " ")),
                (.description // "N/A" | gsub(","; "")),
                .priority
            ] | @csv' >> "$OUTPUT_FILE"
    done
done

echo "----------------------------------------------------"
echo "✅ Script finished successfully!"
echo "Report saved to $OUTPUT_FILE"