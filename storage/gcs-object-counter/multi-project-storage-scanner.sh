#!/bin/bash

# --- Safety Configuration ---
export CLOUDSDK_CORE_DISABLE_PROMPTS=1

# --- Configuration ---
PROJECT_LIST=("YOUR_PROJECT_ID_3" "YOUR_PROJECT_ID_1" "YOUR_PROJECT_ID_2" "YOUR_PROJECT_ID_4")
OUTPUT_FILE="gcp_storage_security_audit.csv"

# --- Script Body ---

# 1. Create CSV Header
echo "Project Name,Bucket Name,RISK LEVEL,Public Access Prevention,Uniform Access (UBLA),Versioning,Logging Target,Encryption Type,CORS Configured,Labels Found,Creation Date" > "$OUTPUT_FILE"

echo "CSV file created: $OUTPUT_FILE"

for project in "${PROJECT_LIST[@]}"; do
    echo "----------------------------------------------------"
    echo "🔍 Processing Project: $project"
    
    # 2. Switch Project Context
    if ! gcloud config set project "$project" 2>/dev/null; then
        echo "   ❌ Error: Could not set project. Skipping."
        echo "$project,ACCESS_DENIED,,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A" >> "$OUTPUT_FILE"
        continue
    fi

    # 3. PROBE: Check if Storage API is accessible
    if ! gcloud storage buckets list --limit=1 >/dev/null 2>&1; then
        echo "   ⚠️  Storage API Disabled or Permission Denied."
        echo "$project,API_DISABLED,,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A" >> "$OUTPUT_FILE"
        continue
    fi

    # 4. Fetch Bucket Metadata & Parse Security Findings
    echo "   -> Fetching bucket metadata..."
    
    gcloud storage buckets list --format=json | \
    jq -r --arg project "$project" '
        .[] | 
        
        # --- Extraction & Normalization ---
        (.iamConfiguration.publicAccessPrevention // "Inherited") as $pap |
        (if .iamConfiguration.uniformBucketLevelAccess.enabled then "Enabled" else "Disabled" end) as $ubla |
        (if .versioning.enabled then "Enabled" else "Disabled" end) as $ver |
        (.logging.logBucket // "None") as $log |
        (if .encryption.defaultKmsKeyName then "CMEK" else "Google-Managed" end) as $enc |
        (if .cors then "Yes" else "No" end) as $cors |
        (if .labels then "Yes" else "No" end) as $lbl |
        
        # --- Risk Calculation Logic ---
        (
            if $pap == "Inherited" then "HIGH (Public Risk)"
            elif $ubla == "Disabled" then "MED (ACLs Active)"
            elif $ver == "Disabled" or $log == "None" then "MED (Data/Audit Risk)"
            else "LOW"
            end
        ) as $risk |

        # --- Output Array ---
        [
            $project,
            .name,
            $risk,
            $pap,
            $ubla,
            $ver,
            $log,
            $enc,
            $cors,
            $lbl,
            # FIX: We treat .timeCreated as a string or default to "N/A" before splitting
            ((.timeCreated // "N/A") | split("T")[0])
        ] | @csv' >> "$OUTPUT_FILE"

    bucket_count=$(gcloud storage buckets list --format="value(name)" | wc -l)
    echo "   -> Processed $bucket_count buckets."

done

echo "----------------------------------------------------"
echo "✅ Audit finished successfully!"
echo "Report saved to $OUTPUT_FILE"