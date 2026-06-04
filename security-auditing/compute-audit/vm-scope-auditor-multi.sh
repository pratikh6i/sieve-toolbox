#!/bin/bash

# ===================================================================================
# GCP Compute Instance Robust Audit Script (Pipe-Delimited CSV)
#
# Description:
# This script scans a list of GCP Project IDs for Compute Instances. It is designed
# to be robust and fast. If the Compute Engine API is not enabled on a project,
# it will report this status in the output and continue to the next project
# without getting stuck.
#
# This script makes NO CHANGES to your infrastructure. It is READ-ONLY.
#
# Author: Gemini
# Version: 2.2
#
# Pre-requisites:
# 1. Google Cloud SDK (`gcloud`) installed and authenticated.
# 2. `jq` (a lightweight command-line JSON processor) must be installed.
# 3. Authenticated user must have 'Compute Viewer' and 'Service Usage Viewer'
#    IAM roles on the projects being scanned.
#
# How to Use:
# 1. Make the script executable: `chmod +x gcp_robust_audit.sh`
# 2. Run and save the output: `./gcp_robust_audit.sh > full_vm_report.csv`
# 3. In Google Sheets, go to File > Import > Upload, select the CSV file,
#    and under "Separator type", choose "Custom" and enter the pipe `|` character.
# ===================================================================================

# --- Configuration ---

# Prompt the user for a comma-separated list of Project IDs
read -p "Enter a comma-separated list of GCP Project IDs to scan: " project_ids

# Check if the project_ids string is empty. If so, exit.
if [[ -z "$project_ids" ]]; then
    echo "Error: No Project IDs entered. Exiting." >&2
    exit 1
fi

# --- Script Start ---

# Print the pipe-separated CSV header row.
echo "Project ID|Project Name|Instance Name|Status|Service Account|Scope Type|API Scopes|Startup Script|Shutdown Script"

# Define the standard default scopes for comparison.
default_scopes_sorted=$(printf '%s\n' \
    "https://www.googleapis.com/auth/devstorage.read_only" \
    "https://www.googleapis.com/auth/logging.write" \
    "https://www.googleapis.com/auth/monitoring.write" \
    "https://www.googleapis.com/auth/service.management.readonly" \
    "https://www.googleapis.com/auth/servicecontrol" \
    "https://www.googleapis.com/auth/trace.append" | sort | tr '\n' ';')

# Convert the comma-separated string into a bash array.
IFS=',' read -r -a project_array <<< "$project_ids"

# Loop through each Project ID provided by the user.
for project_id in "${project_array[@]}"; do
    # Trim leading/trailing whitespace from the project_id
    project_id=$(echo "$project_id" | xargs)

    # Send progress messages to stderr to keep stdout clean for the CSV data.
    echo "--> Scanning project: $project_id..." >&2

    # Set the current project for gcloud commands.
    if ! gcloud config set project "$project_id" >/dev/null 2>&1; then
        echo "Error: Failed to set project '$project_id'. Check ID and permissions. Skipping." >&2
        # Add a row to the CSV indicating the project was invalid
        echo "$project_id|\"INVALID_PROJECT_ID\"|N/A|N/A|N/A|N/A|N/A|N/A|N/A"
        continue # Skip to the next project.
    fi
    
    # Get the project name early for consistent reporting
    project_name=$(gcloud projects describe "$project_id" --format="value(name)" 2>/dev/null || echo "N/A")

    # === ROBUSTNESS CHECK: Verify that the Compute Engine API is enabled ===
    api_enabled=$(gcloud services list --enabled --filter="name:compute.googleapis.com" --format="value(name)" 2>/dev/null)

    if [[ -z "$api_enabled" ]]; then
        echo "Info: Compute Engine API is not enabled for project '$project_id'. Skipping VM scan." >&2
        # Add a row to the CSV indicating the API status and continue
        echo "$project_id|\"$project_name\"|N/A|API_DISABLED|N/A|N/A|N/A|N/A|N/A"
        continue
    fi

    # Get all instance details in JSON format.
    instance_list_json=$(gcloud compute instances list --format="json" 2>/dev/null) || true

    # If no instances are found, inform via stderr and move on.
    if [[ -z "$instance_list_json" || "$instance_list_json" == "[]" ]]; then
        echo "Info: No compute instances found in project '$project_id'." >&2
        continue
    fi

    # Process each instance using jq.
    echo "$instance_list_json" | jq -c '.[]' | while read -r instance_json; do
        # --- Extract Base VM Info ---
        instance_name=$(echo "$instance_json" | jq -r '.name')
        status=$(echo "$instance_json" | jq -r '.status')
        sa_email=$(echo "$instance_json" | jq -r '.serviceAccounts[0].email // "N/A"')

        # --- Extract Metadata Scripts ---
        startup_script=$(echo "$instance_json" | jq -r '(.metadata.items[]? | select(.key == "startup-script").value) // "Not Present"')
        shutdown_script=$(echo "$instance_json" | jq -r '(.metadata.items[]? | select(.key == "shutdown-script").value) // "Not Present"')

        # --- Format Scripts for CSV ---
        csv_safe_startup_script=$(echo "$startup_script" | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g' -e 's/"/""/g' -e 's/|/ /g')
        csv_safe_shutdown_script=$(echo "$shutdown_script" | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g' -e 's/"/""/g' -e 's/|/ /g')

        # --- API Scopes Processing ---
        scopes_json_array=$(echo "$instance_json" | jq -r '.serviceAccounts[0].scopes // []')
        formatted_scopes=$(echo "$scopes_json_array" | jq -r 'join("; ")')

        # --- Scope Type Classification ---
        scope_type="Custom Scope"
        
        if [[ "$formatted_scopes" == *"https://www.googleapis.com/auth/cloud-platform"* ]]; then
            scope_type="Full Scope"
        else
            instance_scopes_sorted=$(echo "$scopes_json_array" | jq -r '. | sort | join(";")')
            if [[ -n "$instance_scopes_sorted" ]]; then
                instance_scopes_sorted+=";"
            fi
            if [[ "$instance_scopes_sorted" == "$default_scopes_sorted" ]]; then
                scope_type="Default Scope"
            elif [[ -z "$formatted_scopes" ]]; then
                scope_type="No Scopes"
            fi
        fi

        # --- Print the Final Pipe-Delimited Row ---
        echo "$project_id|\"$project_name\"|$instance_name|$status|$sa_email|$scope_type|\"[$formatted_scopes]\"|\"$csv_safe_startup_script\"|\"$csv_safe_shutdown_script\""
    done
done

echo "Scan complete." >&2 
