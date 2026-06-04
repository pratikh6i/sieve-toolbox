#!/bin/bash

# ===================================================================================
# GCP Compute Instance Scope Audit Script (CSV Output)
#
# Description:
# This script prompts for a single GCP Project ID and scans all Compute Instances
# within it. It gathers the instance name, its service account, and all associated
# API scopes. It then categorizes the scope usage as 'Default', 'Full', or 'Custom'.
# The output is formatted as CSV.
#
# This script makes NO CHANGES to your infrastructure. It is READ-ONLY.
#
# Author: Gemini
# Version: 1.0
#
# Pre-requisites:
# 1. Google Cloud SDK (`gcloud`) installed and authenticated.
# 2. `jq` (a lightweight command-line JSON processor) must be installed.
# 3. The authenticated user/service account must have the 'Compute Viewer' IAM
#    role on the project being scanned.
#
# How to Use:
# 1. Make the script executable: `chmod +x gcp_scope_audit.sh`
# 2. Run the script: `./gcp_scope_audit.sh`
# 3. When prompted, enter your GCP Project ID.
# 4. To save the output, redirect it to a file:
#    `./gcp_scope_audit.sh > scope_report.csv`
# ===================================================================================

# --- Configuration ---

# Prompt the user for the Project ID
read -p "Enter the GCP Project ID to scan: " project_id

# Check if the project_id is empty. If so, exit.
if [[ -z "$project_id" ]]; then
    echo "Error: No Project ID entered. Exiting."
    exit 1
fi

# --- Script Start ---

# Set the current project for gcloud commands quietly and check for errors.
if ! gcloud config set project "$project_id" >/dev/null 2>&1; then
    echo "Error: Failed to set project '$project_id'. Please check if the project ID is correct and you have permissions."
    exit 1
fi

echo "Scanning project: $project_id..."

# Print the CSV header row.
echo "Project ID,Instance Name,Service Account,Scope Type,API Scopes"

# Define the standard default scopes for comparison.
# Note: This is a common default set. It might vary slightly in older projects.
# We sort them to ensure consistent comparison.
default_scopes_sorted=$(printf '%s\n' \
  "https://www.googleapis.com/auth/devstorage.read_only" \
  "https://www.googleapis.com/auth/logging.write" \
  "https://www.googleapis.com/auth/monitoring.write" \
  "https://www.googleapis.com/auth/service.management.readonly" \
  "https://www.googleapis.com/auth/servicecontrol" \
  "https://www.googleapis.com/auth/trace.append" | sort | tr '\n' ';')

# Get all instance details in JSON format.
# The `|| true` prevents the script from exiting if a project has no instances.
instance_list_json=$(gcloud compute instances list --format="json" 2>/dev/null) || true

# If there are no instances, inform the user and exit.
if [[ -z "$instance_list_json" || "$instance_list_json" == "[]" ]]; then
    echo "No compute instances found in project '$project_id'."
    exit 0
fi

# Process each instance using jq.
echo "$instance_list_json" | jq -c '.[]' | while read -r instance_json; do
    instance_name=$(echo "$instance_json" | jq -r '.name')
    sa_email=$(echo "$instance_json" | jq -r '.serviceAccounts[0].email // "N/A"')
    
    # --- API Scopes Processing ---
    # Get all scopes as a JSON array, handle null case by defaulting to an empty array [].
    scopes_json_array=$(echo "$instance_json" | jq -r '.serviceAccounts[0].scopes // []')
    
    # Format the scopes into a single string with semicolons
    formatted_scopes=$(echo "$scopes_json_array" | jq -r 'join("; ")')

    # --- Scope Type Classification ---
    scope_type="Custom Scope" # Default to Custom
    
    # Check for full 'cloud-platform' scope first, as it's the highest privilege.
    if [[ "$formatted_scopes" == *"https://www.googleapis.com/auth/cloud-platform"* ]]; then
        scope_type="Full Scope"
    else
        # To accurately check for default, we sort the instance's scopes and compare.
        instance_scopes_sorted=$(echo "$scopes_json_array" | jq -r '. | sort | join(";")')
        
        # Add a semicolon at the end for a perfect match with our reference string.
        if [[ -n "$instance_scopes_sorted" ]]; then
            instance_scopes_sorted+=";"
        fi

        if [[ "$instance_scopes_sorted" == "$default_scopes_sorted" ]]; then
            scope_type="Default Scope"
        elif [[ -z "$formatted_scopes" ]]; then
            scope_type="No Scopes" # Handle case where there are no scopes defined.
        fi
    fi

    # Print the CSV row for the current instance.
    # The quotes ensure that the scopes list is treated as a single CSV field.
    echo "$project_id,$instance_name,$sa_email,$scope_type,\"[$formatted_scopes]\""
done

echo "Scan complete."
