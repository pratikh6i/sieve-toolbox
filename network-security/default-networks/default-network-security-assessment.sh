#!/bin/bash

# ===================================================================================
# GCP Network Inventory Script (CSV Output for Google Sheets)
#
# Description:
# This script collects specific network inventory details for a list of projects.
# The output is formatted as CSV (Comma-Separated Values) to be directly
# copy-pasted into a Google Sheet.
#
# It makes NO CHANGES to your infrastructure.
#
# Author: Gemini
# Version: 3.1
#
# Pre-requisites:
# 1. Google Cloud SDK (`gcloud`) installed and authenticated.
# 2. The authenticated user/service account must have the following IAM roles
#    on each project being scanned: 'Compute Viewer', 'Kubernetes Engine Viewer'.
#
# How to Use:
# 1. Edit the `PROJECT_IDS` array below to include your four project IDs.
# 2. Make the script executable: `chmod +x gcp_network_inventory.sh`
# 3. Run the script and redirect the output to a file:
#    `./gcp_network_inventory.sh > network_inventory_report.csv`
# 4. Open the `network_inventory_report.csv` file, copy its contents, and
#    paste them into a cell in a blank Google Sheet.
# ===================================================================================

# --- Configuration ---
# !!! IMPORTANT !!!
# Replace the placeholder project IDs with your actual GCP project IDs.
PROJECT_IDS=(
  "YOUR_PROJECT_ID_1"
  "YOUR_PROJECT_ID_2"
  "YOUR_PROJECT_ID_3"
  "YOUR_PROJECT_ID_4"
)

# --- Script Start ---

# Print the CSV header row. This will be the first row in your Google Sheet.
echo "Project ID,Network Name,Subnet Count,Resources in Default Network (Format: Type:Name;)"

# Loop through each project and perform the assessment
for project_id in "${PROJECT_IDS[@]}"; do
  # Set the current project for gcloud commands quietly
  gcloud config set project "$project_id" >/dev/null 2>&1

  # Get a list of all networks in the project
  gcloud compute networks list --format="value(name)" 2>/dev/null | while read -r network_name; do
    # Get the count of subnets for the current network. `wc -l` counts the lines. `xargs` trims whitespace.
    subnet_count=$(gcloud compute networks subnets list --network="$network_name" --format="value(name)" 2>/dev/null | wc -l | xargs)

    resources_in_default="N/A"
    # Check if the current network is the 'default' network
    if [[ "$network_name" == "default" ]]; then
        all_resources=""

        # Find Compute Instances in the default network
        instance_list=$(gcloud compute instances list --filter="networkInterfaces.network:default" --format="value(name.basename())" 2>/dev/null | tr '\n' ' ')
        if [[ -n "$instance_list" ]]; then
            for instance in $instance_list; do
                all_resources+="Instance:$instance; "
            done
        fi

        # Find GKE Clusters in the default network
        cluster_list=$(gcloud container clusters list --filter="network=default" --format="value(name)" 2>/dev/null | tr '\n' ' ')
        if [[ -n "$cluster_list" ]]; then
            for cluster in $cluster_list; do
                all_resources+="GKE Cluster:$cluster; "
            done
        fi

        if [[ -z "$all_resources" ]]; then
            resources_in_default="No Compute Instances or GKE Clusters found"
        else
            # Remove the trailing space for cleanliness
            resources_in_default="${all_resources% }"
        fi
    fi

    # Print the CSV row for the current network
    echo "$project_id,$network_name,$subnet_count,\"$resources_in_default\""
  done
done

