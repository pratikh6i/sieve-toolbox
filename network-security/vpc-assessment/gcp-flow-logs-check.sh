#!/bin/bash

# ===================================================================================
# GCP VPC Flow Logs Assessment Script (CSV Output for Google Sheets)
#
# Description:
# This script checks the status of VPC Flow Logs for every subnet in a list of
# projects. The output is formatted as CSV to be directly pasted into a
# Google Sheet.
#
# It makes NO CHANGES to your infrastructure.
#
# Author: Gemini
# Version: 1.0
#
# Pre-requisites:
# 1. Google Cloud SDK (`gcloud`) installed and authenticated.
# 2. The authenticated user/service account must have the 'Compute Viewer' IAM
#    role on each project being scanned.
#
# How to Use:
# 1. Edit the `PROJECT_IDS` array below to include your project IDs.
# 2. Make the script executable: `chmod +x gcp-flow-logs-check.sh`
# 3. Run the script and redirect the output to a file:
#    `./gcp-flow-logs-check.sh > flow_logs_report.csv`
# 4. Open `flow_logs_report.csv`, copy its contents, and paste into a Google Sheet.
# ===================================================================================

# --- Configuration ---
# !!! IMPORTANT !!!
# Replace the placeholder project IDs with your actual GCP project IDs.
PROJECT_IDS=(
  "YOUR_PROJECT_ID_1"
  "YOUR_PROJECT_ID_2"
)

# --- Script Start ---

# Print the CSV header row for your Google Sheet.
echo "Project ID,Region,Network,Subnet Name,Flow Logs Status,Recommendation"

# Loop through each project to perform the assessment
for project_id in "${PROJECT_IDS[@]}"; do
  # Set the current project for gcloud commands quietly
  gcloud config set project "$project_id" >/dev/null 2>&1

  # Get all subnets and their flow log status for the current project
  # The format is specified to make parsing easy and reliable
  gcloud compute networks subnets list --format="value(region.basename(), network.basename(), name, logConfig.enable)" 2>/dev/null | while read -r region network_name subnet_name log_status; do

    # Standardize the output for clarity in the report
    if [[ "$log_status" == "True" ]]; then
      status="ENABLED"
      recommendation="N/A"
    else
      status="DISABLED"
      recommendation="Enable Flow Logs for security monitoring and forensics."
    fi

    # Print the CSV row for the current subnet
    echo "$project_id,$region,$network_name,$subnet_name,$status,\"$recommendation\""
  done
done
