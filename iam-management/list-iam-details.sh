#!/bin/bash

# This interactive script generates a pipe-separated IAM report.
# It allows the user to choose the scope: Organization, Folder, or Project.
# IT IS STRICTLY READ-ONLY.

# --- Preamble: Exit on error ---
set -e

# --- 1. Display Menu and Get User Choice ---
echo "Google Cloud IAM Policy Exporter"
echo "------------------------------------"
echo "Please select the scope to query:"
echo "  1. Organization"
echo "  2. Folder"
echo "  3. Project"
echo ""
read -p "Enter your choice (1-3): " scope_choice

# --- 2. Determine Scope and Get ID ---
# Based on the user's choice, set the correct gcloud command and prompt for the appropriate ID.
case $scope_choice in
  1)
    read -p "Enter the Organization ID: " resource_id
    gcloud_command_base="gcloud organizations get-iam-policy"
    scope_name="org"
    ;;
  2)
    read -p "Enter the Folder ID: " resource_id
    gcloud_command_base="gcloud resource-manager folders get-iam-policy"
    scope_name="folder"
    ;;
  3)
    read -p "Enter the Project ID: " resource_id
    gcloud_command_base="gcloud projects get-iam-policy"
    scope_name="project"
    ;;
  *)
    echo "Error: Invalid choice. Please run the script again and enter 1, 2, or 3."
    exit 1
    ;;
esac

# Check if the resource_id is empty
if [ -z "$resource_id" ]; then
    echo "Error: The ID cannot be empty."
    exit 1
fi

# Define the output filename based on the scope and ID
output_file="iam_report_${scope_name}_${resource_id}.txt"

echo ""
echo "Fetching IAM policy for ${scope_name} '${resource_id}' (read-only operation)..."

# --- 3. Execute Command and Generate Report ---
# This block is now generic and uses the variables set in the case statement.
# The awk script remains the same, as it processes the standardized output from gcloud.
$gcloud_command_base "$resource_id" \
    --flatten="bindings[].members" \
    --format="value(bindings.members, bindings.role)" \
    --sort-by="bindings.members" | \
awk '
BEGIN {
    # Set the Output Field Separator to a pipe
    OFS="|";
    # Print the pipe-separated header
    print "Type|Principal|Roles";
}
{
    principal_full = $1
    role = $2

    # Aggregate roles with a comma and a space for readability.
    if (roles[principal_full]) {
        roles[principal_full] = roles[principal_full] ", " role;
    } else {
        roles[principal_full] = role;
    }
}
END {
    for (p in roles) {
        split(p, parts, ":");
        type = parts[1];
        principal_name = substr(p, length(type) + 2);

        # Format the roles list within "[ ]" and quote the entire field.
        formatted_roles = "\"[[ " roles[p] " ]]\"";
        
        print type, principal_name, formatted_roles;
    }
}
' > "$output_file"

echo "--------------------------------------------------"
echo "✅ Success! Report saved to: $output_file"
echo "This file uses a pipe '|' as the separator."
echo "When importing to Google Sheets, choose 'Custom' separator and enter '|'."
echo "--------------------------------------------------" 
