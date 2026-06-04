#!/bin/bash

# Output file name
output_file="address_groups_report.csv"

# Write the header row using pipe (|) as the separator
echo "Project ID|Address Group Name|Location|Type|Capacity|Purpose|Description|IP Addresses" > "$output_file"

# Prompt user for project IDs
read -p "Enter Project IDs (comma-separated): " input_projects

# Convert the comma-separated input into an array
IFS=',' read -r -a projects <<< "$input_projects"

for proj in "${projects[@]}"; do
    # Trim whitespace from the project ID
    proj=$(echo "$proj" | xargs)
    
    # Skip if empty
    if [[ -z "$proj" ]]; then
        continue
    fi
    
    echo "Fetching address groups for project: $proj ..."
    
    # Fetch address groups. 
    # Added --quiet to prevent gcloud from hanging on "Would you like to enable this API?" prompts.
    json_data=$(gcloud network-security address-groups list --project="$proj" --location="global" --format="json" --quiet 2>/dev/null)
    
    # Capture the exit code of the gcloud command
    exit_code=$?
    
    # Handle Errors or Empty Results and log them directly into the CSV
    if [[ $exit_code -ne 0 ]]; then
        echo "  -> Error: API disabled or access denied. Logging to file."
        # Write a row stating the API is disabled
        echo "$proj|N/A|N/A|N/A|N/A|N/A|ERROR: Network Security API disabled or Permission Denied|N/A" >> "$output_file"
        
    elif [[ -z "$json_data" || "$json_data" == "[]" ]]; then
        echo "  -> No address groups found. Logging to file."
        # Write a row stating no groups were found
        echo "$proj|N/A|N/A|N/A|N/A|N/A|No global address groups found in this project|N/A" >> "$output_file"
        
    else
        # If successful and data exists, parse the JSON with jq and append to the output file.
        echo "$json_data" | jq -r --arg PROJECT "$proj" '
        .[] | 
        [
          $PROJECT,
          (if .name then (.name | split("/")[-1]) else "" end),
          (if .name then (.name | split("/")[-3]) else "" end),
          (.type // "N/A"),
          (.capacity // "N/A"),
          (if .purpose then (.purpose | join(", ")) else "N/A" end),
          (.description // "" | gsub("\\|"; "-") | gsub("\n"; " ")),
          (if .items then (.items | join(", ")) else "" end)
        ] | join("|")
        ' >> "$output_file"
        
        echo "  -> Details added to report."
    fi
done

echo "----------------------------------------------------"
echo "Script complete! The details have been saved to: $output_file"
