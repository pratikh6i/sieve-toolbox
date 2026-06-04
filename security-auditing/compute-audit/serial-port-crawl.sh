#!/bin/bash

# Prompt the user to enter their GCP Project ID
read -p "Enter your GCP Project ID: " PROJECT_ID

# Check if the user provided a Project ID
if [ -z "$PROJECT_ID" ]; then
    echo "Error: Project ID cannot be empty."
    exit 1
fi

echo ""
echo "🔍 Checking serial port status for all instances in project: $PROJECT_ID"
echo "--------------------------------------------------------------------"

# Get the list of all instances (name and zone) in the specified project.
# The `gcloud` command outputs two columns (name and zone) which are then read by the while loop.
gcloud compute instances list --project="$PROJECT_ID" --format="value(name,zone)" | while read -r INSTANCE_NAME ZONE; do
    # Ensure that the instance name is not empty
    if [ -n "$INSTANCE_NAME" ]; then
        # For each instance, check its metadata for the 'serial-port-enable' key.
        # The result is stored in the SERIAL_PORT_ENABLED variable.
        # We redirect stderr to /dev/null to hide potential errors if metadata is not found.
        SERIAL_PORT_ENABLED=$(gcloud compute instances describe "$INSTANCE_NAME" \
            --zone="$ZONE" \
            --project="$PROJECT_ID" \
            --format="value(metadata.items.serial-port-enable)" 2>/dev/null)

        # Check the value of the 'serial-port-enable' metadata key.
        # If it's 'true', the serial port is enabled. Otherwise, it is disabled.
        if [ "$SERIAL_PORT_ENABLED" == "true" ]; then
            echo "Compute Instance: $INSTANCE_NAME, Serial port is ✅ Enabled"
        else
            echo "Compute Instance: $INSTANCE_NAME, Serial port is ❌ Disabled"
        fi
    fi
done

echo "--------------------------------------------------------------------"
echo "Script execution finished."
