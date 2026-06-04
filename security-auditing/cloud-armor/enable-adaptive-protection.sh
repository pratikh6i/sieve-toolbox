#!/bin/bash

# Ask for project ID
read -p "Enter your Google Cloud Project ID: " project_id

# Set the project
echo "Setting project to $project_id..."
gcloud config set project "$project_id"

# List all Cloud Armor security policies
echo "Fetching Cloud Armor policies..."
policies=$(gcloud compute security-policies list --format="value(name)")

# Check if any policies exist
if [ -z "$policies" ]; then
 echo "No Cloud Armor policies found in project $project_id."
 exit 0
fi

# Loop through each policy and enable adaptive protection if not already enabled
for policy in $policies; do
 echo "Checking policy: $policy"
  # Check if adaptive protection is already enabled
 ap_status=$(gcloud compute security-policies describe "$policy" --format="value(adaptiveProtectionConfig.layer7DdosDefenseConfig.enable)")
  if [ "$ap_status" = "True" ]; then
   echo "✓ Adaptive Protection already enabled for $policy"
 else
   echo "→ Enabling Adaptive Protection for $policy..."
   gcloud compute security-policies update "$policy" --enable-layer7-ddos-defense
   echo "✓ Adaptive Protection enabled for $policy"
 fi
  echo "------------------------"
done

echo "All done! Adaptive Protection has been enabled for all Cloud Armor policies."
