#!/bin/bash

PROJECT_LIST=("YOUR_PROJECT_ID_1" "YOUR_PROJECT_ID_2" "YOUR_PROJECT_ID_4" "YOUR_PROJECT_ID_3")

for project in "${PROJECT_LIST[@]}"; do
  echo "Processing project: $project"

  gcloud config set project "$project"
  gcloud compute forwarding-rules list --format="csv[no-heading](name,IPAddress)" > "${project}_forwarding_rules.csv"

  echo "Saved forwarding rules to ${project}_forwarding_rules.csv"
done

echo "Process complete."
