#!/bin/bash
PROJECT_LIST=("YOUR_PROJECT_ID_1" "YOUR_PROJECT_ID_2" "YOUR_PROJECT_ID_4" "YOUR_PROJECT_ID_3")


for project in "${PROJECT_LIST[@]}"; do
  echo "Processing Reserved IPs in project: $project"
  gcloud config set project "$project"

  gcloud compute addresses list --format="csv[no-heading](name,address,status)" > "${project}_reserved_ips.csv"

  echo "Saved reserved IPs to ${project}_reserved_ips.csv"
done

echo "Reserved IP check complete."
