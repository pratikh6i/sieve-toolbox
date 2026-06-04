#!/bin/bash

PROJECT_LIST=("YOUR_PROJECT_ID_1" "YOUR_PROJECT_ID_2" "YOUR_PROJECT_ID_4" "YOUR_PROJECT_ID_3")
for project in "${PROJECT_LIST[@]}"; do
  echo "Processing SQL Instances in project: $project"
  gcloud config set project "$project"

  gcloud sql instances list --format="csv[no-heading](name,ipAddresses.ipAddress.flatten())" > "${project}_sql_instances.csv"

  echo "Saved SQL instance IPs to ${project}_sql_instances.csv"
done

echo "SQL instance check complete."

