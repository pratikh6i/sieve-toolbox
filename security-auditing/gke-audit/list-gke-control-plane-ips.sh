#!/bin/bash

PROJECT_LIST=("YOUR_PROJECT_ID_1" "YOUR_PROJECT_ID_2" "YOUR_PROJECT_ID_4" "YOUR_PROJECT_ID_3")

for project in "${PROJECT_LIST[@]}"; do
  echo "Processing GKE Control Planes in project: $project"
  gcloud config set project "$project"

  gcloud container clusters list --format="csv[no-heading](name,endpoint)" > "${project}_gke_control_planes.csv"

  echo "Saved GKE control plane IPs to ${project}_gke_control_planes.csv"
done

echo "GKE control plane check complete."

