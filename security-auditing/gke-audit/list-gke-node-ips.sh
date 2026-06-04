
#!/bin/bash

PROJECT_LIST=("YOUR_PROJECT_ID_1" "YOUR_PROJECT_ID_2" "YOUR_PROJECT_ID_4" "YOUR_PROJECT_ID_3")

for project in "${PROJECT_LIST[@]}"; do
  echo "Processing GKE Nodes in project: $project"
  gcloud config set project "$project"

  gcloud compute instances list --filter="name~'gke-'" --format="csv[no-heading](name,networkInterfaces[0].accessConfigs[0].natIP)" > "${project}_gke_nodes.csv"

  echo "Saved GKE node IPs to ${project}_gke_nodes.csv"
done

echo "GKE node check complete."
