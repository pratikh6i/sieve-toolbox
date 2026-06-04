#!/bin/bash
echo "=========================================="
echo "       PROWLER POC - STATUS CHECK         "
echo "=========================================="
echo ""
echo "--- 1. Current Directory Files ---"
ls -la | grep -E "prowler|\.sh|\.yaml|\.log"
echo ""
echo "--- 2. GCP Infrastructure ---"
echo "> GKE Clusters:"
gcloud container clusters list --format="table(name,zone,status)"
echo ""
echo "> Static IPs:"
gcloud compute addresses list --filter="name~'prowler'" --format="table(name,region,address,status)"
echo ""
echo "--- 3. Kubernetes Status ---"
if kubectl get ns prowler >/dev/null 2>&1; then
    echo "> Pods:"
    kubectl get pods -n prowler
    echo ""
    echo "> Services:"
    kubectl get svc -n prowler
    echo ""
    echo "> Persistent Volume Claims (Disks):"
    kubectl get pvc -n prowler
else
    echo "Namespace 'prowler' does not exist."
fi
echo "=========================================="
echo "COPY AND PASTE THIS ENTIRE OUTPUT BACK TO ME."
