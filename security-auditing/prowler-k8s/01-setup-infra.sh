#!/bin/bash
# 01-setup-infra.sh
# Sets up GKE Cluster and Static IP with logging.

# --- Configuration ---
LOG_FILE="prowler_setup.log"
REGION="us-central1"
ZONE="us-central1-a"
CLUSTER_NAME="prowler-cluster"
IP_NAME="prowler-static-ip"
MACHINE_TYPE="e2-standard-2" # 2 vCPU, 8GB RAM (Optimized for Dashboard + DB)

# --- Logging Setup ---
exec > >(tee -a "$LOG_FILE") 2>&1
echo "=== Starting Infrastructure Setup at $(date) ==="

# 1. Enable APIs
echo "--> Enabling Compute and Container APIs..."
gcloud services enable compute.googleapis.com container.googleapis.com

# 2. Reserve Static IP
echo "--> Checking/Reserving Static IP ($IP_NAME)..."
if gcloud compute addresses describe $IP_NAME --region=$REGION > /dev/null 2>&1; then
    echo "    IP $IP_NAME already exists."
else
    gcloud compute addresses create $IP_NAME --region=$REGION
    echo "    IP reserved."
fi

STATIC_IP=$(gcloud compute addresses describe $IP_NAME --region=$REGION --format='get(address)')
echo "    STATIC IP: $STATIC_IP"

# 3. Create GKE Cluster (Zonal for cost savings)
echo "--> Creating GKE Cluster ($CLUSTER_NAME)..."
# We use --num-nodes=1 to keep costs low. The e2-standard-2 can handle the load.
if gcloud container clusters describe $CLUSTER_NAME --zone=$ZONE > /dev/null 2>&1; then
    echo "    Cluster $CLUSTER_NAME already exists."
else
    gcloud container clusters create $CLUSTER_NAME \
        --zone=$ZONE \
        --num-nodes=1 \
        --machine-type=$MACHINE_TYPE \
        --disk-size=30GB \
        --scopes=cloud-platform \
        --enable-ip-alias
fi

# 4. Configure kubectl
echo "--> Getting Cluster Credentials..."
gcloud container clusters get-credentials $CLUSTER_NAME --zone=$ZONE

echo "=== Infrastructure Setup Complete ==="
echo "Static IP reserved: $STATIC_IP"
echo "You can now run ./02-deploy-prowler.sh"
