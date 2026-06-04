# Workload Identity Federation (WIF) PoC

Scripts demonstrating how to configure and test GCP Workload Identity Federation for Kubernetes workloads. These scripts deploy a Java application to GKE that authenticates to GCP APIs using WIF instead of service account key files.

## Purpose

Replaces static service account key file authentication with WIF, allowing GKE pods to authenticate to GCP APIs using projected service account tokens. This eliminates the need to distribute and rotate JSON key files.

## Scripts

| Script | Description |
|--------|-------------|
| `run-wif-k8s-poc.sh` | End-to-end PoC: creates GCS bucket, creates SA, configures WIF binding, builds Java image, deploys to GKE, and validates access |

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| GKE Cluster | Must support Workload Identity |
| `gcloud` CLI | Authenticated with Project Editor permissions |
| `kubectl` | Connected to the target cluster |
| Docker / Artifact Registry | For building and pushing the Java test image |
| Java + Maven | For building the test application |

## Configuration

Edit the following variables at the top of `run-wif-k8s-poc.sh`:

```bash
PROJECT_ID="YOUR_PROJECT_ID"          # Your GCP project ID
PROJECT_NUMBER="YOUR_PROJECT_NUMBER"  # Your GCP project number (12-digit)
```

All other values (SA name, bucket name, region, image name) are derived from `PROJECT_ID`.

## Usage

```bash
chmod +x run-wif-k8s-poc.sh

# Ensure your GKE cluster is configured for Workload Identity:
# gcloud container clusters update YOUR_CLUSTER \
#   --workload-pool=YOUR_PROJECT_ID.svc.id.goog

./run-wif-k8s-poc.sh
```

The script will:
1. Create a GCS bucket and upload a test file
2. Create a GCP service account with Storage Viewer permissions
3. Create a Kubernetes service account in the `wif-poc` namespace
4. Bind the K8s SA to the GCP SA via IAM WIF policy
5. Build and push a Java test app to Artifact Registry
6. Deploy the app to GKE
7. Verify the app can list GCS buckets using WIF credentials (no key file)

## How WIF Works

```
K8s Pod (service account token)
        │
        ▼
GCP Token Exchange Endpoint
        │
        ▼
GCP Access Token (scoped to GCP SA)
        │
        ▼
GCP API (GCS, BigQuery, etc.)
```

## Security Benefit

| Before (Key Files) | After (WIF) |
|--------------------|-------------|
| Static JSON keys that expire and must be rotated | No key files — tokens are short-lived and automatic |
| Keys can be leaked if committed to source control | No secret to leak |
| Manual key rotation process | Automatic |
