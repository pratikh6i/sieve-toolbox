# Prowler on GKE PoC

Shell scripts to deploy Prowler, a cloud security posture assessment tool, inside a GKE cluster with a Neo4j knowledge graph backend. Includes infrastructure setup, deployment, health checks, and teardown.

## Purpose

Deploys a self-hosted Prowler environment on GKE to run cloud security assessments across GCP projects and visualize findings through a Neo4j graph database.

## Architecture

```
GKE Cluster (prowler-cluster)
├── Prowler (security scanner)
├── Neo4j (knowledge graph / findings storage)
└── Static External IP (reserved)
```

## Scripts

| Script | Description |
|--------|-------------|
| `01-setup-infra.sh` | Creates the GKE cluster, reserves static IP, and enables required APIs |
| `deploy-prowler-master.sh` | Deploys Prowler and Neo4j workloads to the GKE cluster |
| `check-health.sh` | Checks the health and readiness of deployed pods and services |
| `all-in-one.sh` | Final deployment script combining infrastructure + Prowler deployment |
| `teardown.sh` | Status check / cleanup helper for the cluster |

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| `gcloud` CLI | Authenticated with Project Editor or Owner permissions |
| `kubectl` | Installed and connected to the cluster |
| GCP Project | With billing enabled, `compute.googleapis.com` and `container.googleapis.com` enabled |

## Usage

```bash
# Step 1: Set up the GKE cluster and static IP
chmod +x 01-setup-infra.sh && ./01-setup-infra.sh

# Step 2: Deploy Prowler and Neo4j
chmod +x deploy-prowler-master.sh && ./deploy-prowler-master.sh

# Step 3: Verify deployment health
chmod +x check-health.sh && ./check-health.sh
```

All scripts write log output to `prowler_setup.log` in the current directory.

## Configuration

Key values to customize at the top of each script:

| Variable | Default | Description |
|----------|---------|-------------|
| `REGION` | `us-central1` | GCP region for the cluster |
| `ZONE` | `us-central1-a` | GCP zone for the cluster |
| `CLUSTER_NAME` | `prowler-cluster` | GKE cluster name |
| `MACHINE_TYPE` | `e2-standard-2` | Machine type (2 vCPU, 8GB RAM) |

## Notes

- These scripts were developed as a Proof-of-Concept and may require adaptation for production use.
- The Neo4j default credentials should be changed before any internet-facing deployment.
