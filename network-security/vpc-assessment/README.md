# VPC Assessment Scripts

Two read-only scripts to audit VPC Flow Logs status and collect network inventory across GCP projects.

## Scripts

### 1. `gcp-flow-logs-check.sh` — VPC Flow Logs Checker

Checks the status of VPC Flow Logs for every subnet in a list of projects.

#### Usage

```bash
chmod +x gcp-flow-logs-check.sh
./gcp-flow-logs-check.sh > flow_logs_report.csv
```

#### Output Columns

| Column | Description |
|--------|-------------|
| Project ID | GCP project identifier |
| Region | Region of the subnet |
| Network | Parent VPC network name |
| Subnet Name | Subnet identifier |
| Flow Logs Status | `ENABLED` or `DISABLED` |
| Recommendation | Action text if disabled |

---

### 2. `network-inventory.sh` — Network Inventory

Collects VPC network details per project, including subnet counts and resources attached to the default network.

#### Usage

```bash
chmod +x network-inventory.sh
./network-inventory.sh > network_inventory_report.csv
```

#### Output Columns

| Column | Description |
|--------|-------------|
| Project ID | GCP project identifier |
| Network Name | VPC name |
| Subnet Count | Total subnets in the network |
| Resources in Default Network | Compute instances / GKE clusters attached to the default network |

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| `gcloud` CLI | Authenticated and configured |
| IAM Roles | `roles/compute.viewer`, `roles/container.viewer` |

## Configuration

Edit the `PROJECT_IDS` array at the top of either script:

```bash
PROJECT_IDS=(
  "your-project-id-1"
  "your-project-id-2"
)
```

---

## 3. `gcp-flow-logs-check-v2.sh` — VPC Flow Logs Checker (Updated)

An updated version of the flow logs checker with improved output formatting and additional subnet metadata. Use this in preference to `gcp-flow-logs-check.sh` for newer assessments.

### Usage
```bash
chmod +x gcp-flow-logs-check-v2.sh
./gcp-flow-logs-check-v2.sh > flow_logs_report_v2.csv
```
