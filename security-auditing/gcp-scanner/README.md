# GCP Security Health Analytics Scanner

A comprehensive, read-only Python scanner that checks GCP resources for security misconfigurations and outputs findings in Security Command Center (SCC)-compatible format.

## Purpose

Scans the following GCP resource types across an organization or list of projects:
- **Compute Engine Instances** — API scopes, public IPs, Shielded VM, Secure Boot, vTPM, serial ports, SSH keys, default SA
- **GKE Clusters** — Private cluster, master authorized networks, Workload Identity, legacy ABAC, network policy, Binary Authorization
- **Cloud Storage Buckets** — Public ACL, uniform access, logging, versioning, retention policy
- **VPC Firewall Rules** — Open SSH/RDP/MySQL/Postgres/MongoDB/Redis, wide egress
- **Cloud SQL Instances** — Public IP, SSL enforcement, backups, authorized networks, database flags

All operations are **read-only** and do not modify any infrastructure.

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Python 3.8+ | |
| GCP Libraries | `pip install -r requirements.txt` |
| `gcloud` CLI | Authenticated via ADC |
| IAM Roles | `roles/compute.viewer`, `roles/container.viewer`, `roles/storage.admin`, `roles/cloudsql.viewer`, `roles/resourcemanager.projectViewer` |

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Scan all projects in a GCP organization
python3 gcp-security-scanner.py --org-id YOUR_ORGANIZATION_ID

# Scan specific projects
python3 gcp-security-scanner.py --project-ids project-a,project-b,project-c

# Adjust parallelism
python3 gcp-security-scanner.py --org-id YOUR_ORG_ID --max-workers 20
```

## Output

Generates a CSV file named `security_findings_<TIMESTAMP>.csv` with these columns:

| Column | Description |
|--------|-------------|
| finding_name | Unique finding ID |
| finding_category | e.g., `FULL_API_ACCESS`, `OPEN_SSH_PORT` |
| finding_severity | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| finding_state | ACTIVE / INACTIVE |
| finding_class | VULNERABILITY / MISCONFIGURATION / OBSERVATION |
| resource_name | Full GCP resource path |
| resource_type | e.g., `compute.googleapis.com/Instance` |
| resource_project | Project ID |
| resource_location | Zone or region |
| finding_description | Human-readable description |
| remediation | Recommended action |
| compliance | CIS GCP / NIST 800-53 / PCI-DSS references |
| scan_time | ISO 8601 timestamp |

## Finding Categories

The scanner includes 50+ predefined finding types mapped to CIS GCP, NIST 800-53, and PCI-DSS controls. See the `FINDING_DEFINITIONS` dictionary in the script for the full list.
