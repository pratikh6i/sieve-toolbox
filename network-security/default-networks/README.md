# Default VPC Network Detector

Scans a list of GCP projects to detect the presence of default VPC networks and inventories all resources attached to them.

## Purpose

The GCP default VPC network poses a security risk because it includes permissive firewall rules. This script checks each project for a default network and, if found, reports all resources attached to it: Compute VMs, GKE clusters, Load Balancers, Cloud SQL, Redis, Memcached, AlloyDB, Filestore, VPC peerings, and Cloud NAT.

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| `gcloud` CLI | Authenticated and configured |
| IAM Roles | `roles/compute.viewer`, `roles/container.viewer`, `roles/cloudsql.viewer`, `roles/redis.viewer` on each project |
| Shell tools | `bash`, `grep`, `sed`, `timeout` |

## Configuration

Edit the `PROJECTS` array in the script:

```bash
PROJECTS=(
  "your-project-id-1"
  "your-project-id-2"
)
```

## Usage

```bash
chmod +x detect-default-networks.sh

# Run and pipe to CSV
./detect-default-networks.sh > default_vpc_report.csv 2>scan.log

# Progress messages go to stderr (visible in terminal)
# CSV data goes to stdout (redirected to file)
```

## Importing to Google Sheets

1. Open Google Sheets
2. File → Import → Upload `default_vpc_report.csv`
3. Select **Custom separator** → enter `|` (pipe)
4. Click Import

## Output Columns

| Column | Description |
|--------|-------------|
| Project ID | GCP project being scanned |
| Default Network Exists? | Yes / No |
| Compute VMs | VM instances in the default network |
| GKE Clusters | GKE clusters using the default network |
| Load Balancers | Forwarding rules on the default network |
| Serverless VPC Connectors | VPC Access connectors |
| Cloud SQL (Private) | SQL instances with private IPs in default network |
| Memorystore Redis | Redis instances |
| Memorystore Memcached | Memcached instances |
| AlloyDB Clusters | AlloyDB clusters |
| Filestore Instances | Filestore instances |
| PSA Peerings | Private Service Access peerings |
| User VPC Peerings | User-created VPC peerings |
| Cloud NAT | Cloud Router/NAT configurations |
| Notes | Error messages or additional context |
