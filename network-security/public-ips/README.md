# Public IP Inventory Tools

Shell scripts to inventory public IP addresses across GCP resources: Load Balancers, Reserved IPs, and Cloud SQL instances.

## Scripts

### 1. `list-lb-ips.sh` — Load Balancer IPs

Lists all forwarding rules (Load Balancer frontend IPs) for a set of projects, outputting the IP address, port range, load balancing scheme, and target backend.

#### Usage
```bash
chmod +x list-lb-ips.sh

# Run for all projects — outputs per-project CSV files
./list-lb-ips.sh

# Output files: YOUR_PROJECT_ID_forwarding_rules.csv
```

#### Output Columns
`Project ID, Forwarding Rule Name, IP Address, Port Range, Protocol, Load Balancing Scheme, Target`

---

### 2. `list-reserved-ips.sh` — Reserved (Static) IPs

Lists all reserved static external IP addresses per project including their current status (IN_USE vs RESERVED) and the resource they are attached to.

#### Usage
```bash
chmod +x list-reserved-ips.sh
./list-reserved-ips.sh

# Output files: YOUR_PROJECT_ID_reserved_ips.csv
```

#### Output Columns
`Project ID, IP Name, IP Address, Region, Status, Users (attached resource)`

---

### 3. `list-sql-instance-ips.sh` — Cloud SQL Instance IPs (in `security-auditing/public-ips/`)

Lists all Cloud SQL instances per project with their public and private IP addresses.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| `gcloud` CLI | Authenticated and configured |
| IAM Roles | `roles/compute.viewer` (for LB/Reserved), `roles/cloudsql.viewer` (for SQL) |

## Configuration

Edit the `PROJECT_LIST` array at the top of each script:
```bash
PROJECT_LIST=("your-project-id-1" "your-project-id-2")
```
