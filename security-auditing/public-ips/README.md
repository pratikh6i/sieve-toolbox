# Public IP & SQL Instance Inventory Tools

Scripts to inventory public-facing Cloud SQL instances and their network configurations.

## Scripts

### 1. `list-sql-instance-ips.sh` — Cloud SQL Public IPs

Lists all Cloud SQL instances across a set of projects with their IP addresses (public and private), database version, region, and tier. Outputs per-project CSV files.

#### Usage
```bash
chmod +x list-sql-instance-ips.sh
./list-sql-instance-ips.sh

# Output: YOUR_PROJECT_ID_sql_instances.csv per project
```

#### Configuration
Edit the `PROJECT_LIST` array at the top:
```bash
PROJECT_LIST=("your-project-id-1" "your-project-id-2")
```

#### Output Columns
`Project ID, Instance Name, Database Version, Region, Tier, Public IP, Private IP, Activation Policy`

---

### 2. `sql-instance-net-details.sh` — SQL Instance Network Details

Fetches detailed network configuration for Cloud SQL instances including authorized networks, SSL enforcement status, and connectivity mode.

#### Usage
```bash
chmod +x sql-instance-net-details.sh
# Edit the target project at the top of the script
./sql-instance-net-details.sh
```

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| `gcloud` CLI | Authenticated and configured |
| IAM Role | `roles/cloudsql.viewer` on target projects |
