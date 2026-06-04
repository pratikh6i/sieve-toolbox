# SSL/TLS Component

This component provides a suite of scripts for auditing, hardening, and mapping SSL/TLS security policies across target GCP projects.

## Tools Overview

### 1. [describe-ssl-policies.sh](describe-ssl-policies.sh)
Queries and documents all configured SSL policies across configured GCP projects, exporting details like minimum TLS versions, profile types, custom features, and timestamps into a pipe-delimited CSV (`gcp_ssl_policies_inventory.csv`).

### 2. [harden-ssl-policy.sh](harden-ssl-policy.sh)
An interactive script to upgrade a specific SSL Policy's minimum TLS version to `1.2` and remove weak/insecure cipher suites if the policy is using a `CUSTOM` profile.

### 3. [map-ssl-policies-to-proxies.sh](map-ssl-policies-to-proxies.sh)
Audits configured SSL policies and checks if they are associated with active target HTTPS proxies or SSL proxies, mapping policies directly to the resources utilizing them in a CSV report.

---

## SSL Policies Inventory (`describe-ssl-policies.sh`)

### Purpose
- Automate discovery of all SSL policies across multiple project contexts.
- Document compliance levels (e.g. minimum TLS version).

### Target Variables
- **PROJECT_IDS**: Array of GCP project IDs to audit. Modify the `PROJECT_IDS` array directly in the script to point to your target environments.
- **OUTPUT_FILE**: Writes pipe-delimited values to `gcp_ssl_policies_inventory.csv`.

### Prerequisites
- Google Cloud SDK (`gcloud`) and JSON parser `jq` installed.
- Appropriate IAM roles allowing compute reader permissions on target projects.

### Usage
```bash
chmod +x describe-ssl-policies.sh
./describe-ssl-policies.sh
```

---

## SSL Policy Hardener (`harden-ssl-policy.sh`)

### Purpose
- Interactively harden a custom SSL policy by enforcing TLS 1.2 minimum and removing weak cipher suites (e.g., 3DES, AES CBC).

### Target Variables
- **FEATURES_TO_DISABLE**: A predefined list of ciphers to disable.
- User input is requested for GCP Project ID and the specific SSL Policy Name.

### Prerequisites
- `gcloud` and `jq` installed.
- Requires Compute Security Admin permissions or equivalent to write updates to SSL policies.

### Usage
```bash
chmod +x harden-ssl-policy.sh
./harden-ssl-policy.sh
```

---

## Map SSL Policies to Proxies (`map-ssl-policies-to-proxies.sh`)

### Purpose
- Cross-reference SSL policies to actual target HTTPS and SSL proxy resources to identify unused policies or target components needing upgrades.

### Target Variables
- **PROJECT_IDS**: Array of GCP project IDs to audit.
- **OUTPUT_CSV_FILE**: Writes CSV results to a file named `gcp_tls_policy_report_YYYYMMDD_HHMMSS.csv`.

### Prerequisites
- `gcloud` and `jq` installed.

### Usage
```bash
chmod +x map-ssl-policies-to-proxies.sh
./map-ssl-policies-to-proxies.sh
```

---

## SSL Policy Lister (`list-ssl-policies.sh`)

### Purpose
Lists all SSL policies across a set of projects in a quick CSV format. Simpler than `describe-ssl-policies.sh` — designed for fast multi-project inventory snapshots.

### Configuration
Edit `PROJECTS_TO_SCAN` at the top of the script:
```bash
PROJECTS_TO_SCAN=("your-project-id-1" "your-project-id-2")
```

### Usage
```bash
chmod +x list-ssl-policies.sh
./list-ssl-policies.sh
```

---

## Updated SSL Policies Reporter (`updated-ssl-policies.sh`)

### Purpose
An enhanced version of the SSL policy lister that also checks which target HTTPS/SSL proxies are referencing each policy, providing a more complete compliance picture in a single pass.

### Configuration
Edit `PROJECTS_TO_SCAN` at the top of the script.

### Usage
```bash
chmod +x updated-ssl-policies.sh
./updated-ssl-policies.sh
```
