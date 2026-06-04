# Load Balancer Component

This component provides tools to audit GCP HTTP(S) Load Balancer topologies and their associated routing rules and security profiles (e.g. Cloud Armor policies).

## Tools Overview

### 1. [gcp-urlmap-extractor.py](gcp-urlmap-extractor.py)
A read-only python tool that queries URL maps (Load Balancer configurations) and backend services for specified projects, extracts domain routes, paths, targets, and identifies which backends lack a Cloud Armor protection policy.

---

## URL Map Extractor (`gcp-urlmap-extractor.py`)

### Purpose
- Extract and document routes, domains, target paths, backend services, and Security Policies (Cloud Armor) across HTTP(S) load balancers.
- Group and highlight routes that are protected vs unprotected by Cloud Armor.
- Generate a structured pipe-delimited output file `url_map_inventory.csv`.

### Target Variables
- **Output Report**: Writes results to `url_map_inventory.csv` in the current directory.

### Prerequisites
- Google Cloud SDK (`gcloud`) installed and authenticated.
- Authorized principal requires Compute Viewer permissions (`roles/compute.viewer`) or equivalent read access on target GCP projects.
- Python 3 environment.

### Usage
Run the script and provide comma-separated project IDs when prompted:
```bash
python3 gcp-urlmap-extractor.py
```

Example prompt:
```text
  ══════════════════════════════════════════════
    🗺️  URL Map API Extractor  |  Read-Only
  ══════════════════════════════════════════════

  Enter GCP Project IDs (comma-separated): my-prod-project, my-staging-project
```
