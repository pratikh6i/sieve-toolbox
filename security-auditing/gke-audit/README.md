# GKE Audit Component

This component provides a robust engine for auditing Google Kubernetes Engine (GKE) clusters across multiple GCP projects. It discovers live GKE topologies, assesses compliance, analyzes control plane vs. node pool version status, and retrieves historical master/node upgrade log operations.

## Tools Overview

### 1. [gke-upgrade-audit.py](gke-upgrade-audit.py)
Sequentially inspects target GCP projects to retrieve active GKE clusters, their locations, control plane versions, node pool statuses (auto-upgrade state), and version alignment. It extracts the chronological history of cluster upgrade operations to generate a complete compliance and health matrix report.

---

## GKE Upgrade Audit Engine (`gke-upgrade-audit.py`)

### Purpose
- Discover active GKE clusters in target projects.
- Extract node pool configuration details (auto-upgrade status, versions).
- Detect and flag control plane vs. node pool version mismatches.
- Retrieve chronological upgrade history (last 5 operations) and identify the last successful upgrade date/time (in IST).
- Generate a pipe-delimited CSV matrix report.

### Target Variables
- **SOP_INVENTORY**: Pre-configured dictionary mapping project IDs to their primary logical purpose. Modify this dictionary inside the script to register your own GCP project metadata.
- **DEFAULT_PROJECTS**: The base list of GCP projects scanned by default.
- **Output Report**: Generates a pipe-delimited CSV file named `gke_upgrade_report_YYYYMMDD_HHMMSS.csv`.

### Prerequisites
- Google Cloud SDK (`gcloud`) installed and authenticated.
- The authenticated principal requires:
  - Kubernetes Engine Viewer (`roles/container.viewer`) or Kubernetes Engine Admin (`roles/container.admin`) on target GCP projects.
- Python 3 with standard libraries (`subprocess`, `csv`, `json`, `datetime`).

### Usage
Run the script interactively:
```bash
python3 gke-upgrade-audit.py
```

During execution, the script will:
1. Print the baseline project scope.
2. Ask if you want to temporarily append any additional comma-separated GCP Project IDs.
3. List the live GKE cluster topology found.
4. Prompt you to confirm (`Y/y`) before initiating deep upgrade log extraction.
