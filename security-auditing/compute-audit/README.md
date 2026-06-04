# GCP Compute Engine Security Auditing Tools

A suite of tools for auditing virtual machines, OS images, internal/external IPs, deletion protection, startup/shutdown scripts, metadata, and service account API scopes.

---

## 1. VM Security Auditor (`vm-security-auditor.py`)

### Purpose
High-performance parallel script that queries VM instance configurations (machine sizes, network interface IPs, ephemeral vs static external IPs, OS images, service accounts, deletion protection status, metadata scripts, and tags) across a large set of projects.

### Target Variables
- **PROJECT_IDS**: Configured in script or loaded dynamically via `GCP_PROJECTS` environment variable (as JSON array, e.g. `export GCP_PROJECTS='["proj-1", "proj-2"]'`).
- **OUTPUT_FILE**: Generates `gcp_vm_parallel_report.csv`.

### Prerequisites
- Python 3 with no external dependencies (uses standard library `subprocess` and `concurrent.futures`).
- Google Cloud SDK (`gcloud`) authenticated.
- Principal requires **Compute Viewer** (`roles/compute.viewer`) on target projects.

### Usage
```bash
python3 vm-security-auditor.py
```

---

## 2. Multi-Project Scope Auditor (`vm-scope-auditor-multi.sh`)

### Purpose
Shell script that scans a comma-separated list of projects, inventories Compute Instances, maps their service accounts and API scopes, and classifies the scope usage as "Default Scope", "Full Scope", "Custom Scope", or "No Scopes".

### Target Variables
- Prompted interactively for a comma-separated list of GCP Project IDs.
- Outputs pipe-separated CSV fields to stdout.

### Usage
```bash
chmod +x vm-scope-auditor-multi.sh
./vm-scope-auditor-multi.sh > vm_scope_report.csv
```

---

## 3. Single-Project Scope Auditor (`vm-scope-auditor-single.sh`)

### Purpose
Shell script that scans a single project's Compute instances and audits their service accounts and API scopes.

### Usage
```bash
chmod +x vm-scope-auditor-single.sh
./vm-scope-auditor-single.sh > single_project_scope_report.csv
```
