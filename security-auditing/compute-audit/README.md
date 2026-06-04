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

---

## 4. VM OS Licensing Auditor (`audit-vm-os-licensing.sh`)

### Purpose
Parallelized, org-aware scanner that inventories all Compute Engine instances across an entire GCP organization and detects their OS type (Windows Server, RHEL, Ubuntu, Debian, CentOS, SUSE, or Linux/Other) using license and disk image metadata. Useful for Windows licensing audits and OS-specific compliance checks.

### Prerequisites
- `gcloud` CLI authenticated with org-level access.
- `jq` installed.
- IAM: `roles/compute.viewer` on all scanned projects.

### Usage
```bash
chmod +x audit-vm-os-licensing.sh
./audit-vm-os-licensing.sh > windows_report.csv
# Prompted interactively for your GCP Organization ID.
```

**Output columns**: Project ID, Instance Name, Zone, Status, Is Windows?, Detected OS Family

---

## 5. VM Security Profile Auditor (`audit-vm-security-profile.sh`)

### Purpose
Interactive script that audits Shielded VM configuration (Secure Boot, vTPM, Integrity Monitoring), API scopes, public IPs, OS Config agent, Confidential Compute, and serial port access. Generates actionable security recommendations per instance.

### Target Variables
- **PROJECT_IDS_LIST**: Edit the array in the script with your actual GCP project IDs.

### Prerequisites
- `gcloud` CLI authenticated.
- `jq` installed.
- IAM: `roles/compute.viewer` and `roles/serviceusage.serviceUsageViewer` on target projects.

### Usage
```bash
chmod +x audit-vm-security-profile.sh
./audit-vm-security-profile.sh > vm_security_report.csv
# Interactive: choose to scan all pre-defined projects or enter a single custom project.
```

**Output columns**: Project ID, Instance Name, Zone, Service Account, Has Public IP, Public IP Address, API Scopes, OS Config, Confidential Compute, Secure Boot, vTPM, Integrity Monitoring, Serial Port, Patch Manager Status, Recommendation

---

## 6. Read-Only Compute Audit (`read-only-compute-audit.py`)

### Purpose
Python script for a comprehensive, read-only audit of all Compute Engine instances across a project. Covers machine type, boot disk, public IP, service account, deletion protection, and metadata. Suitable for an initial baseline assessment of VM configurations.

### Usage
```bash
python3 read-only-compute-audit.py
# Prompted for Project ID
# Output: CSV to stdout or file
```

---

## 7. Compute Audit Apr 2026 (`compute-audit-apr2026.py`)

### Purpose
Updated version of the read-only compute auditor with additional fields and logic introduced in April 2026 (including enhanced Shielded VM checks and improved scope analysis).

### Usage
```bash
python3 compute-audit-apr2026.py
```

---

## 8. API Scope Lister (`list-api-scopes.sh`)

### Purpose
Quickly lists all Compute Engine instances in a project along with their service account and API scope configuration. Useful as a lightweight, fast alternative to the full VM security auditors.

### Usage
```bash
chmod +x list-api-scopes.sh
./list-api-scopes.sh
```

---

## 9. GCP Compute Audit (`gcp-compute-audit.sh`)

### Purpose
A shell-based compute inventory script covering instance name, zone, machine type, status, external IP, and OS disk. Designed for quick multi-project snapshots.

### Usage
```bash
chmod +x gcp-compute-audit.sh
./gcp-compute-audit.sh
```

---

## 10. Serial Port Crawler (`serial-port-crawl.sh`)

### Purpose
Scans all Compute Engine instances across specified projects to identify those with **serial port access enabled** — a potential security risk that allows low-level access to the VM console.

### Usage
```bash
chmod +x serial-port-crawl.sh
./serial-port-crawl.sh
```
