# IAM Management Component

Tools and scripts for auditing GCP Identity & Access Management (IAM) configurations, analysing bindings, processing recommendations, and producing security hardening reports.

## Subdirectories and Tools

### 1. [Bindings Analyzer](bindings-analyzer/)
Analyses GCP IAM bindings and outputs a summary of unique principals and their assigned roles.

### 2. [Recommender Processor](recommender-processor/)
Processes IAM recommendations from GCP's Recommender API to automate security hardening actions.

### 3. [IAM Audit Report Generator](iam-audit-report.py)
A Python utility that generates a comprehensive audit report detailing service accounts, assigned roles, and actual permission usage in the last 90 days. It enriches results with security commentary highlighting over-privileged or inactive service accounts.

---

## IAM Audit Report (`iam-audit-report.py`)

### Purpose
Audits a Google Cloud project to map assigned roles to service accounts, compares them with Recommender permissions usage insights, and flags unused privileges.

### Target Variables
- **Project ID**: Prompted interactively during execution.
- **Output File**: Saved as `iam_audit_report_[PROJECT_ID].csv`.

### Prerequisites
- Google Cloud SDK (`gcloud`) installed and authenticated.
- Principal requires:
  - **Cloud Asset Viewer** (`roles/cloudasset.viewer`)
  - **Recommender Viewer** (`roles/recommender.iamViewer`)
  - **Security Reviewer** (`roles/iam.securityReviewer`) or **IAM Admin** (`roles/iam.iamAdmin`)
- Python 3 dependencies:
  ```bash
  pip install google-cloud-asset google-cloud-recommender google-cloud-iam
  ```

### Usage
```bash
python3 iam-audit-report.py
```

---

## IAM Details Lister (`list-iam-details.sh`)

### Purpose
Shell script that retrieves and displays IAM policy bindings for a project or folder/organization using `gcloud`. Exports bindings in a clean human-readable format and optionally writes to a text file. Useful as a quick read-only snapshot of IAM state.

### Usage
```bash
chmod +x list-iam-details.sh
./list-iam-details.sh
# Prompted for: Project ID or Org/Folder ID, scope type, and optional output file.
```
