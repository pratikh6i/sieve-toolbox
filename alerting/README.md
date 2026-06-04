# GCP Monitoring Alert Policies Exporter

## Purpose
This tool fetches all configured alert policies (Metric Threshold, Metric Absence, PromQL, and MQL conditions) for a specified Google Cloud project and exports them to a readable CSV report for compliance audits and security reviews.

## Target Variables
- **Project ID**: The GCP Project ID to query, prompted interactively.
- **Output Filename**: Saved as `gcp_alert_policies_audit.csv` by default.

## Prerequisites
- Google Cloud SDK (`gcloud`) installed and authenticated.
- The authenticated principal must have the **Monitoring Viewer** (`roles/monitoring.viewer`) role on the target project.
- Python 3 library dependencies:
  ```bash
  pip install google-cloud-monitoring
  ```

## Usage
Run the script and enter your GCP Project ID when prompted:
```bash
python3 export-alerts.py
```
