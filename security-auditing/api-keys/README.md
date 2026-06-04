# API Keys Auditor

Inventories all GCP API Keys across one or more projects in parallel and exports a CSV report.

## Purpose

Lists all GCP API Keys per project, capturing key metadata including:
- Key display name and UID
- Creation date
- API restrictions (which GCP services are allowed)
- Application restrictions (allowed IPs, HTTP referrers, Android/iOS apps)
- Access errors (API not enabled, permission denied)

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| `gcloud` CLI | Authenticated and configured |
| IAM Role | `roles/apikeys.viewer` on each target project |
| API | `apikeys.googleapis.com` must be enabled in each project |

## Usage

```bash
python3 list-api-keys.py
# Prompted: Enter the Project IDs separated by commas: project-a,project-b,project-c
```

**Output**: `gcp_api_keys_report.csv` in the current directory.

## Configuration

Edit the constants at the top of the script if needed:

| Variable | Default | Description |
|----------|---------|-------------|
| `OUTPUT_CSV` | `gcp_api_keys_report.csv` | Output file name |
| `MAX_THREADS` | `10` | Parallel threads for multi-project scans |

## Output Columns

| Column | Description |
|--------|-------------|
| Project ID | GCP project identifier |
| Key Display Name | Human-readable name of the key |
| Key ID (UID) | Unique identifier |
| Creation Date | ISO 8601 timestamp |
| API Restrictions | Target GCP services or "Unrestricted" |
| Application Restrictions | IP/referrer/app restrictions or "None" |
| Status / Debug Info | "Success" or error description |
