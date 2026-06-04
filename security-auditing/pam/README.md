# PAM (Privileged Access Management) Audit Tools

Tools for exporting and analyzing GCP Privileged Access Manager (PAM) entitlements across projects.

## `pam-entitlements-export.py`

### Purpose
Exports all GCP PAM entitlements across a list of projects into a unified CSV report. For each entitlement, captures:
- Entitlement name and status (Active/Inactive)
- Max grant duration
- Roles and conditions granted
- Requester, Approver, and Notification configurations

### Prerequisites

| Requirement | Notes |
|-------------|-------|
| Python 3 | |
| `google-cloud-privilegedaccessmanager` | `pip install google-cloud-privilegedaccessmanager` |
| IAM Role | `roles/privilegedaccessmanager.viewer` on target projects |
| GCP PAM API | `privilegedaccessmanager.googleapis.com` must be enabled |

### Usage

```bash
pip install google-cloud-privilegedaccessmanager

python3 pam-entitlements-export.py
# Prompted for a comma-separated list of Project IDs
# Output: GCP_PAM_Entitlements.csv
```

### Output Columns

| Column | Description |
|--------|-------------|
| Project ID | GCP project identifier |
| Entitlement Name | Short name of the PAM entitlement |
| Status | `ACTIVE` or `DELETED` |
| Max Duration | Maximum grant duration (e.g., `3600s`) |
| Roles & Conditions | IAM roles included in the entitlement with any conditions |
| Requester(s) | Principals allowed to request access |
| Approver(s) | Principals configured as approvers |
| Admin Notifications | Email addresses for admin alerts |
| Requester Notifications | Email addresses for requester alerts |
| Approver Notifications | Email addresses for approver alerts |
