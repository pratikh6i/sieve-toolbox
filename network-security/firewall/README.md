# ICMP Firewall Rule Cleanup Tools

## Purpose
These scripts scan, audit, and clean up ICMP-only ingress firewall rules in Google Cloud Platform (GCP). In their default safe preview mode, they identify firewall rules that allow *only* the ICMP protocol and list them for deletion or disabling without modifying anything.
*   `disable-icmp-project.sh`: Audits firewall rules for a single target project ID.
*   `disable-icmp-organization.sh`: Fetches all projects under a target GCP Organization ID and audits ICMP rules across all of them sequentially.

## Target Variables to Change
None. The scripts prompt interactively for input parameters:
*   `Project ID` (for project script)
*   `Organization ID` (for organization-wide script)

To enable deletion or disabling instead of just previewing, uncomment the respective lines inside the loops in each script:
*   **To delete**: Uncomment `# gcloud compute firewall-rules delete ...`
*   **To disable**: Uncomment `# gcloud compute firewall-rules update ... --disabled`

## Prerequisites
*   **CLI Tools**: `gcloud` SDK and `jq` command-line JSON processor installed.
*   **IAM Roles**: `Compute Security Admin` or `Compute Admin` to delete/update firewall rules. Organization-wide execution requires the `Viewer` or `Browser` role at the organization level to list projects.

## Usage
### Project Level Audit
```bash
chmod +x disable-icmp-project.sh && ./disable-icmp-project.sh
```

### Organization Level Audit
```bash
chmod +x disable-icmp-organization.sh && ./disable-icmp-organization.sh
```
