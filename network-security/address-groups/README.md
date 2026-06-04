# GCP Network Security IP Address Groups Extractor

## Purpose
This tool queries global Network Security IP Address Groups across a comma-separated list of Google Cloud projects, parses the configuration with `jq`, and writes the details to a pipe-delimited CSV.

## Target Variables
- **Project IDs**: Entered interactively as a comma-separated list.
- **Output File**: Saved as `address_groups_report.csv` in the execution folder.

## Prerequisites
- Google Cloud SDK (`gcloud`) installed and authenticated.
- `jq` JSON processor installed on the local system.
- The authenticated principal must have the **Network Security Viewer** or similar permissions to list address groups.

## Usage
Make the script executable and run it:
```bash
chmod +x get-address-groups.sh
./get-address-groups.sh
```
