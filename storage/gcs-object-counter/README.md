# GCS Bucket Object Counter

## Purpose
This script lists all Google Cloud Storage (GCS) buckets within a specified project and prints the object counts for each bucket. It is useful for security auditing, storage inventory assessments, and lifecycle policy reviews.

## Target Variables to Change
None. The script prompts interactively for:
*   `Project ID`

## Prerequisites
*   **Libraries**: Python 3.x with `google-cloud-storage` library installed.
    ```bash
    pip install google-cloud-storage
    ```
*   **Authentication**: Authenticate using standard Google Cloud Application Default Credentials (ADC):
    ```bash
    gcloud auth application-default login
    ```
*   **IAM Roles**: `Storage Admin` or `Storage Object Viewer` (to list buckets and count objects).

## Usage
```bash
python3 bucket-object-counter.py
```

---

## Multi-Project Storage Security Scanner (`multi-project-storage-scanner.sh`)

### Purpose
Scans GCS buckets across multiple projects for public access, uniform bucket-level access status, and logging configuration. Outputs a CSV report.

### Configuration
Edit `PROJECT_LIST` at the top of the script:
```bash
PROJECT_LIST=("your-project-id-1" "your-project-id-2")
```

### Usage
```bash
chmod +x multi-project-storage-scanner.sh
./multi-project-storage-scanner.sh > gcp_storage_security_audit.csv
```

### Output Columns
`Project ID, Bucket Name, Location, Public Access, Uniform Bucket Access, Logging Enabled`
