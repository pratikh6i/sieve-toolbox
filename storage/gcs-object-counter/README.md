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
