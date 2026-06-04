# IAM Recommender Actions Processor

## Purpose
This tool processes GCP IAM Recommender payloads containing recommended changes (ADD and REMOVE actions) for role assignments. It aggregates recommendations by principal, displaying a consolidated list of roles to remove and roles to add.

## Target Variables to Change
*   **Input File Path**: By default, the script looks for `iam-recommendations-sample.json` in the same directory. You can edit `filename` in `process-iam-recommendations.py` to point to your actual exported recommender JSON file.
*   **Input Data Placeholders**: Replace placeholders like `YOUR_ORGANIZATION_ID` and `YOUR_DOMAIN` in your input JSON with actual GCP details before processing.

## Prerequisites
*   Python 3.x installed.
*   An exported JSON file of IAM Recommender actions.

## Usage
```bash
python3 process-iam-recommendations.py
```
