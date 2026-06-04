# IAM Bindings Role Summarizer

## Purpose
This tool parses a list of exported Google Cloud IAM role bindings in JSON format and groups them by principal. It outputs a consolidated table showing each unique IAM principal and all of their associated roles.

## Target Variables to Change
*   **Input File Path**: By default, the script looks for `iam-bindings-sample.json` in the same directory. You can edit `filename` in `summarize-iam-bindings.py` to point to your actual exported bindings JSON file.
*   **Input Data Placeholders**: Replace placeholders like `YOUR_PROJECT_ID`, `YOUR_PROJECT_NUMBER`, and `YOUR_DOMAIN` in your input JSON with actual GCP details before processing.

## Prerequisites
*   Python 3.x installed.
*   An exported JSON file of IAM bindings.

## Usage
```bash
python3 summarize-iam-bindings.py
```
