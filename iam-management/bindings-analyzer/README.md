# IAM Bindings Role Summarizer

## Purpose
This tool parses a list of exported Google Cloud IAM role bindings in JSON format and groups them by principal. It outputs a consolidated table showing each unique IAM principal and all of their associated roles.

## Target Variables to Change
*   **Input File Path**: By default, the script looks for `iam-bindings-sample.json` in the same directory. You can edit `filename` in `summarize-iam-bindings.py` to point to your actual exported bindings JSON file.
*   **Input Data Placeholders**: Replace placeholders like `YOUR_PROJECT_ID`, `YOUR_PROJECT_NUMBER`, and `YOUR_DOMAIN` in your input JSON with actual GCP details before processing.

## Prerequisites
*   Python 3.x installed.
*   An exported JSON file of IAM bindings.

python3 summarize-iam-bindings.py
```

---

## IAM Recommender CSV Processor (`process-bindings-csv.py`)

### Purpose
Processes a raw IAM Recommender text file (`iam-raw.txt`) and a matching IAM bindings CSV (`iam-binding.csv`) to produce a clean, merged output (`iam-bindings-final.csv`). Maps role recommendations (REVOKE/REPLACE) to their corresponding bindings data.

### Usage
```bash
python3 process-bindings-csv.py
# Reads: iam-raw.txt and iam-binding.csv
# Output: iam-bindings-final.csv
```

---

## IAM Raw Bindings Formatter (`format-raw-bindings.py`)

### Purpose
Transforms `gcloud projects get-iam-policy` raw output text into a structured, project-grouped format. Useful as a preprocessing step before importing into Google Sheets.

### Usage
```bash
python3 format-raw-bindings.py
# Reads: iam-raw.txt
# Prints formatted output to stdout
```

---

## IAM Bindings Summary by Project (`summarize-bindings-by-project.py`)

### Purpose
Groups IAM Recommender CSV output by project and role, counting the number of principals per role recommendation across all projects. Outputs a summary CSV for governance review.

### Usage
```bash
python3 summarize-bindings-by-project.py
# Reads: iam-binding.csv
# Output: project_role_summary.csv
```
