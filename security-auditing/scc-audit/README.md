# Security Command Center (SCC) Findings Analyzer

## Purpose
This tool parses and aggregates security findings exported from Google Cloud Security Command Center (SCC). It groups findings by GCP Project Name and Finding Category, displaying a sorted summary of finding counts to help engineers identify security hotspots.

## Target Variables to Change
*   **Finding CSV**: Place your exported SCC CSV file in the same directory as this script and name it `findingsofssc.csv`.

## Prerequisites
*   **Libraries**: Python 3.x with `pandas` library installed.
    ```bash
    pip install pandas
    ```
*   **Input Data**: An SCC findings export file containing the columns `resource.gcp_metadata.project_display_name` and `finding.category`.

## Usage
```bash
python3 analyze-scc-findings.py
```
