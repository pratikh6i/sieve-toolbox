# Security Command Center (SCC) Audit Tools

A suite of tools for processing, auditing, bulk inactivating, and analyzing security findings exported from Google Cloud Security Command Center (SCC).

## Tools Overview

### 1. [analyze-scc-findings.py](analyze-scc-findings.py)
Parses and aggregates exported SCC findings CSV. It groups findings by GCP Project Name and Finding Category, displaying a sorted summary of finding counts to identify hotspots.

### 2. [bulk-inactivate-findings.sh](bulk-inactivate-findings.sh)
Reads finding names/IDs from a text file, checks if they are currently active, and bulk-updates them to `INACTIVE` state via the gcloud CLI.

### 3. [auto-analyze-scc-threats.py](auto-analyze-scc-threats.py)
Correlates SCC Cloud Armor threat logs. For findings in the last 30 days, it pulls a 20-minute log window from Cloud Logging around the incident, resolves WHOIS info for offending IPs, lists target URLs, HTTP methods, user agents, and status codes, and outputs an assessment CSV.

### 4. [let-him-cook.py](let-him-cook.py)
GCP Security Command Center (SCC) Executive Report Generator. Consolidates multiple SCC vulnerability CSV files into formatted 5-tab Excel reports with built-in 3D charts.

---

## Bulk Inactivate Findings (`bulk-inactivate-findings.sh`)

### Target Variables
- **FILE**: Input file containing finding IDs (one per line, e.g. `findings.txt`). Defaults to `findings.txt` if not passed as an argument.

### Prerequisites
- Google Cloud SDK (`gcloud`) installed and authenticated.
- Principal requires Security Command Center permissions to update findings (e.g. **Security Center Findings Editor** role).

### Usage
```bash
chmod +x bulk-inactivate-findings.sh
./bulk-inactivate-findings.sh findings-list.txt
```

---

## SCC Threat Auto-Analyzer (`auto-analyze-scc-threats.py`)

### Target Variables
- **Input CSV**: Auto-discovers the latest CSV file in the same directory (excluding output name).
- **Output CSV**: Generates `scc-automated-report.csv`.

### Prerequisites
- Google Cloud SDK authenticated with Application Default Credentials:
  ```bash
  gcloud auth application-default login
  ```
- Principal requires **Logging Viewer** (`roles/logging.viewer`) on target projects.
- Python 3 dependencies:
  ```bash
  pip install pandas google-cloud-logging ipwhois
  ```

### Usage
```bash
python3 auto-analyze-scc-threats.py
```

---

## SCC Findings Flattener (`flatten-scc-findings.py`)

### Purpose
Reads a raw SCC JSON export (`all_findings.json`) and dynamically flattens all nested fields into a clean, wide CSV using `pandas.json_normalize`. Ideal for bulk SCC exports that need to be analyzed in Google Sheets or Excel.

### Prerequisites
```bash
pip install pandas
```

### Usage
```bash
# First export findings from SCC:
gcloud scc findings list organizations/YOUR_ORG_ID --format=json > all_findings.json

# Then flatten:
python3 flatten-scc-findings.py
# Output: scc_all_findings_flattened.csv
```

---

## SCC Executive Report Generator (`let-him-cook.py`)

### Prerequisites
```bash
pip install pandas openpyxl
```

### Usage
```bash
python3 let-him-cook.py
```
Follow the interactive prompts to:
1. Enter the **Customer Name**.
2. Provide **SCC export CSV paths** (wildcards like `*.csv` are supported).
3. The tool generates styled Excel reports (`*_OS_Vulnerability_Report_*.xlsx` and `*_Software_Vulnerability_Report_*.xlsx`) featuring 3D Pie and Stacked Column charts.

