# Security Command Center (SCC) Audit Tools

A suite of tools for processing, auditing, bulk inactivating, and analyzing security findings exported from Google Cloud Security Command Center (SCC).

## Tools Overview

### 1. [analyze-scc-findings.py](analyze-scc-findings.py)
Parses and aggregates exported SCC findings CSV. It groups findings by GCP Project Name and Finding Category, displaying a sorted summary of finding counts to identify hotspots.

### 2. [bulk-inactivate-findings.sh](bulk-inactivate-findings.sh)
Reads finding names/IDs from a text file, checks if they are currently active, and bulk-updates them to `INACTIVE` state via the gcloud CLI.

### 3. [auto-analyze-scc-threats.py](auto-analyze-scc-threats.py)
Correlates SCC Cloud Armor threat logs. For findings in the last 30 days, it pulls a 20-minute log window from Cloud Logging around the incident, resolves WHOIS info for offending IPs, lists target URLs, HTTP methods, user agents, and status codes, and outputs an assessment CSV.

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
