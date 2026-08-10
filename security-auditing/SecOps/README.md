# Google SecOps Case Management Tools

A collection of Python scripts for exporting, checking, bulk-closing, and reconciling Google SecOps (Chronicle) cases against GCP Security Command Center (SCC).

---

## Prerequisites

All scripts require:
- Python 3.8+
- `gcloud` CLI authenticated:
  ```bash
  gcloud auth application-default login
  ```
- Install dependencies:
  ```bash
  pip install requests google-auth pandas
  ```

---

## Tools

### 1. [`export_secops_cases.py`](export_secops_cases.py) — Case Exporter (v3)
Exports all SecOps cases to CSV using parallel time-sliced API streams. Supports resume with fast-forward, crash-safe writes, and a live dashboard.

**Update before running:**
```python
# In the script (or pass via CLI flags)
DEFAULT_PROJECT_ID  = "YOUR_PROJECT_ID"
DEFAULT_INSTANCE_ID = "YOUR_INSTANCE_ID"
DEFAULT_REGION      = "us"   # Change if needed
```

**Usage:**
```bash
# New export — interactive wizard
python3 export_secops_cases.py -p YOUR_PROJECT_ID -i YOUR_INSTANCE_ID

# Export last 30 days
python3 export_secops_cases.py -p YOUR_PROJECT_ID -i YOUR_INSTANCE_ID -t 30d

# Resume from existing CSV
python3 export_secops_cases.py --resume existing_report.csv
```

---

### 2. [`check_secops_cases.py`](check_secops_cases.py) — Case Status Checker
Checks the open/closed status of a list of SecOps case IDs in parallel. Prints a summary report with counts of open, closed, and errored cases.

**Update before running:**
```python
PROJECT_ID  = "YOUR_PROJECT_ID"
INSTANCE_ID = "YOUR_INSTANCE_ID"
LOCATION    = "us"   # Change if needed
```

**Usage:**
```bash
python3 check_secops_cases.py
# Prompts: Enter Case IDs to check status (comma-separated): 101, 102, 103
```

---

### 3. [`close_secops_cases.py`](close_secops_cases.py) — Bulk Case Closer
Bulk-closes a list of SecOps case IDs in parallel batches. Falls back to individual case processing if a batch request fails.

**Update before running:**
```python
PROJECT_ID    = "YOUR_PROJECT_ID"
INSTANCE_ID   = "YOUR_INSTANCE_ID"
LOCATION      = "us"            # Change if needed
CLOSE_REASON  = "MAINTENANCE"   # Options: MAINTENANCE, FALSE_POSITIVE, etc.
ROOT_CAUSE    = "Other"
CLOSE_COMMENT = "Clean up activity."
```

**Usage:**
```bash
python3 close_secops_cases.py
# Prompts: Enter Case IDs to close (comma-separated): 101, 102, 103
```

---

### 4. [`secops_scc_scanner.py`](secops_scc_scanner.py) — SecOps vs. SCC Reconciler (Simple)
Reads a SecOps case export CSV, queries each associated SCC finding via the SCC REST API, and generates a CSV recommending whether to close or keep each case open.

Handles one SCC finding path per case. Use `process.py` if cases have multiple findings.

**Input required:** SecOps case export CSV (pipe `|` delimited, from `export_secops_cases.py`)

**Usage:**
```bash
python3 secops_scc_scanner.py
# Prompts: Enter the path/filename of exported SecOps cases CSV: secops_export.csv
```

**Outputs:**
- `scc_unique_findings_lookup.csv` — SCC state per finding
- `secops_case_reconciliation_report.csv` — Close/Keep recommendation per case

---

### 5. [`process.py`](process.py) — SecOps vs. SCC Reconciler (Multi-Path)
Extended version of `secops_scc_scanner.py`. Handles cases where multiple SCC findings are linked (semicolon-separated) and applies smarter close/keep decision logic.

**Rule:** Case is marked `CLOSE_SECOPS_CASE` only if **all** associated SCC findings exist and are `INACTIVE`.

**Input required:** SecOps case export CSV (pipe `|` delimited)

**Usage:**
```bash
python3 process.py
# Prompts: Enter SecOps export CSV filename: secops_export.csv
```

**Outputs:**
- `scc_unique_findings_lookup.csv` — SCC state per unique finding path
- `secops_case_reconciliation_report.csv` — Final case action recommendations

---

## Recommended Workflow

```
1. export_secops_cases.py   →  Export all open cases to CSV
2. process.py               →  Reconcile each case against SCC findings
3. check_secops_cases.py    →  Verify status of specific case IDs
4. close_secops_cases.py    →  Bulk-close cases recommended for closure
```
