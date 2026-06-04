# Log Converters & Utilities

Python utility scripts for converting GCP logs and JSON exports into CSV format, and sending automated emails via Google Apps Script.

## Scripts

### 1. `gcp-logs-json-to-csv.py` — GCP Log JSON to Pipe-Separated CSV

Converts GCP Cloud Logging JSON exports (e.g., downloaded from the Logs Explorer or BigQuery) into a pipe-separated CSV file suitable for import into Google Sheets.

#### Usage

```bash
python3 gcp-logs-json-to-csv.py
# Reads: gcp_logs.json (or modify INPUT_FILE in the script)
# Output: output.csv (pipe-separated)
```

#### Importing to Google Sheets
File → Import → Upload → Custom Separator → `|`

---

### 2. `json-to-csv-flattener.py` — Nested JSON Deep Flattener

Recursively flattens deeply nested JSON files (e.g., SCC finding exports) into a flat CSV with one row per record. Uses `pandas.json_normalize` to handle arbitrary nesting depth.

#### Usage

```bash
python3 json-to-csv-flattener.py
# Reads: threats.csv (or modify INPUT_FILE in the script)
# Output: flattened CSV to stdout
```

---

### 3. `email-via-apps-script.py` — Automated Email via Apps Script

Sends emails using a Google Apps Script Web App endpoint, authenticated via GCP Application Default Credentials (ADC). Useful for sending automated reports from GCP environments without SMTP setup.

#### Prerequisites

```bash
pip install requests google-auth
gcloud auth application-default login
```

#### Configuration

Edit the constants at the top of `email-via-apps-script.py`:

| Variable | Description |
|----------|-------------|
| `APPS_SCRIPT_URL` | Your deployed Apps Script Web App URL |
| `AUTH_KEY` | Secret key validated by the Apps Script |
| `EMAIL_RECIPIENT` | Recipient email address |
| `EMAIL_SUBJECT` | Email subject line |
| `EMAIL_BODY` | Email body text |

#### Usage

```bash
python3 email-via-apps-script.py
```

#### Setting Up the Apps Script

1. Create a Google Apps Script project at [script.google.com](https://script.google.com)
2. Add a `doPost(e)` function that validates `auth_key` and calls `GmailApp.sendEmail()`
3. Deploy as a Web App with "Execute as: Me" and "Who has access: Anyone"
4. Copy the deployment URL into `APPS_SCRIPT_URL`

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Python 3 | |
| `pandas` | `pip install pandas` (for json-to-csv-flattener.py) |
| `requests` + `google-auth` | `pip install requests google-auth` (for email-via-apps-script.py) |
