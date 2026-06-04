# Cloud Armor Monitoring Tools

Scripts for monitoring Cloud Armor preview rule metrics and scraping Gmail 4xx alert emails.

## Scripts

### 1. `audit-preview-metrics.py` (in parent directory)

Queries Cloud Armor preview rule hit counts via the Cloud Monitoring API for a specified time window. Outputs a pipe-separated CSV with per-rule preview request counts.

#### Prerequisites
```bash
pip install google-cloud-compute google-cloud-monitoring tqdm python-dateutil
```

#### Usage
```bash
python3 audit-preview-metrics.py
# Prompts for:
#   - Project ID
#   - Date and time (DD-MM-YYYY HH:MM IST format)
```

**Output**: `cloud_armor_preview_metrics.csv` with columns: Project ID, Policy Name, Rule Priority, Rule Description, Preview Request Count.

#### Configuration
Edit constants at the top of the script:

| Variable | Default | Description |
|----------|---------|-------------|
| `LOOKBACK_MINUTES` | `60` | Minutes of metrics to look back from the given time |
| `RETRY_COUNT` | `3` | API retry attempts per rule |
| `MAX_THREADS` | `10` | Parallel threads for rule processing |

---

### 2. `gmail-alert-scraper.py`

Automates Chrome via `undetected-chromedriver` (bypasses bot detection) to scrape 4xx response code alert emails from Gmail. Parses structured alert data (trigger values, project IDs, URL maps, response codes) into a CSV.

#### Prerequisites
```bash
pip install undetected-chromedriver selenium pandas
# Chrome browser must be installed
```

#### Usage
```bash
python3 gmail-alert-scraper.py
# Opens Chrome browser — log in to Gmail manually, then press ENTER in the terminal.
```

#### Configuration
Edit constants at the top of the script:

| Variable | Default | Description |
|----------|---------|-------------|
| `SEARCH_QUERY` | `label:clients-awr-4xx-alerts ...` | Gmail search query to filter alert emails |
| `CSV_FILENAME` | `gmail_scrape_report.csv` | Output file name |

#### Output Columns
| Column | Description |
|--------|-------------|
| Date | Email timestamp |
| Status | Resolved / Unresolved |
| Trigger Value | Count that triggered the alert |
| Closing Value | Count when alert resolved |
| Response Code | HTTP status code (e.g., 403, 429) |
| Project ID | Extracted from email subject |
| URL Map | GCP URL map name |
| Subject | Full email subject |
| Full Body | Complete email body text |
