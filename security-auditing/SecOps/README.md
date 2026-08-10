# SecOps Case Exporter (v3)

High-speed bulk exporter for Google SecOps (Chronicle) cases to CSV using parallel time-sliced API streams.

---

## Features

- **Resume with Fast-Forward**: Automatically detects the latest watermark from an existing CSV and scans only the uncovered/new timeframe (+2h safety overlap).
- **Gap-Aware Scanning**: Scans previously unexported older ranges if you widen the timeframe window (use `--full-rescan` to override and force a complete rescan).
- **Multi-Stream Parallel Fetching**: Splits timeframe into concurrent workers to maximize API throughput.
- **Automatic Rate-Limit & Token Handling**: Smart exponential backoff on `429` / `RESOURCE_EXHAUSTED` errors to prevent data loss.
- **Crash-Safe & Checkpointed Writes**: Writes dynamically to a temp file and performs atomic renaming on completion. Periodic checkpoints ensure progress is not lost.
- **Clean Live Dashboard**: Displays a single-line live progress bar, processing rates, ETA, and rate-limiting metrics instead of verbose terminal logs.
- **Readable Output**: Converts epoch timestamps to `DD MMMM YYYY, HH:MM IST` and maps API camelCase keys into spaces-separated clean column headers.

---

## Prerequisites

- Python 3.8+
- `gcloud` CLI authenticated (`gcloud auth login`)
- `requests` library (auto-installed if missing)

---

## Usage

```bash
# New Export: Interactive wizard (prompts for timeframe if omitted)
python3 export_secops_cases.py -p YOUR_PROJECT_ID -i YOUR_INSTANCE_ID

# Export specific timeframe (e.g. 30 days)
python3 export_secops_cases.py -p YOUR_PROJECT_ID -i YOUR_INSTANCE_ID -t 30d

# Resume Export (watermark fast-forward only scanning new cases)
python3 export_secops_cases.py -p YOUR_PROJECT_ID -i YOUR_INSTANCE_ID --resume existing_report.csv

# Resume Export with complete re-scan
python3 export_secops_cases.py -p YOUR_PROJECT_ID -i YOUR_INSTANCE_ID --resume existing_report.csv --full-rescan

# Export specific date range
python3 export_secops_cases.py -p YOUR_PROJECT_ID -i YOUR_INSTANCE_ID --start 2026-01-01 --end 2026-03-31 -o q1_report.csv
```

---

## CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-p`, `--project` | GCP Project ID | *Required (or env default)* |
| `-i`, `--instance` | SecOps Instance/Customer ID | *Required (or env default)* |
| `-r`, `--region` | SecOps region (`us`, `eu`, `asia-south1`) | `us` |
| `-t`, `--timeframe` | Relative timeframe (e.g., `15d`, `90d`, `24h`) | interactive |
| `--start` / `--end` | Absolute date range (`YYYY-MM-DD`) | — |
| `-o`, `--output` | Output CSV filename | auto-timestamped |
| `--resume` | Resume export from an existing CSV file | — |
| `--full-rescan` | Disable watermark fast-forward; re-scan the entire timeframe | off |
| `-s`, `--slices` | Parallel streams for Phase 1 time-slicing | `6` |
| `-w`, `--workers` | Parallel worker threads for Phase 2 hydration | `40` |
| `-c`, `--fetch-custom` | Fetch deep `customFieldValues` sub-resource per case | off |
| `--checkpoint-every` | Auto-save CSV every N hydrated cases (0 to disable) | `2000` |
| `--no-color` | Disable ANSI terminal colors | off |
