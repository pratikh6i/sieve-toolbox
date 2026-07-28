# SecOps Case Exporter

High-speed bulk exporter for Google SecOps (Chronicle) cases to CSV using parallel time-sliced API streams.

---

## Features

- **Multi-stream parallel fetching** — splits the time range into concurrent workers for maximum throughput
- **Automatic 429 retry** — exponential backoff on rate limits, zero data loss
- **Human-readable output** — epoch timestamps → `12 July 2026, 18:32 IST`, camelCase headers → `Clean Title Case`
- **Flexible time input** — relative (`15d`, `90d`, `24h`) or absolute (`YYYY-MM-DD`) ranges
- **Deep custom fields** — optional per-case `customFieldValues` sub-resource fetch
- **Deduplication** — built-in case ID dedup across overlapping slices

## Prerequisites

- Python 3.8+
- `gcloud` CLI authenticated (`gcloud auth login`)
- `requests` library (auto-installed if missing)

## Usage

```bash
# Interactive mode — prompts for timeframe
python3 export_secops_cases.py -p YOUR_PROJECT_ID -i YOUR_INSTANCE_ID

# Export last 30 days
python3 export_secops_cases.py -p YOUR_PROJECT_ID -i YOUR_INSTANCE_ID -t 30d

# Export a specific date range with custom output
python3 export_secops_cases.py -p YOUR_PROJECT_ID -i YOUR_INSTANCE_ID \
  --start 2025-01-01 --end 2025-03-31 -o q1_cases.csv

# Include custom field values (slower, deeper export)
python3 export_secops_cases.py -p YOUR_PROJECT_ID -i YOUR_INSTANCE_ID -t 90d -c
```

## CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-p`, `--project` | GCP Project ID | *(required)* |
| `-i`, `--instance` | SecOps Customer / Instance ID | *(required)* |
| `-r`, `--region` | SecOps region (`us`, `eu`, `asia-south1`) | `us` |
| `-t`, `--timeframe` | Relative time (`15d`, `90d`, `24h`) | interactive |
| `--start` / `--end` | Absolute date range (`YYYY-MM-DD`) | — |
| `-f`, `--filter` | Additional API filter expression | — |
| `-o`, `--output` | Output CSV filename | auto-timestamped |
| `-d`, `--delimiter` | CSV delimiter | `\|` |
| `-s`, `--slices` | Parallel stream count | `6` |
| `-c`, `--fetch-custom` | Fetch deep custom field values | off |

## Variables to Change

| Variable | What to set |
|----------|-------------|
| `YOUR_PROJECT_ID` | Your GCP project ID (pass via `-p` flag) |
| `YOUR_INSTANCE_ID` | Your SecOps/Chronicle instance ID (pass via `-i` flag) |

---

## Reference
This script was created with the help of this Gemini chat: [Gemini Chat Reference](https://gemini.google.com/app/cb4b4dbe9a8abf91)

