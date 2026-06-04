# MXToolbox Blacklist Checker

Checks a list of IP addresses against email/IP blacklists via MXToolbox's SuperTool, outputting a CSV report with status and blacklist count.

## Purpose

Automates the manual process of checking IP addresses against spam and abuse blacklists (RBLs). For each IP, the script scrapes MXToolbox's web interface to determine if the IP is listed and on how many blacklists.

## Use Case

- Verify IPs used by GCP outbound services are not blacklisted
- Validate IP reputation before routing critical traffic through them
- Investigate IPs flagged by Cloud Armor or SCC for abuse patterns

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Python 3 | |
| `requests` | `pip install requests` |
| `beautifulsoup4` | `pip install beautifulsoup4` |
| Network access | Must be able to reach `mxtoolbox.com` |

## Configuration

Edit the constants at the top of the script:

| Variable | Default | Description |
|----------|---------|-------------|
| `INPUT_FILE` | `ips.txt` | Text file with one IP per line |
| `OUTPUT_FILE` | `blacklist_results.csv` | Output CSV report |

## Usage

1. Create `ips.txt` with one IP address per line:
   ```
   8.8.8.8
   1.1.1.1
   192.168.0.1
   ```

2. Run the script:
   ```bash
   python3 mxtoolbox-blacklist-checker.py
   ```

3. Review `blacklist_results.csv`.

## Output Columns

| Column | Description |
|--------|-------------|
| IP Address | The checked IP |
| Status | `Clean`, `Listed in X blacklists`, or error message |
| Blacklist Count | Number of blacklists the IP appears on (0 = clean) |

## Notes

- The script adds a random 1.5–3.5 second delay between requests to be respectful of MXToolbox's servers.
- Page structure changes on MXToolbox may require updating the HTML selectors.
