# Ingress Logging Component

This component provides advanced read-only threat auditing tools that inspect Google Cloud HTTP(S) Load Balancer logs and Security Policy logs to identify anomalies, brute force attacks, scanning patterns, and potential WAF bypasses.

## Tools Overview

### 1. [asm-ingress-analyzer.py](asm-ingress-analyzer.py)
A high-throughput threat scanner that pulls load balancer access logs across multiple projects, matches sources against a whitelist of authorized ASM (Attack Surface Management) scanners, flags external threats based on volume, error rates, and path patterns, performs optional IPinfo geographic/ASN enrichment, and formats the output into executive reports.

---

## ASM Ingress Threat Analyzer (`asm-ingress-analyzer.py`)

### Purpose
- Auditing HTTP(S) load balancer access logs to detect external scanning, brute-forcing, and vulnerability probing.
- Whitelisting known internal scanning IPs to suppress noise.
- Flagging severe actors using heuristics (e.g. sustained volume, high 403 block rate, 404 scanning, or 401 credential attacks).
- Querying IPinfo API in batch mode (free tier friendly) to obtain geolocation and ISP/ASN categorization.
- Exporting details to a raw CSV data table and generating an Executive Markdown summary report.

### Key Features
- **Strictly Read-Only**: Interacts solely with Cloud Logging API. Does not modify configurations.
- **Global Rate Limiting**: Employs a unified rate limiter (55 requests/minute) to respect consumer-project quotas across concurrent threads.
- **High-Water Mark Timestamps**: Monotonic log sorting allows resuming interrupted processes without double-counting entries.
- **Scrub on Failure**: Clears partial project extractions if a worker fails to prevent database pollution.

### Prerequisites
- Python 3 with `google-cloud-logging` installed:
  ```bash
  pip install --user google-cloud-logging
  ```
- Active Google Cloud SDK authentication with permissions to read project logging entries (`roles/logging.viewer`).
- (Optional) IPinfo API key for provider/geolocation enrichment.

### Usage
Run the script:
```bash
python3 asm-ingress-analyzer.py
```
You will be prompted for:
1. GCP Project IDs (comma-separated).
2. Additional whitelisted scanner IPs (comma-separated).
3. Scanning timeframe (either relative e.g., `2d`, or absolute IST timestamps).
4. Number of worker threads.
5. URL capture preference (capturing exact request paths).
6. IPinfo API Token (optional, press Enter to skip).

### Output Artifacts
The tool writes outputs under a directory structured as `YYYY-MM-DD/HH-MM/`:
- `Security_Analysis_Data.csv`: Complete, sorted database of scanned IPs and HTTP properties.
- `Security_Analysis_Report.md`: Executive summary detailing mitigated vs unmitigated attacks, country metrics, top providers, and action recommendations.
- `debug.log`: Detailed engine logs.
