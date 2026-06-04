# Cloud Armor Security Automations

A comprehensive suite of tools to manage, analyze, monitor, and provision Google Cloud Armor security policies.

---

## 1. Cloud Armor Adaptive Protection Enablement (`enable-adaptive-protection.sh`)
- **Purpose**: Automates enabling Layer 7 DDoS Defense across all policies in a specified project.
- **Usage**:
  ```bash
  chmod +x enable-adaptive-protection.sh && ./enable-adaptive-protection.sh
  ```

---

## 2. GCP Log Link Opener (`open-gcp-log-links.py` / `links-template.json`)
- **Purpose**: Converts local IST times to UTC and automatically opens Chrome tabs for WAF logs and monitoring dashboards.
- **Usage**:
  ```bash
  python3 open-gcp-log-links.py
  ```

---

## 3. Cloud Armor Preview Rule Analyzer (`audit-preview-rules.py`)
- **Purpose**: High-throughput read-only tool that inventories WAF policies and their preview rules, queries logs in daily chunks to bypass query timeout limits, maps triggers to OWASP signature descriptions, and exports results.
- **Prerequisites**:
  ```bash
  pip install google-cloud-compute google-cloud-logging tqdm
  ```
- **Usage**:
  ```bash
  python3 audit-preview-rules.py -f projects.txt -o report.csv
  ```

---

## 4. Policy Metadata Collector (`collect-policy-metadata.py`)
- **Purpose**: Parallelized multithreaded script that gathers policies, rules, and backend attachments across a project list.
- **Usage**:
  ```bash
  python3 collect-policy-metadata.py -f projects.txt --threads 10
  ```

---

## 5. Apply Standard Preview WAF Policies (`apply-preview-waf-policies.sh`)
- **Purpose**: Provisions a security policy (`std-armor-policy`) with 15 preconfigured WAF rules in preview mode across a list of projects.
- **Usage**:
  - Edit `PROJECTS` in `apply-preview-waf-policies.sh` and run:
  ```bash
  chmod +x apply-preview-waf-policies.sh
  ./apply-preview-waf-policies.sh
  ```

---

## 6. Auto-Investigate 429 Incidents (`auto-investigate-429.py`)
- **Purpose**: Auto-investigates load balancer HTTP 429 rate limit violations, conducts WHOIS lookup on offending IPs, and posts structured alerts to a Google Chat Webhook.
- **Prerequisites**:
  - Requires a local rule inventory JSON file and GCP Application Default Credentials configured.
  - Set the `GC_WEBHOOK_URL` and `RULE_INVENTORY_PATH` env variables or edit the script configuration.
- **Usage**:
  ```bash
  python3 auto-investigate-429.py
  ```

---

## 7. Batch 429 Log Analyzer (`analyze-429-logs.py`)
- **Purpose**: Parses email alert logs from a CSV export, queries Cloud Logging around incident windows, enriches IPs, and groups rules.
- **Usage**:
  ```bash
  python3 analyze-429-logs.py alerts_export.csv
  ```

---

## 8. Monitoring Counters (`monitoring/`)

### A. Preview Log Hit Counter (`monitoring/log-hit-counter.py`)
- **Purpose**: Counts preview rule log hits by splitting the time range into daily jobs to prevent logging API timeouts.
- **Usage**:
  ```bash
  python3 monitoring/log-hit-counter.py
  ```

### B. Metrics Hit Counter (`monitoring/monitoring-hit-counter.py`)
- **Purpose**: Quick-checks the total aggregated evaluated counts for a preview rule over the last 30 days using the Monitoring API.
- **Usage**:
  ```bash
python3 monitoring/monitoring-hit-counter.py
  ```

---

## Multi-Project Cloud Armor Scanner (`multi-project-ca-scanner.sh`)

- **Purpose**: Shell script that audits Cloud Armor policy rules across multiple projects in a single run. Lists all security policies, their rules, actions (allow/deny/redirect), priorities, and target backends.
- **Configuration**: Edit `PROJECT_LIST` at the top of the script with your project IDs.
- **Usage**:
  ```bash
  chmod +x multi-project-ca-scanner.sh
  ./multi-project-ca-scanner.sh > ca_policy_report.csv
  ```

---

## GCP Security Audit (`gcp-security-audit.py`)

- **Purpose**: Standalone Python script that audits Cloud Armor policies within a project, focusing on WAF rule validation, rule ordering issues, and preview vs. enforcement mode mismatches. Outputs findings in a structured CSV.
- **Usage**:
  ```bash
  python3 gcp-security-audit.py
  # Prompted for Project ID
  ```
