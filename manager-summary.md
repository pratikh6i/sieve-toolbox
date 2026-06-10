# GCP Security Tools & Scripts — Built by Pratik Shetti

> **Repository**: [github.com/pratikh6i/sieve-toolbox](https://github.com/pratikh6i/sieve-toolbox)
> **Total Tools**: 121 scripts & files across 9 security domains
> **Tech Stack**: Python 3, Bash/Shell, Google Apps Script, GCP SDK (`gcloud`, `kubectl`)

---

## Summary Table

| Client | Domain | # Tools | Key Benefit |
|--------|--------|---------|-------------|
| AWR | Cloud Armor, SCC, IAM, Networking | 25+ | End-to-end GCP security posture management |
| PICKME | Compute, VM Security, Networking | 20+ | Multi-project VM and network audit automation |
| NTUC | IAM, Alerting, Workload Identity | 8 | Automated real-time SCC alerting + WIF migration |
| CardinalGroup | VM OS, Compute | 3 | Org-wide Windows VM license discovery |
| CxApp | SCC Findings | 2 | Flattened SCC exports for governance reviews |
| VITU | JSON/Data Utilities | 2 | Log flattening and CSV processing pipelines |
| ISM-Games | GKE, Prowler | 6 | Automated cloud security scanner on Kubernetes |
| D-mart | Reporting | 1 | Automated weekly security report generation |
| Multi-client / General | All Domains | 25+ | Reusable tools deployable across any GCP org |

---

## AWR
*Cloud security posture management across a large multi-project GCP environment.*

### Cloud Armor
| Tool | What It Does | Business Impact |
|------|-------------|-----------------|
| `audit-preview-rules.py` | Lists all Cloud Armor security policies and rules in preview mode | Identifies which WAF rules are being evaluated but not enforced |
| `apply-preview-waf-policies.sh` | Applies WAF managed rules in preview mode across all CA policies | Safe rollout of WAF protection without blocking live traffic |
| `enable-adaptive-protection.sh` | Enables Layer 7 DDoS Adaptive Protection across all policies | Automated DDoS defence enablement at scale |
| `auto-investigate-429.py` | Auto-investigates 429 HTTP throttle events from SCC logs | Cuts incident triage time from hours to minutes |
| `analyze-429-logs.py` | Correlates Cloud Logging 429 events with Cloud Armor rule hits | Pinpoints offending IPs and target endpoints |
| `collect-policy-metadata.py` | Inventories all CA policy metadata (rules, priorities, actions) | Single-pane-of-glass CA policy compliance view |
| `gcp-security-audit.py` | Audits CA policies for WAF rule ordering issues and preview vs. enforce mismatches | Catches misconfigured rules before they cause incidents |
| `multi-project-ca-scanner.sh` | Scans CA policies and rules across multiple projects in one run | Eliminates manual per-project checks |
| `audit-preview-metrics.py` | Queries Cloud Monitoring for preview rule hit counts over time | Quantifies traffic impact before enforcing a rule |
| `gmail-alert-scraper.py` | Scrapes 4xx alert emails from Gmail into a structured CSV | Builds a historical timeline of CA alert events |
| `open-gcp-log-links.py` | Generates direct deep-links to GCP Log Explorer for CA findings | Speeds up log investigation during incidents |
| `log-hit-counter.py` | Counts rule hits from raw Cloud Logging exports | Offline analysis of rule effectiveness |
| `monitoring-hit-counter.py` | Queries Monitoring API for 30-day preview rule hit totals | Helps decision-making on whether to enforce a rule |
| `links-template.json` | Reusable Cloud Logging query templates for CA investigation | Standardises how the team investigates CA events |

### Security Command Center (SCC)
| Tool | What It Does | Business Impact |
|------|-------------|-----------------|
| `analyze-scc-findings.py` | Parses exported SCC findings CSV, groups by project and category | Quick hotspot identification across all projects |
| `auto-analyze-scc-threats.py` | Correlates SCC threats with Cloud Logging and WHOIS data for offending IPs | Automated threat investigation reports |
| `bulk-inactivate-findings.sh` | Bulk-updates SCC findings to INACTIVE state from a text file | Saves hours of manual finding management |
| `flatten-scc-findings.py` | Flattens SCC JSON exports into wide CSV | Makes bulk SCC data usable in Google Sheets |

### IAM
| Tool | What It Does | Business Impact |
|------|-------------|-----------------|
| `iam-audit-report.py` | Maps service account roles vs. actual 90-day usage via Recommender API | Identifies over-privileged service accounts |
| `process-bindings-csv.py` | Merges IAM Recommender output with raw bindings data | Actionable REVOKE/REPLACE recommendations per principal |
| `format-raw-bindings.py` | Structures raw `gcloud get-iam-policy` output | Preprocessing for Sheets import |
| `summarize-bindings-by-project.py` | Summarises IAM role counts per project | Governance-level view of IAM posture |

### Alerting (Real-time)
| Tool | What It Does | Business Impact |
|------|-------------|-----------------|
| `scc-alert-handler.py` | Cloud Function: forwards CRITICAL SCC findings to Google Chat via webhook | Zero-delay security alert delivery to the team |

### Google Sheets Utilities
| Tool | What It Does | Business Impact |
|------|-------------|-----------------|
| `cloud-armor-processor.js` | Apps Script to process raw Cloud Armor CSV into a formatted analysis sheet | One-click report generation inside Google Sheets |
| `custom-secops-tools.js` | Apps Script with IP geolocation, JSON extractors, and advanced IP Kundli (RIPEstat + AbuseIPDB) | Enriches security data without leaving Google Sheets |
| `sync-reports-to-slides.js` | Apps Script that syncs Sheet data into a Google Slides report template | Automated slide deck generation for client reporting |
| `scc-pivot-tables.js` / `dialog.html` | Apps Script + dialog UI to generate side-by-side pivot tables from raw and filtered SCC findings | One-click vulnerability and findings distribution report |

---

## PICKME
*Compute Engine and network security audits across a multi-project ride-sharing platform environment.*

### Compute / VM Security
| Tool | What It Does | Business Impact |
|------|-------------|-----------------|
| `vm-security-auditor.py` | Parallel audit of all VMs: public IPs, scopes, deletion protection, metadata | Baseline VM security posture across all projects |
| `audit-vm-security-profile.sh` | Audits Shielded VM, Secure Boot, vTPM, serial port, OS Config per VM | Detailed Shielded VM compliance check |
| `read-only-compute-audit.py` | Read-only VM inventory: machine type, disk, IP, service account | Safe initial baseline assessment |
| `compute-audit-apr2026.py` | Enhanced compute audit with improved Shielded VM and scope analysis | Most up-to-date VM audit tool |
| `vm-scope-auditor-multi.sh` | Scans multi-project service account API scopes | Identifies over-scoped VMs at scale |
| `vm-scope-auditor-single.sh` | Single-project scope audit | Quick per-project scope check |
| `list-api-scopes.sh` | Lightweight API scope lister per instance | Fast scope snapshot for triage |
| `gcp-compute-audit.sh` | Shell-based VM inventory (name, zone, machine type, IP, disk) | Quick multi-project snapshot |
| `serial-port-crawl.sh` | Identifies VMs with serial port access enabled | Flags low-level console access risk |
| `check_os_agents.sh` | Checks if OS Config agent is running on each VM | Validates patch management coverage |

### GKE
| Tool | What It Does | Business Impact |
|------|-------------|-----------------|
| `gke-upgrade-audit.py` | Audits GKE cluster versions, node pool auto-upgrade, upgrade history | Compliance tracking for GKE version currency |
| `list-gke-control-plane-ips.sh` | Lists all GKE control plane (master) public IPs | Firewall rule and IP allowlist management |
| `list-gke-node-ips.sh` | Lists all GKE worker node external IPs | Network exposure assessment |

### Networking
| Tool | What It Does | Business Impact |
|------|-------------|-----------------|
| `detect-default-networks.sh` | Detects default VPC networks and all resources attached to them | Identifies insecure default network exposure |
| `default-network-security-assessment.sh` | Simpler default network detector with resource counts | Quick initial assessment |
| `gcp-flow-logs-check.sh` | Checks VPC Flow Logs status per subnet | Validates logging coverage for forensics |
| `gcp-flow-logs-check-v2.sh` | Updated flow logs checker with enhanced output | Latest version for current assessments |
| `network-inventory.sh` | VPC network inventory with default network resource list | Full network topology snapshot |
| `list-lb-ips.sh` | Lists all Load Balancer frontend IPs | Public IP exposure inventory |
| `list-reserved-ips.sh` | Lists all reserved static external IPs with attachment status | Identifies orphaned/unused reserved IPs |
| `list-ssl-policies.sh` | Lists SSL policies across multiple projects | SSL/TLS version compliance check |
| `updated-ssl-policies.sh` | Enhanced SSL policy reporter with proxy mapping | Full TLS compliance picture |

### Storage
| Tool | What It Does | Business Impact |
|------|-------------|-----------------|
| `multi-project-storage-scanner.sh` | Scans GCS buckets for public access, uniform access, logging | Prevents data exposure via public buckets |

---

## NTUC
*Real-time alerting, IAM governance, and Workload Identity Federation for a large retail organisation.*

| Tool | What It Does | Business Impact |
|------|-------------|-----------------|
| `scc-alert-handler.py` | Cloud Function: SCC → Google Chat real-time alerts | Security team notified of CRITICAL findings instantly |
| `process-bindings-csv.py` | IAM Recommender CSV processor | Speeds up IAM hygiene remediation |
| `summarize-bindings-by-project.py` | Project-level IAM role count summary | Governance reporting for IAM reviews |
| `run-wif-k8s-poc.sh` | End-to-end Workload Identity Federation PoC on GKE | Eliminated service account key files from GKE workloads |
| `pam-entitlements-export.py` | Exports all PAM entitlements to CSV | Audit trail for privileged access grants |

---

## CardinalGroup
*VM license and OS compliance audit across a GCP organisation.*

| Tool | What It Does | Business Impact |
|------|-------------|-----------------|
| `audit-vm-os-licensing.sh` | Org-wide parallelised scan detecting Windows vs. Linux VMs using license metadata | Identifies all Windows Server VMs for licensing compliance |
| `audit-vm-security-profile.sh` | Shielded VM, serial port, and API scope audit | VM-level security hardening checklist |
| `list-api-keys.py` | Parallel API Keys inventory across projects | Discovers unrestricted or overly-permissive API keys |

---

## CxApp
*SCC findings export and governance.*

| Tool | What It Does | Business Impact |
|------|-------------|-----------------|
| `flatten-scc-findings.py` | Flattens nested SCC JSON exports to CSV | Makes bulk SCC data analysable in Google Sheets |
| `analyze-scc-findings.py` | Groups and counts findings by project and category | Hotspot identification for governance reviews |

---

## VITU
*Data pipeline utilities for threat intelligence and log processing.*

| Tool | What It Does | Business Impact |
|------|-------------|-----------------|
| `json-to-csv-flattener.py` | Recursively flattens any nested JSON (SCC, logs) to CSV | Enables Sheets-based analysis of complex nested data |
| `gcp-logs-json-to-csv.py` | Converts GCP Cloud Logging JSON exports to pipe-separated CSV | Simplifies log import into Google Sheets |

---

## ISM-Games
*Cloud security posture scanner deployed on Kubernetes using Prowler.*

| Tool | What It Does | Business Impact |
|------|-------------|-----------------|
| `01-setup-infra.sh` | Creates GKE cluster and reserves static IP for Prowler | Automated infra provisioning |
| `deploy-prowler-master.sh` | Deploys Prowler + Neo4j to GKE | Runs continuous cloud security scans on K8s |
| `check-health.sh` | Checks health and readiness of Prowler pods | Operational monitoring for the scanner |
| `all-in-one.sh` | Combined infra + deployment script | One-command full Prowler environment setup |
| `teardown.sh` | Status check and cluster cleanup | Safe decommissioning of the PoC |
| `gcp-security-scanner.py` | 50+ check GCP security scanner (SCC-compatible output) | Comprehensive resource-level security assessment |

---

## D-mart
*Automated weekly security reporting.*

| Tool | What It Does | Business Impact |
|------|-------------|-----------------|
| `ael-weekly-report` | Generates weekly AEL (Alert Event Log) security report | Automated recurring security digest for the client |

---

## Reusable / Multi-Client Tools

These tools are generic and can be applied across any GCP organisation or client.

| Tool | Domain | What It Does |
|------|--------|-------------|
| `mxtoolbox-blacklist-checker.py` | Network | Checks IP lists against email/spam blacklists via MXToolbox |
| `generate-firewall-report.py` | Network | Correlates firewall rules to actual VMs with public IPs |
| `disable-icmp-project.sh` | Network | Identifies and optionally disables ICMP-only firewall rules |
| `disable-icmp-organization.sh` | Network | Org-wide ICMP firewall rule audit and cleanup |
| `get-address-groups.sh` | Network | Lists all Cloud Armor address group definitions |
| `describe-ssl-policies.sh` | SSL/TLS | Full SSL policy inventory with min TLS version |
| `harden-ssl-policy.sh` | SSL/TLS | Enforces TLS 1.2 and removes weak ciphers |
| `map-ssl-policies-to-proxies.sh` | SSL/TLS | Maps SSL policies to their target HTTPS proxies |
| `asm-ingress-analyzer.py` | Ingress | Analyses ASM/Istio ingress gateway configurations |
| `gcp-urlmap-extractor.py` | Load Balancer | Extracts URL map routing rules for LB audit |
| `bucket-object-counter.py` | Storage | Counts objects per GCS bucket for lifecycle review |
| `list-iam-details.sh` | IAM | Quick IAM policy snapshot for any project/org/folder |
| `process-iam-recommendations.py` | IAM | Processes IAM Recommender API output for remediation |
| `export-alerts.py` | Alerting | Exports GCP Monitoring alert policies to CSV |
| `email-via-apps-script.py` | Utility | Sends automated emails via Apps Script using GCP ADC |
| `pam-entitlements-export.py` | PAM | Exports PAM entitlements across projects |
| `list-api-keys.py` | Security | Multi-project GCP API Keys inventory |
| `list-sql-instance-ips.sh` | SQL | Lists Cloud SQL instances with public/private IPs |
| `sql-instance-net-details.sh` | SQL | Detailed SQL network configuration (SSL, auth networks) |

---

## How These Tools Help — Key Themes

| Theme | Impact |
|-------|--------|
| **Automation at Scale** | Scripts run across dozens of projects in parallel — what used to take a week manually now runs in minutes |
| **Read-Only & Safe** | All audit scripts are non-destructive. No changes are made unless explicitly enabled |
| **Google Sheets Integration** | Apps Script tools and pipe-separated CSV outputs allow direct Sheets import for client-ready reports |
| **Sanitized & Reusable** | All scripts use `YOUR_PROJECT_ID` placeholders — ready to deploy for any new client |
| **SCC-Compatible Output** | Security scanner findings follow SCC field naming conventions for easy integration |
| **Real-Time Alerting** | Cloud Function + Pub/Sub architecture delivers SCC findings to Google Chat in seconds |
