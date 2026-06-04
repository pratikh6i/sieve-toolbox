#!/usr/bin/env python3
"""
Cloud Armor SCC Bulk Auto-Investigator (With Deep Traffic Insights)
========================================================================
Analyses Google Security Command Center (SCC) Cloud Armor threat findings
exported as CSV. For every finding still within GCP's 30-day log retention
window it:
  - Queries Cloud Logging for the exact 20-minute traffic window
  - Enriches the top offending IPs with WHOIS/RDAP (country + ISP)
  - Extracts targeted URLs, HTTP Methods, User-Agents, and Status Codes
  - Produces a CISO-grade written assessment of the incident
  - Outputs a clean, paste-ready CSV
"""

import os
import sys
import csv
import json
import re
import urllib.parse
import glob
import time
import logging as py_logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from collections import Counter, defaultdict

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
_missing = []
try:
    import pandas as pd
except ImportError:
    _missing.append("pandas")

try:
    from google.cloud import logging as gcp_logging
    from google.api_core.exceptions import GoogleAPICallError, PermissionDenied, NotFound
except ImportError:
    _missing.append("google-cloud-logging")

try:
    from ipwhois import IPWhois
    from ipwhois.exceptions import IPDefinedError
except ImportError:
    _missing.append("ipwhois")

if _missing:
    print(f"\nCRITICAL: Missing dependencies: {', '.join(_missing)}")
    print(f"   Run: pip install {' '.join(_missing)}\n")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

OUTPUT_CSV_FILENAME = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "scc-automated-report.csv"
)

LOG_RETENTION_DAYS    = 30
LOG_WINDOW_MINUTES    = 10     
MAX_LOG_LIMIT         = 5000   
TOP_N_IPS             = 3
TOP_N_RULES           = 3
TOP_N_URIS            = 5      # Number of top URLs to display per IP
TOP_N_AGENTS          = 3      # Number of top User-Agents to display per IP
WHOIS_TIMEOUT         = 8      
WHOIS_MAX_WORKERS     = 10     

RPS_NEGLIGIBLE = 20.0          
RPS_LOW        = 100.0
RPS_MEDIUM     = 500.0         

CLOUD_ASN_KEYWORDS = {
    "AMAZON", "AWS", "GOOGLE", "GOOGL",   
    "MICROSOFT", "AZURE", "DIGITALOCEAN",
    "LINODE", "AKAMAI", "CLOUDFLARE", "OVH", "VULTR", "HETZNER",
    "LEASEWEB", "CHOOPA", "COGENT", "ZAYO",
}

_PRIVATE_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|fc|fd|fe80)"
)


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
py_logging.basicConfig(
    level=py_logging.INFO,
    format="%(asctime)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = py_logging.getLogger("scc")


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def safe_str(value) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    return str(value).strip()

def extract_last_segment(resource_path: str) -> str:
    if not resource_path:
        return ""
    return resource_path.rstrip("/").split("/")[-1]

def parse_event_time(ts: str):
    if not ts:
        return None
    ts = ts.strip().rstrip("Z").replace(" ", "T")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(ts[: len(fmt) + 6], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None

def parse_source_properties(raw: str) -> dict:
    if not raw:
        return {}
    for candidate in (raw, raw.replace("'", '"')):
        try:
            data = json.loads(candidate)
            break
        except (json.JSONDecodeError, TypeError):
            continue
    else:
        return {}

    if isinstance(data, list):
        return {
            item["key"]: item.get("value")
            for item in data
            if isinstance(item, dict) and "key" in item
        }
    if isinstance(data, dict):
        return data
    return {}

def safe_float(value, default=None):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default

def is_private_ip(ip: str) -> bool:
    return bool(_PRIVATE_RE.match(ip))

def age_days(event_time: datetime) -> int:
    return (datetime.now(tz=timezone.utc) - event_time).days

def is_beyond_retention(event_time: datetime) -> bool:
    return age_days(event_time) >= LOG_RETENTION_DAYS

def is_cloud_asn(isp: str) -> bool:
    upper = isp.upper()
    return any(kw in upper for kw in CLOUD_ASN_KEYWORDS)


# ---------------------------------------------------------------------------
# URL builders
# ---------------------------------------------------------------------------

def build_log_explorer_url(project_id: str, backend: str, start: datetime, end: datetime) -> str:
    query = (
        'resource.type="http_load_balancer" '
        f'resource.labels.backend_service_name="{backend}"'
    )
    t_fmt = "%Y-%m-%dT%H:%M:%SZ"
    return (
        "https://console.cloud.google.com/logs/query"
        f";query={urllib.parse.quote(query)}"
        f";timeRange={start.strftime(t_fmt)}/{end.strftime(t_fmt)}"
        f"?project={project_id}"
    )

def build_adaptive_protection_url(project_id: str, org_id: str) -> str:
    base = "https://console.cloud.google.com/net-security/securitypolicies/adaptiveprotection"
    if org_id:
        params = f"referrer=search&organizationId={org_id}&project={project_id}"
    else:
        params = f"referrer=search&project={project_id}"
    return f"{base}?{params}"


# ---------------------------------------------------------------------------
# WHOIS enrichment
# ---------------------------------------------------------------------------

_WHOIS_CACHE: dict = {}

def whois_lookup(ip: str) -> dict:
    if ip in _WHOIS_CACHE:
        return _WHOIS_CACHE[ip]

    if is_private_ip(ip):
        result = {"country": "Private", "isp": "Private/Internal"}
        _WHOIS_CACHE[ip] = result
        return result

    for attempt in range(2):
        try:
            res = IPWhois(ip, timeout=WHOIS_TIMEOUT).lookup_rdap(depth=1)
            result = {
                "country": res.get("asn_country_code") or "Unknown",
                "isp":     (res.get("network") or {}).get("name") or "Unknown",
            }
            _WHOIS_CACHE[ip] = result
            return result
        except IPDefinedError:
            result = {"country": "Reserved", "isp": "Reserved Range"}
            _WHOIS_CACHE[ip] = result
            return result
        except Exception as exc:
            if attempt == 0:
                time.sleep(0.5)
            else:
                log.debug(f"WHOIS failed for {ip}: {exc}")

    result = {"country": "Unknown", "isp": "Unknown"}
    _WHOIS_CACHE[ip] = result
    return result

def whois_bulk(ips: list) -> dict:
    uncached = [ip for ip in ips if ip not in _WHOIS_CACHE]
    if uncached:
        workers = min(WHOIS_MAX_WORKERS, len(uncached))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(whois_lookup, ip): ip for ip in uncached}
            for future in as_completed(futures):
                try:
                    future.result() 
                except Exception:
                    pass
    return {
        ip: _WHOIS_CACHE.get(ip, {"country": "Unknown", "isp": "Unknown"})
        for ip in ips
    }


# ---------------------------------------------------------------------------
# Log analysis - DEEP TRAFFIC EXTRACTION
# ---------------------------------------------------------------------------

def analyze_logs(logs: list) -> dict:
    """
    Aggregate detailed per-IP stats from raw GCP Cloud Logging entries.
    Extracts URLs, Methods, User-Agents, and Status Codes.
    """
    data = defaultdict(lambda: {
        "total": 0, "accepted": 0, "denied": 0,
        "rules": Counter(), 
        "uris": Counter(), 
        "methods": Counter(),
        "user_agents": Counter(),
        "status_codes": Counter()
    })

    for entry in logs:
        try:
            payload = {}
            if hasattr(entry, "payload") and isinstance(entry.payload, dict):
                payload = entry.payload
            elif hasattr(entry, "struct_payload") and entry.struct_payload:
                payload = entry.struct_payload

            http_req = getattr(entry, "http_request", None) or {}
            if hasattr(http_req, "_pb"):
                from google.protobuf.json_format import MessageToDict
                http_req = MessageToDict(http_req._pb)

            ip = (
                payload.get("remoteIp")
                or payload.get("remote_ip")
                or (http_req.get("remoteIp") if isinstance(http_req, dict) else None)
            )
            if not ip or not isinstance(ip, str):
                continue
            ip = ip.split(":")[0]  # strip port

            data[ip]["total"] += 1

            # HTTP Request specifics extraction
            status = None
            if isinstance(http_req, dict):
                status = http_req.get("status") or http_req.get("responseCode")
                
                # Extract URL (stripping query parameters for clean grouping)
                uri = http_req.get("requestUrl") or http_req.get("request_url")
                if uri and isinstance(uri, str):
                    clean_uri = uri.split("?")[0][:200]
                    data[ip]["uris"][clean_uri] += 1
                
                # Extract HTTP Method (GET, POST, etc.)
                method = http_req.get("requestMethod")
                if method:
                    data[ip]["methods"][str(method)] += 1
                    
                # Extract User-Agent
                user_agent = http_req.get("userAgent")
                if user_agent:
                    # Truncate extremely long user agents for readability
                    clean_ua = str(user_agent)[:150]
                    data[ip]["user_agents"][clean_ua] += 1
            
            # Status code counting and accept/deny grouping
            if status is not None:
                try:
                    status_code = int(status)
                    data[ip]["status_codes"][str(status_code)] += 1
                    
                    if 200 <= status_code < 300:
                        data[ip]["accepted"] += 1
                    else:
                        data[ip]["denied"] += 1
                except (TypeError, ValueError):
                    pass

            # Cloud Armor Rule Extraction
            policy_data = payload.get("enforcedSecurityPolicy", {})
            if isinstance(policy_data, dict):
                rule = policy_data.get("priority") or policy_data.get("name")
                if rule is not None:
                    data[ip]["rules"][str(rule)] += 1

        except Exception as exc:
            log.debug(f"Log parse error: {exc}")

    return data


# ---------------------------------------------------------------------------
# CISO-grade analytical conclusion builder
# ---------------------------------------------------------------------------

def build_conclusion(
    alert_type:     str,
    peak_rps,
    baseline_rps,
    logs_count:     int,
    logs_expired:   bool,
    top_ips_data:   dict,   
    rules_agg:      Counter,
    deny_ratio_pct: float,
) -> str:
    NL    = chr(10)
    peak  = safe_float(peak_rps)
    base  = safe_float(baseline_rps)
    lines = []

    if logs_expired:
        if peak is not None and peak < RPS_NEGLIGIBLE:
            lines.append("ASSESSMENT: Likely False Positive — Metadata Only")
            lines.append(f"Peak RPS reported by SCC was {peak:.1f}, which is well below the {RPS_NEGLIGIBLE:.0f} RPS threshold.")
        else:
            lines.append("ASSESSMENT: Indeterminate — Logs Outside Retention Window")
            lines.append(f"Finding older than {LOG_RETENTION_DAYS} days. Logs purged by GCP.")
        return NL.join(lines)

    if logs_count == 0:
        lines.append("ASSESSMENT: Inconclusive — No Log Data Retrieved")
        lines.append("Verify IAM roles (roles/logging.viewer) or check if spike was too transient.")
        return NL.join(lines)

    if peak is None: severity_label = "UNDETERMINED"
    elif peak < RPS_NEGLIGIBLE: severity_label = "LOW — Likely False Positive"
    elif peak < RPS_LOW: severity_label = "LOW"
    elif peak < RPS_MEDIUM: severity_label = "MEDIUM"
    else: severity_label = "HIGH"

    cloud_count   = 0
    country_list  = []
    all_blocked   = True    

    for ip_data in top_ips_data.values():
        country = ip_data.get("country", "Unknown")
        isp     = ip_data.get("isp", "Unknown")
        if country not in ("Unknown", "Private", "Reserved"): country_list.append(country)
        if is_cloud_asn(isp): cloud_count += 1
        if ip_data.get("accepted", 0) > 0: all_blocked = False

    unique_countries = list(dict.fromkeys(country_list))
    cloud_pct        = (cloud_count / len(top_ips_data) * 100) if top_ips_data else 0.0

    if deny_ratio_pct >= 90: deny_narrative = f"Cloud Armor denied {deny_ratio_pct:.0f}% of observed traffic — policy effective."
    elif deny_ratio_pct >= 50: deny_narrative = f"{deny_ratio_pct:.0f}% denied. Evaluate thresholds; significant traffic reached backend."
    elif deny_ratio_pct > 0: deny_narrative = f"Only {deny_ratio_pct:.0f}% denied. Majority allowed. Investigate policy gaps."
    else: deny_narrative = "No requests blocked. Verify if legitimate traffic spike."

    rule_notes = []
    for rule_id, hits in rules_agg.most_common(TOP_N_RULES):
        rid = str(rule_id).split(".")[0]
        if rid == "2147483647": rule_notes.append(f"Rule 2147483647 ({hits} hits): Default-deny triggered.")
        else: rule_notes.append(f"Rule {rid} ({hits} hits): Custom rule matched.")

    lines.append(f"SEVERITY: {severity_label}")
    lines.append(f"ALERT TYPE: {alert_type}")

    if peak is not None:
        rps_context = f"  ({(peak/base):.1f}x baseline)" if base is not None and base > 0 else ""
        lines.append(f"TRAFFIC VOLUME: Peak {peak:.1f} RPS{rps_context} | {logs_count:,} logs analysed.")

    lines.append(f"DENY RATIO: {deny_narrative}")

    if top_ips_data:
        geo_str = ", ".join(unique_countries) if unique_countries else "Unknown origin"
        lines.append(f"ATTACKER PROFILE: {len(top_ips_data)} source IPs across {len(unique_countries)} region(s) [{geo_str}].")
        if cloud_pct >= 66: lines.append("Highly automated profile (Cloud/Hosting ASNs).")
        elif cloud_pct > 0: lines.append("Mixed profile (Cloud & Residential).")
        else: lines.append("Residential ISPs observed - monitor for targeted probing.")

    if rule_notes:
        lines.append("RULE ANALYSIS:")
        lines.extend(f"  - {note}" for note in rule_notes)

    if "Increasing Deny Ratio" in alert_type: lines.append("RECOMMENDATION: Policy effective. Monitor for escalation.")
    elif "Potential Layer 7 DDoS" in alert_type: lines.append("RECOMMENDATION: ESCALATE. Review ML WAF rule suggestions immediately.")
    else: lines.append("RECOMMENDATION: Review full findings and Adaptive Protection dashboard.")

    return NL.join(lines)


def _build_log_filter(backend: str, start: datetime, end: datetime) -> str:
    return (
        'resource.type="http_load_balancer" '
        f'resource.labels.backend_service_name="{backend}" '
        f'timestamp >= "{start.isoformat()}" '
        f'AND timestamp <= "{end.isoformat()}"'
    )


# ---------------------------------------------------------------------------
# Main analyser
# ---------------------------------------------------------------------------

class SCCBulkAnalyzer:
    def __init__(self):
        print("\nCloud Armor SCC Bulk Auto-Investigator")
        print("=" * 65)
        self.csv_file     = self._find_latest_csv()
        self._gcp_clients: dict = {}

    def _find_latest_csv(self) -> str:
        candidates = [f for f in glob.glob("*.csv") if os.path.abspath(f) != OUTPUT_CSV_FILENAME]
        if not candidates:
            log.error("No input CSV files found.")
            sys.exit(1)
        return max(candidates, key=os.path.getmtime)

    @staticmethod
    def _verify_gcp_auth():
        try:
            import google.auth
            import google.auth.transport.requests
            credentials, project = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            credentials.refresh(google.auth.transport.requests.Request())
            log.info(f"GCP auth OK  (project hint: {project or 'not set'})")
        except Exception as exc:
            print("\nGCP AUTH FAILED. Run: gcloud auth application-default login\n")
            sys.exit(1)

    def _get_gcp_client(self, project_id: str):
        if project_id not in self._gcp_clients:
            try:
                self._gcp_clients[project_id] = gcp_logging.Client(project=project_id)
            except Exception:
                self._gcp_clients[project_id] = None
        return self._gcp_clients[project_id]

    def _fetch_logs(self, project_id: str, backend: str, start: datetime, end: datetime) -> list:
        client = self._get_gcp_client(project_id)
        if client is None: return []
        try:
            return list(client.list_entries(
                filter_=_build_log_filter(backend, start, end),
                page_size=1000,
                max_results=MAX_LOG_LIMIT,
                order_by=gcp_logging.DESCENDING,
            ))
        except Exception as exc:
            log.warning(f"  Fetch error - {project_id}/{backend}: {exc}")
        return []

    def run(self):
        self._verify_gcp_auth()

        try:
            df = pd.read_csv(self.csv_file, dtype=str, keep_default_na=False)
        except Exception as exc:
            sys.exit(1)

        log.info(f"Loaded {len(df)} rows.")

        active_rows, expired_rows, invalid_rows = [], [], []

        for idx, row in df.iterrows():
            project_id = safe_str(row.get("resource.gcp_metadata.parent_display_name")) or extract_last_segment(safe_str(row.get("resource.gcp_metadata.project")))
            backend = safe_str(row.get("resource.display_name"))
            if not project_id or not backend:
                invalid_rows.append(idx)
                continue

            et = parse_event_time(safe_str(row.get("finding.event_time")))
            if et is None:
                invalid_rows.append(idx)
                continue

            if is_beyond_retention(et): expired_rows.append((idx, et))
            else: active_rows.append((idx, et))

        written = 0

        with open(OUTPUT_CSV_FILENAME, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            # UPDATED HEADER for new fields
            writer.writerow([
                "Event Time (UTC)", "Project Name", "Affected Service", "Alert Type",
                "Severity", "Baseline RPS", "Peak RPS", "Deny Ratio", "Security Policy",
                "Top IPs (Profile & Volume)", 
                "IP Targets (Top URLs & HTTP Methods)", 
                "IP User-Agents", 
                "IP Response Codes",
                "Top Triggered Rules",
                "Security Assessment", "Log Explorer Link", "Adaptive Protection Dashboard"
            ])

            # Process Active Rows
            for counter, (idx, event_time) in enumerate(active_rows, start=1):
                row        = df.loc[idx]
                project_id = safe_str(row.get("resource.gcp_metadata.parent_display_name")) or extract_last_segment(safe_str(row.get("resource.gcp_metadata.project")))
                backend    = safe_str(row.get("resource.display_name"))
                alert_type = safe_str(row.get("finding.category"))
                props      = parse_source_properties(safe_str(row.get("finding.source_properties")))
                org_id     = extract_last_segment(safe_str(row.get("resource.gcp_metadata.organization")))

                baseline_rps = props.get("Long_Term_Allowed_RPS") or props.get("Long_Term_Incoming_RPS") or "N/A"
                peak_rps     = props.get("Short_Term_Allowed_RPS") or props.get("Short_Term_Incoming_RPS") or props.get("Long_Term_Denied_RPS") or "N/A"
                policy_name  = props.get("Security_Policy") or "N/A"
                
                start_w = event_time - timedelta(minutes=LOG_WINDOW_MINUTES)
                end_w   = event_time + timedelta(minutes=LOG_WINDOW_MINUTES)

                log.info(f"[{counter}/{len(active_rows)}] Analyzing: {backend} ...")
                logs = self._fetch_logs(project_id, backend, start_w, end_w)
                analysis = analyze_logs(logs)
                
                top_ips = dict(sorted(analysis.items(), key=lambda x: x[1]["total"], reverse=True)[:TOP_N_IPS])
                geo_map = whois_bulk(list(top_ips.keys())) if top_ips else {}

                rules_agg = Counter()
                
                # Formatted strings for the CSV
                NL = chr(10)
                ip_profile_lines = []
                ip_target_lines = []
                ip_ua_lines = []
                ip_status_lines = []
                enriched_ips = {}

                for ip, stats in top_ips.items():
                    geo = geo_map.get(ip, {"country": "Unknown", "isp": "Unknown"})
                    
                    # 1. IP Profile & Volume
                    ip_profile_lines.append(f"• {ip} ({geo['country']} | {geo['isp']}) [{stats['total']} reqs]")
                    
                    # 2. IP Targets (URLs and Methods)
                    top_urls = ", ".join([f"{u} ({c})" for u, c in stats["uris"].most_common(TOP_N_URIS)])
                    top_methods = ", ".join([f"{m} ({c})" for m, c in stats["methods"].most_common(3)])
                    ip_target_lines.append(f"• {ip} -> Methods: [{top_methods}] | URLs: {top_urls}")
                    
                    # 3. IP User Agents
                    top_uas = ", ".join([f"{ua} ({c})" for ua, c in stats["user_agents"].most_common(TOP_N_AGENTS)])
                    ip_ua_lines.append(f"• {ip} -> UAs: {top_uas}")
                    
                    # 4. IP Status Codes
                    top_statuses = ", ".join([f"HTTP {s} ({c})" for s, c in stats["status_codes"].most_common(5)])
                    ip_status_lines.append(f"• {ip} -> Status: {top_statuses}")

                    rules_agg.update(stats["rules"])
                    enriched_ips[ip] = {**stats, **geo}

                all_total  = sum(s["total"] for s in analysis.values())
                all_denied = sum(s["denied"] for s in analysis.values())
                deny_ratio = (all_denied / all_total * 100) if all_total > 0 else 0.0

                peak = safe_float(peak_rps)
                severity = "UNDETERMINED" if peak is None else "LOW" if peak < RPS_LOW else "MEDIUM" if peak < RPS_MEDIUM else "HIGH"

                rules_str = NL.join(f"Rule {k} ({v} hits)" for k, v in rules_agg.most_common(TOP_N_RULES)) or "N/A"

                assessment = build_conclusion(alert_type, peak_rps, baseline_rps, len(logs), False, enriched_ips, rules_agg, deny_ratio)

                writer.writerow([
                    event_time.strftime("%Y-%m-%d %H:%M:%S UTC"), project_id, backend, alert_type,
                    severity, baseline_rps, peak_rps, f"{deny_ratio:.1f}%", policy_name,
                    NL.join(ip_profile_lines) if ip_profile_lines else "N/A",
                    NL.join(ip_target_lines) if ip_target_lines else "N/A",
                    NL.join(ip_ua_lines) if ip_ua_lines else "N/A",
                    NL.join(ip_status_lines) if ip_status_lines else "N/A",
                    rules_str, assessment,
                    build_log_explorer_url(project_id, backend, start_w, end_w),
                    build_adaptive_protection_url(project_id, org_id)
                ])
                written += 1

        print("=" * 65)
        log.info(f"Complete. {written} findings written to {OUTPUT_CSV_FILENAME}")

if __name__ == "__main__":
    SCCBulkAnalyzer().run()
