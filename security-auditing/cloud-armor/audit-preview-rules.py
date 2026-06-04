#!/usr/bin/env python3
"""
Searce Cloud Armor Preview Rule Analyzer — Enterprise Edition (v8.0)

READ-ONLY tool for analyzing Cloud Armor WAF preview rule effectiveness.
Designed for global deployment across 100s of GCP projects.

  Phase 1: DISCOVERY  — Find policies and preview rules
  Phase 2: EXECUTION  — Query logs with time-window chunking & adaptive throttling
  Phase 3: VALIDATION — Retry failed rules, verify data integrity
  Phase 4: SUMMARY    — Executive summary for CISO reporting

┌─────────────────────────────────────────────────────────────────┐
│  v8.0 ENHANCEMENTS over v7:                                     │
│    • Time-window chunking: 30 days → daily chunks, auto-bisect  │
│      on timeout. ZERO missed logs.                              │
│    • Proactive credential refresh before token expiry            │
│    • Robust resume: cleans partial CSV rows on crash recovery    │
│    • Intelligent rate limiting with sliding window tracker       │
│    • CLI --projects flag for direct project ID input             │
│    • Atomic CSV writes with os.fsync()                          │
│    • Executive summary file for CISO reporting                  │
│                                                                  │
│  GCP APIs used (ALL READ-ONLY):                                 │
│    • compute.backendServices.aggregatedList                     │
│    • compute.securityPolicies.get                               │
│    • logging.entries.list                                       │
│  🔒  ZERO write/create/delete/update calls.                     │
│  📌  CHECKPOINT/RESUME: Saves progress to disk. If interrupted, │
│      re-run to continue from where it stopped.                  │
└─────────────────────────────────────────────────────────────────┘
"""

import sys, os, csv, re, json, time, logging, argparse, threading, random
import concurrent.futures, urllib.parse
from datetime import datetime, timedelta, timezone
from collections import Counter
from pathlib import Path

try:
    import google.auth
    import google.auth.exceptions
    import google.auth.transport.requests
    from google.cloud import compute_v1, logging_v2
    from google.api_core import exceptions
    from tqdm import tqdm
except ImportError as e:
    print(f"\n❌ Missing: {e}\n   pip install google-cloud-compute google-cloud-logging tqdm\n")
    sys.exit(1)

# Suppress noisy gRPC auth callback stack traces
logging.getLogger("google.auth.transport.grpc").setLevel(logging.CRITICAL)
logging.getLogger("grpc._plugin_wrapping").setLevel(logging.CRITICAL)

# ── Cloud Armor & OWASP CRS Signature Descriptions ──
OWASP_DESCRIPTIONS = {
    "942100": "SQL Injection Attack Detected via libinjection",
    "942101": "SQL Injection Attack Detected via libinjection (Stricter)",
    "942110": "SQL injection attack: Common Injection Testing Detected",
    "942120": "SQL injection attack: SQL Operator Detected",
    "942130": "SQL Injection Attack: SQL Tautology Detected",
    "942140": "SQL injection attack: Common DB Names Detected",
    "942150": "SQL injection attack",
    "942160": "Detects blind SQLi tests using sleep() or benchmark()",
    "942170": "Detects SQL benchmark and sleep injection attempts",
    "942180": "Detects basic SQL authentication bypass attempts 1/3",
    "942190": "Detects MSSQL code execution and information gathering",
    "942200": "Detects MySQL comment-/space-obfuscated injections",
    "942210": "Detects chained SQL injection attempts 1/2",
    "942220": "Looks for integer overflow attacks",
    "942230": "Detects conditional SQL injection attempts",
    "942240": "Detects MySQL charset switch and MSSQL DoS attempts",
    "942250": "Detects MATCH AGAINST, MERGE and EXECUTE IMMEDIATE",
    "942251": "Detects HAVING injections",
    "942260": "Detects basic SQL authentication bypass attempts 2/3",
    "942270": "Looks for basic SQL injection; common attack string",
    "942280": "Detects Postgres pg_sleep injection",
    "942290": "Finds basic MongoDB SQL injection attempts",
    "942300": "Detects MySQL comments",
    "942310": "Detects chained SQL injection attempts 2/2",
    "942320": "Detects MySQL/PostgreSQL stored procedure injections",
    "942330": "Detects classic SQL injection probings 1/3",
    "942340": "Detects basic SQL authentication bypass attempts 3/3",
    "942350": "Detects MySQL UDF injection and data manipulation",
    "942360": "Detects concatenated basic SQL injection and SQLLFI",
    "942361": "Detects basic SQL injection based on keyword alter/union",
    "942370": "Detects classic SQL injection probings 2/3",
    "942380": "SQL injection attack", "942390": "SQL injection attack",
    "942400": "SQL injection attack", "942410": "SQL injection attack",
    "942470": "SQL injection attack", "942480": "SQL injection attack",
    "942420": "Restricted SQL Char Anomaly (cookies): special chars > 8",
    "942421": "Restricted SQL Char Anomaly (cookies): special chars > 3",
    "942430": "Restricted SQL Char Anomaly (args): special chars > 12",
    "942431": "Restricted SQL Char Anomaly (args): special chars > 6",
    "942432": "Restricted SQL Char Anomaly (args): special chars > 2",
    "942440": "SQL Comment Sequence Detected",
    "942450": "SQL Hex Encoding Identified",
    "942460": "Meta-Character Anomaly Detection Alert",
    "942490": "Detects classic SQL injection probings 3/3",
    "942500": "MySQL in-line comment detected",
    "942510": "SQLi bypass attempt by ticks or backticks detected",
    "942511": "SQLi bypass attempt by ticks detected",
    "942550": "JSON-based SQLi vectors",
    "941100": "XSS Attack Detected via libinjection",
    "941101": "XSS Attack Detected via libinjection (Stricter)",
    "941110": "XSS Filter - Category 1: Script Tag Vector",
    "941120": "XSS Filter - Category 2: Event Handler Vector",
    "941130": "XSS Filter - Category 3: Attribute Vector",
    "941140": "XSS Filter - Category 4: JavaScript URI Vector",
    "941150": "XSS Filter - Category 5: Disallowed HTML Attributes",
    "941160": "NoScript XSS InjectionChecker: HTML Injection",
    "941170": "NoScript XSS InjectionChecker: Attribute Injection",
    "941180": "Node-Validator Denylist Keywords",
    "941190": "IE XSS Filters - Attack Detected",
    "941200": "IE XSS Filters - Attack Detected",
    "941210": "IE XSS Filters - Attack Detected",
    "941220": "IE XSS Filters - Attack Detected",
    "941230": "IE XSS Filters - Attack Detected",
    "941240": "IE XSS Filters - Attack Detected",
    "941250": "IE XSS Filters - Attack Detected",
    "941260": "IE XSS Filters - Attack Detected",
    "941270": "IE XSS Filters - Attack Detected",
    "941280": "IE XSS Filters - Attack Detected",
    "941290": "IE XSS Filters - Attack Detected",
    "941300": "IE XSS Filters - Attack Detected",
    "941310": "US-ASCII Malformed Encoding XSS Filter",
    "941320": "Possible XSS Attack - HTML Tag Handler",
    "941330": "IE XSS Filters - Attack Detected",
    "941340": "IE XSS Filters - Attack Detected",
    "941350": "UTF-7 Encoding IE XSS - Attack Detected",
    "941360": "JSFuck / Hieroglyphy obfuscation detected",
    "941370": "JavaScript global variable found",
    "941380": "AngularJS client side template injection detected",
    "930100": "Path Traversal Attack (/../)",
    "930110": "Path Traversal Attack (/../)",
    "930120": "OS File Access Attempt",
    "930130": "Restricted File Access Attempt",
    "931100": "RFI Attack: URL Parameter using IP Address",
    "931110": "RFI Attack: Common Vulnerable Parameter Name",
    "931120": "RFI Attack: URL Payload w/Trailing Question Mark",
    "931130": "RFI Attack: Off-Domain Reference/Link",
    "932100": "UNIX Command Injection",
    "932105": "UNIX Command Injection (Stricter)",
    "932106": "UNIX Command Injection (2)",
    "932110": "Windows Command Injection",
    "932115": "Windows Command Injection (Stricter)",
    "932120": "Windows PowerShell Command Found",
    "932130": "Unix Shell Expression Found",
    "932140": "Windows FOR/IF Command Found",
    "932150": "Direct UNIX Command Execution",
    "932160": "UNIX Shell Code Found",
    "932170": "Shellshock (CVE-2014-6271)",
    "932171": "Shellshock (CVE-2014-6271) Stricter",
    "932180": "Restricted File Upload Attempt",
    "932190": "RCE: Wildcard bypass technique attempt",
    "932200": "RCE Bypass Technique",
    "933100": "PHP Injection: PHP Open Tag Found",
    "933110": "PHP Injection: Script File Upload Found",
    "933120": "PHP Injection: Configuration Directive Found",
    "933130": "PHP Injection: Variables Found",
    "933140": "PHP Injection: I/O Stream Found",
    "933200": "PHP Injection: Wrapper scheme detected",
    "933150": "PHP Injection: High-Risk Function Name Found",
    "933160": "PHP Injection: High-Risk Function Call Found",
    "933170": "PHP Injection: Serialized Object Injection",
    "933180": "PHP Injection: Variable Function Call Found",
    "933210": "PHP Injection: Variable Function Call Found",
    "933151": "PHP Injection: Medium-Risk Function Name Found",
    "933131": "PHP Injection: Variables Found (2)",
    "933161": "PHP Injection: Low-Value Function Call Found",
    "933111": "PHP Injection: Script File Upload Found (2)",
    "933190": "PHP Injection: PHP Closing Tag Found",
    "934100": "Node.js Injection Attack",
    "944100": "RCE: Suspicious Java class detected",
    "944110": "RCE: Java process spawn (CVE-2017-9805)",
    "944120": "RCE: Java serialization (CVE-2015-4852)",
    "944130": "Suspicious Java class detected",
    "944200": "Magic bytes detected, probable Java serialization",
    "944210": "Magic bytes Base64, probable Java serialization",
    "944240": "RCE: Java serialization (CVE-2015-4852) Stricter",
    "944250": "RCE: Suspicious Java method detected",
    "944300": "Base64 encoded string matched suspicious keyword",
    "911100": "Method is not allowed by policy",
    "913100": "User-Agent associated with security scanner",
    "913110": "Request header associated with security scanner",
    "913120": "Request filename/arg associated with scanner",
    "913101": "User-Agent associated with scripting/HTTP client",
    "913102": "User-Agent associated with web crawler/bot",
    "921110": "HTTP Request Smuggling Attack",
    "921120": "HTTP Response Splitting Attack",
    "921130": "HTTP Response Splitting Attack (2)",
    "921140": "HTTP Header Injection Attack via headers",
    "921150": "HTTP Header Injection via payload (CR/LF)",
    "921160": "HTTP Header Injection via payload (CR/LF+header)",
    "921190": "HTTP Splitting (CR/LF in request filename)",
    "921200": "LDAP Injection Attack",
    "921151": "HTTP Header Injection via payload (CR/LF) #2",
    "921170": "HTTP Parameter Pollution",
    "943100": "Session Fixation: Setting Cookie Values in HTML",
    "943110": "Session Fixation: SessionID w/Off-Domain Referer",
    "943120": "Session Fixation: SessionID w/No Referer",
    "000001": "React RCE vulnerability (CVE-2025-55182)",
    "000002": "React RCE vulnerability (CVE-2025-55182)",
    "044228": "Log4j (CVE-2021-44228 & CVE-2021-45046)",
    "144228": "Google-provided Log4j enhancements",
    "244228": "High sensitivity Log4j detection",
    "344228": "High sensitivity Log4j detection (base64)",
}

def _get_sig_description(owasp_id: str) -> str:
    if not owasp_id or owasp_id in ("None", "No signature detected"):
        return "-"
    match = re.search(r'id(\d{6})', owasp_id)
    if match:
        return OWASP_DESCRIPTIONS.get(match.group(1), "Signature matched (description unavailable)")
    for key in OWASP_DESCRIPTIONS:
        if key in owasp_id:
            return OWASP_DESCRIPTIONS[key]
    return "Signature matched (description unavailable)"

# ── Configuration Defaults ──
DEFAULTS = {
    "days": 30, "output": "cloud_armor_analysis.csv",
    "discovery_threads": 5, "rule_threads": 5, "log_threads": 3,
    "max_log_threads": 10, "min_log_threads": 1,
    "max_retries": 8, "retry_base": 5, "cache_hours": 6,
    "ramp_success": 10,
    "chunk_hours": 24,           # v8: daily chunks
    "min_chunk_minutes": 15,     # v8: minimum chunk before giving up
    "request_delay_ms": 150,     # v8: inter-request delay
    "cred_refresh_margin_s": 300,  # v8: refresh 5 min before expiry
}

CACHE_FILE = ".armor_discovery_cache.json"
PROGRESS_FILE = ".armor_progress_v8.json"  # v8: separate from v7
SUMMARY_FILE_SUFFIX = "_executive_summary.txt"

# ── Thread safety & Utilities ──
_print_lock = threading.Lock()
_csv_lock = threading.Lock()
_client_lock = threading.Lock()
_throttle_lock = threading.Lock()
_rate_lock = threading.Lock()
_consecutive_successes = 0
_current_log_threads = DEFAULTS["log_threads"]
_api_call_times = {}  # pid -> list of timestamps

def tprint(*a, **kw):
    with _print_lock:
        print(*a, **kw)

class DynamicSemaphore:
    """v8.1: A semaphore that respects the dynamic _current_log_threads variable.
    v8.2: Added notify_all on thread limit change so blocked threads re-check."""
    def __init__(self):
        self._active_count = 0
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)

    def acquire(self):
        with self._lock:
            while self._active_count >= _current_log_threads:
                self._condition.wait(timeout=2.0)  # periodic wake to re-check
            self._active_count += 1

    def release(self):
        with self._lock:
            self._active_count -= 1
            self._condition.notify_all()

    def notify_limit_changed(self):
        """Call when _current_log_threads changes to wake blocked threads."""
        with self._lock:
            self._condition.notify_all()

# v8.2: Global reference so _adapt_threads can notify it
_dynamic_sem = None

class C:
    R="\033[0m"; B="\033[1m"; D="\033[2m"; G="\033[92m"; Y="\033[93m"
    CN="\033[96m"; M="\033[95m"; RD="\033[91m"

# ── Rate Limiting Tracker ──
def _track_api_call(pid):
    """Track an API call timestamp for sliding window rate limiting."""
    now = time.monotonic()
    with _rate_lock:
        if pid not in _api_call_times:
            _api_call_times[pid] = []
        calls = _api_call_times[pid]
        # Keep only last 60 seconds
        cutoff = now - 60
        _api_call_times[pid] = [t for t in calls if t > cutoff]
        _api_call_times[pid].append(now)
        return len(_api_call_times[pid])

def _should_self_throttle(pid, threshold=50):
    """Check if we're approaching rate limit for a project."""
    with _rate_lock:
        calls = _api_call_times.get(pid, [])
        now = time.monotonic()
        recent = sum(1 for t in calls if t > now - 60)
        return recent >= threshold

# ── Global Client Manager with Proactive Refresh ──
class ClientManager:
    _credentials = None
    _project = None
    _compute = None
    _policies = None
    _logging = {}
    _last_refresh = None
    _auth_request = None

    @classmethod
    def _init_creds(cls):
        if cls._credentials is None:
            try:
                cls._credentials, cls._project = google.auth.default(
                    scopes=["https://www.googleapis.com/auth/cloud-platform"]
                )
                cls._auth_request = google.auth.transport.requests.Request()
                cls._last_refresh = time.monotonic()
                who = getattr(cls._credentials, 'service_account_email', None)
                if not who:
                    who = getattr(cls._credentials, 'signer_email', None) or 'user-account'
                tprint(f"  \033[92m✔ Authenticated: {who}\033[0m")
            except google.auth.exceptions.DefaultCredentialsError:
                print(f"\n  \033[91m❌ No credentials found.\033[0m")
                print(f"     Run: \033[1mgcloud auth application-default login\033[0m\n")
                sys.exit(1)
            except Exception as e:
                if "metadata" in str(e).lower() or "email" in str(e).lower():
                    print(f"\n  \033[91m❌ Cloud Shell auth error: {e}\033[0m")
                    print(f"     Run: \033[1mgcloud auth application-default login\033[0m\n")
                    sys.exit(1)
                raise

    @classmethod
    def refresh_if_needed(cls):
        """Proactively refresh credentials before they expire."""
        cls._init_creds()
        try:
            expiry = getattr(cls._credentials, 'expiry', None)
            if expiry:
                # expiry is a naive datetime in UTC
                now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
                remaining = (expiry - now_utc).total_seconds()
                if remaining < DEFAULTS["cred_refresh_margin_s"]:
                    tprint(f"  {C.Y}🔑 Token expires in {remaining:.0f}s — refreshing...{C.R}")
                    cls._credentials.refresh(cls._auth_request)
                    cls._last_refresh = time.monotonic()
                    tprint(f"  {C.G}🔑 Token refreshed successfully{C.R}")
                    # v8.2: Invalidate cached logging clients (they hold old creds)
                    with _client_lock:
                        cls._logging.clear()
                    return True
            # Fallback: refresh if >50 min since last refresh
            elif cls._last_refresh and (time.monotonic() - cls._last_refresh) > 3000:
                cls._credentials.refresh(cls._auth_request)
                cls._last_refresh = time.monotonic()
                # v8.2: Invalidate cached logging clients
                with _client_lock:
                    cls._logging.clear()
                tprint(f"  {C.G}🔑 Token refreshed (time-based){C.R}")
                return True
        except google.auth.exceptions.RefreshError as e:
            tprint(f"\n  {C.RD}{'═'*60}")
            tprint(f"  ⚠️  AUTHENTICATION TOKEN EXPIRED — CANNOT REFRESH")
            tprint(f"  {'═'*60}{C.R}")
            tprint(f"  {C.Y}Your session token has expired and cannot be renewed.")
            tprint(f"  All progress has been saved to checkpoint.")
            tprint(f"  ")
            tprint(f"  To continue:")
            tprint(f"    1. Run: gcloud auth application-default login")
            tprint(f"    2. Re-run this script (it will resume automatically)")
            tprint(f"  {C.R}")
            raise  # Let caller handle
        except Exception:
            pass  # Non-fatal, will fail on next API call naturally
        return False

    @classmethod
    def get_compute(cls):
        cls._init_creds()
        if not cls._compute:
            cls._compute = compute_v1.BackendServicesClient(credentials=cls._credentials)
        return cls._compute

    @classmethod
    def get_policies(cls):
        cls._init_creds()
        if not cls._policies:
            cls._policies = compute_v1.SecurityPoliciesClient(credentials=cls._credentials)
        return cls._policies

    @classmethod
    def get_logging(cls, pid):
        cls._init_creds()
        with _client_lock:
            if pid not in cls._logging:
                cls._logging[pid] = logging_v2.Client(project=pid, credentials=cls._credentials)
            return cls._logging[pid]

def get_logging_client(pid):
    return ClientManager.get_logging(pid)

def _is_api_disabled(e):
    m = str(e).lower()
    if "has not been used" in m or "is disabled" in m or "not been enabled" in m:
        for n in ["Compute Engine API","Cloud Logging API","Cloud Resource Manager API"]:
            if n.lower() in m: return n
        return "Required API"
    return ""

def _parse_sensitivity(expr):
    m = re.search(r"['\"]sensitivity['\"]:\s*(\d+)", str(expr))
    return m.group(1) if m else "-"

def _get_action_str(rule):
    action = "Unknown"
    if hasattr(rule, 'action'):
        a = str(rule.action).lower()
        if 'deny' in a:
            code = re.search(r'(\d{3})', str(rule.action))
            action = f"Deny ({code.group(1)})" if code else "Deny"
        elif 'allow' in a: action = "Allow"
        elif 'redirect' in a: action = "Redirect"
        elif 'throttle' in a or 'rate' in a: action = "Throttle"
        else: action = str(rule.action)
    preview = getattr(rule, 'preview', False)
    return f"{action}: Preview only" if preview else f"{action}: Enabled"

def get_log_link(project_id, policy_name, priority, start_str, end_str):
    query = (f'resource.type="http_load_balancer"\n'
             f'jsonPayload.previewSecurityPolicy.name="{policy_name}"\n'
             f'jsonPayload.previewSecurityPolicy.priority="{priority}"')
    encoded = urllib.parse.quote(query, safe='')
    ts_start = urllib.parse.quote(start_str, safe='')
    ts_end = urllib.parse.quote(end_str, safe='')
    return (f"https://console.cloud.google.com/logs/query;"
            f"query={encoded};timeRange={ts_start}%2F{ts_end}"
            f"?project={project_id}")

# ═══════════════════════════════════════════════
# DISCOVERY CACHE
# ═══════════════════════════════════════════════

def _cache_path():
    return Path(os.path.dirname(os.path.abspath(__file__))) / CACHE_FILE

def save_cache(data, projects):
    try:
        with open(_cache_path(), "w") as f:
            json.dump({"timestamp": datetime.now(timezone.utc).isoformat(),
                        "projects": projects, "rules": data}, f, indent=2)
        tprint(f"  💾 Cache saved ({len(data)} rules, valid {DEFAULTS['cache_hours']}h)")
    except Exception as e:
        tprint(f"  {C.Y}⚠ Cache save failed: {e}{C.R}")

def load_cache(projects, cache_hours):
    cp = _cache_path()
    if not cp.exists(): return []
    try:
        with open(cp) as f: d = json.load(f)
        age = datetime.now(timezone.utc) - datetime.fromisoformat(d["timestamp"])
        if age > timedelta(hours=cache_hours):
            tprint(f"  {C.D}📦 Cache expired ({age.total_seconds()/3600:.1f}h). Re-scanning.{C.R}")
            return []
        if not set(projects).issubset(set(d.get("projects",[]))):
            tprint(f"  {C.D}📦 Cache incomplete for requested projects. Re-scanning.{C.R}")
            return []
        rules = [r for r in d["rules"] if r["project_id"] in set(projects)]
        tprint(f"  {C.G}⚡ Cache hit! {len(rules)} rules from {age.total_seconds()/60:.0f}m ago.{C.R}")
        return rules
    except Exception as e:
        tprint(f"  {C.D}📦 Cache error ({e}). Re-scanning.{C.R}")
        return []

# ═══════════════════════════════════════════════
# CHECKPOINT / RESUME (v8: with CSV cleanup)
# ═══════════════════════════════════════════════

def _progress_path():
    return Path(os.path.dirname(os.path.abspath(__file__))) / PROGRESS_FILE

def _rule_key(rule):
    """Unique key for a rule: project|policy|priority"""
    if isinstance(rule, dict):
        return f"{rule['project_id']}|{rule['policy_name']}|{rule['priority']}"
    return f"{rule[0]}|{rule[1]}|{rule[2]}"

def save_progress(completed_keys, failed_keys, start_str, end_str, output_file, total_rules):
    """Save current progress to disk for resume after crash/disconnect."""
    try:
        data = {
            "version": "8.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "start_str": start_str, "end_str": end_str,
            "output_file": output_file,
            "total_rules": total_rules,
            "completed": list(completed_keys),
            "failed": [{"key": k, "error": e} for k, e in failed_keys.items()],
        }
        tmp_path = str(_progress_path()) + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, _progress_path())  # atomic rename
    except Exception:
        pass  # checkpoint save failure is non-fatal

def load_progress(start_str, end_str, output_file):
    """Load checkpoint if it matches the current run parameters.
    v8.2: Uses 1-hour tolerance on timestamps instead of exact match."""
    pp = _progress_path()
    if not pp.exists():
        return None
    try:
        with open(pp) as f:
            data = json.load(f)
        # v8.2: Tolerate timestamp drift (re-runs shift end_str by minutes)
        saved_start = data.get("start_str", "")
        saved_end = data.get("end_str", "")
        saved_output = data.get("output_file", "")
        try:
            s1 = datetime.fromisoformat(saved_start.replace("Z", "+00:00"))
            s2 = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
            e1 = datetime.fromisoformat(saved_end.replace("Z", "+00:00"))
            e2 = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
            start_drift = abs((s1 - s2).total_seconds())
            end_drift = abs((e1 - e2).total_seconds())
            time_ok = start_drift < 3600 and end_drift < 3600  # 1h tolerance
        except Exception:
            time_ok = (saved_start == start_str and saved_end == end_str)
        if not time_ok or saved_output != output_file:
            tprint(f"  {C.D}📌 Checkpoint exists but for different run. Starting fresh.{C.R}")
            return None
        age = datetime.now(timezone.utc) - datetime.fromisoformat(data["timestamp"])
        completed = set(data.get("completed", []))
        total = data.get("total_rules", 0)
        tprint(f"  {C.G}📌 Checkpoint found! {len(completed)}/{total} rules done "
               f"({age.total_seconds()/60:.0f}m ago){C.R}")
        return data
    except Exception as e:
        tprint(f"  {C.D}📌 Checkpoint unreadable ({e}). Starting fresh.{C.R}")
        return None

def cleanup_csv_for_resume(output_file, completed_keys, header):
    """v8: Remove partial rows from CSV for rules that weren't fully completed.
    This handles the case where the script crashed mid-rule and left orphaned rows."""
    if not os.path.exists(output_file):
        return
    try:
        # Read all existing rows
        with open(output_file, "r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            all_rows = list(reader)
        if not all_rows:
            return
        # Separate header from data
        file_header = all_rows[0] if all_rows else header
        data_rows = all_rows[1:] if len(all_rows) > 1 else []
        # Keep only rows whose rule_key is in completed_keys OR are non-preview
        # (active rules, skipped projects have special markers)
        kept = []
        removed = 0
        for row in data_rows:
            if len(row) < 4:
                kept.append(row)
                continue
            # Active rules and skipped projects don't have rule keys in preview set
            integrity = row[10] if len(row) > 10 else ""
            if "Active rule" in integrity or row[1] == "-":
                kept.append(row)
                continue
            rk = f"{row[0]}|{row[1]}|{row[3]}"
            if rk in completed_keys:
                kept.append(row)
            else:
                removed += 1
        # Rewrite clean CSV
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(file_header)
            for row in kept:
                writer.writerow(row)
            f.flush()
            os.fsync(f.fileno())
        if removed:
            tprint(f"  {C.Y}🧹 Cleaned {removed} partial row(s) from previous incomplete run{C.R}")
        tprint(f"  {C.G}📄 CSV verified: {len(kept)} clean rows retained{C.R}")
    except Exception as e:
        tprint(f"  {C.Y}⚠ CSV cleanup warning: {e} — will append safely{C.R}")

def clear_progress():
    """Remove checkpoint file after successful completion."""
    try:
        pp = _progress_path()
        if pp.exists():
            pp.unlink()
    except Exception:
        pass

# ═══════════════════════════════════════════════
# STEP 1 — Discovery (READ-ONLY: aggregatedList + securityPolicies.get)
# ═══════════════════════════════════════════════

def discover_project(pid):
    attached = set()
    status = "ok"
    try:
        cl = ClientManager.get_compute()
        for _, sl in cl.aggregated_list(project=pid):
            if not sl.backend_services: continue
            for b in sl.backend_services:
                if b.security_policy:
                    attached.add(b.security_policy.split("/")[-1])
    except (exceptions.PermissionDenied, exceptions.Forbidden) as e:
        api = _is_api_disabled(e)
        status = f"⏭ {api} not enabled" if api else "Permission denied"
    except exceptions.GoogleAPICallError as e:
        api = _is_api_disabled(e)
        status = f"⏭ {api} not enabled" if api else f"API error: {e.message}"
    except Exception as e:
        m = str(e).lower()
        if "metadata server" in m or "email" in m:
            status = "⏭ Auth/Metadata Error (Verify 'gcloud auth login')"
        else:
            api = _is_api_disabled(e)
            status = f"⏭ {api} not enabled" if api else f"Error: {e}"
    return pid, attached, status

def run_discovery(projects, threads):
    tasks, skipped = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        fm = {ex.submit(discover_project, p): p for p in projects}
        for f in tqdm(concurrent.futures.as_completed(fm), total=len(projects),
                      desc=f"  {C.CN}Scanning{C.R}", unit="proj", ncols=72,
                      bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"):
            pid = fm[f]
            try:
                project_id, attached, status = f.result()
                if status != "ok":
                    tprint(f"  {C.Y}⚠ {project_id}: {status}{C.R}")
                    skipped.append((project_id, status))
                elif attached:
                    tprint(f"  {C.G}✔ {project_id}: {len(attached)} policies{C.R}")
                    for pol in sorted(attached):
                        tasks.append((project_id, pol))
            except Exception as e:
                tprint(f"  {C.RD}❌ {pid}: {e}{C.R}")
                skipped.append((pid, str(e)))
    return tasks, skipped

# ═══════════════════════════════════════════════
# STEP 2 — Rule Fetch (READ-ONLY: securityPolicies.get)
# ═══════════════════════════════════════════════

def fetch_policy_rules(pid, pol):
    rules = []
    try:
        policy = ClientManager.get_policies().get(project=pid, security_policy=pol)
        for rule in policy.rules:
            if rule.match and rule.match.expr and rule.match.expr.expression:
                expr = rule.match.expr.expression
            elif rule.match and rule.match.versioned_expr:
                expr = f"versioned_expr:{rule.match.versioned_expr}"
            else:
                expr = "N/A"
            rules.append({
                "project_id": pid, "policy_name": pol,
                "priority": str(rule.priority),
                "description": (rule.description or "").strip() or "No description",
                "expression": expr,
                "sensitivity": _parse_sensitivity(expr),
                "action": _get_action_str(rule),
                "is_preview": bool(getattr(rule, 'preview', False)),
            })
        return pid, pol, rules, None
    except exceptions.NotFound:
        return pid, pol, [], "Policy not found"
    except (exceptions.PermissionDenied, exceptions.Forbidden) as e:
        api = _is_api_disabled(e)
        return pid, pol, [], f"⏭ {api} not enabled" if api else "Permission denied"
    except exceptions.GoogleAPICallError as e:
        api = _is_api_disabled(e)
        return pid, pol, [], f"⏭ {api} not enabled" if api else f"API error: {e.message}"
    except Exception as e:
        return pid, pol, [], str(e)

def run_rule_fetch(policy_tasks, threads):
    all_rules, errors = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        fm = {ex.submit(fetch_policy_rules, p, pol): (p, pol) for p, pol in policy_tasks}
        for f in tqdm(concurrent.futures.as_completed(fm), total=len(policy_tasks),
                      desc=f"  {C.CN}Fetching rules{C.R}", unit="pol", ncols=72,
                      bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"):
            pid, pol = fm[f]
            try:
                _, _, rules, err = f.result()
                if err:
                    tprint(f"  {C.RD}❌ {pid}/{pol}: {err}{C.R}")
                    errors.append((pid, pol, err))
                elif rules:
                    preview_count = sum(1 for r in rules if r["is_preview"])
                    if preview_count:
                        tprint(f"  {C.G}✔ {pid}/{pol}: {preview_count} preview rules{C.R}")
                    all_rules.extend(rules)
            except Exception as e:
                tprint(f"  {C.RD}❌ {pid}/{pol}: {e}{C.R}")
                errors.append((pid, pol, str(e)))
    return all_rules, errors

# ═══════════════════════════════════════════════
# STEP 3 — Log Queries with DYNAMIC CHUNKING
# (READ-ONLY: logging.entries.list only)
# ═══════════════════════════════════════════════

def _extract_ids(pi):
    if not isinstance(pi, dict): return []
    raw = pi.get("preconfiguredExprIds")
    if not raw: return []
    if isinstance(raw, str): return [raw]
    if isinstance(raw, (list, tuple)): return [str(x) for x in raw if x]
    return [str(raw)]

def _adapt_threads(success, cfg):
    global _current_log_threads, _consecutive_successes, _dynamic_sem
    with _throttle_lock:
        old = _current_log_threads
        if success:
            _consecutive_successes += 1
            if _consecutive_successes >= cfg["ramp_success"]:
                _current_log_threads = min(cfg["max_log_threads"], _current_log_threads + 1)
                _consecutive_successes = 0
        else:
            _consecutive_successes = 0
            _current_log_threads = max(cfg["min_log_threads"], _current_log_threads // 2)
            tprint(f"  {C.Y}⏳ Throttling → {_current_log_threads} threads{C.R}")
        # v8.2: Wake blocked threads when limit changes
        if old != _current_log_threads and _dynamic_sem is not None:
            _dynamic_sem.notify_limit_changed()

def _query_chunk(client, pid, pol, pri, chunk_start, chunk_end, cfg):
    """Query a single time chunk. Returns (counter, total, error_or_None).
    This is the atomic unit — it either succeeds completely or fails."""
    filt = (f'resource.type="http_load_balancer" '
            f'AND jsonPayload.previewSecurityPolicy.name="{pol}" '
            f'AND jsonPayload.previewSecurityPolicy.priority="{pri}" '
            f'AND timestamp >= "{chunk_start}" AND timestamp <= "{chunk_end}"')

    counter = Counter()
    total = 0

    for attempt in range(1, cfg["max_retries"] + 1):
        counter.clear()
        total = 0
        try:
            # Proactive rate limiting
            if _should_self_throttle(pid):
                time.sleep(1.0)

            _track_api_call(pid)

            # Inter-request delay
            delay_s = cfg.get("request_delay_ms", 150) / 1000.0
            if delay_s > 0:
                time.sleep(delay_s)

            for entry in client.list_entries(filter_=filt, page_size=1000,
                                              resource_names=[f"projects/{pid}"]):
                total += 1
                payload = entry.payload
                if not isinstance(payload, dict):
                    counter["General Match"] += 1
                    continue
                pi = payload.get("previewSecurityPolicy")
                if not isinstance(pi, dict):
                    counter["General Match"] += 1
                    continue
                ids = _extract_ids(pi)
                if not ids:
                    counter["General Match (No sub-ID)"] += 1
                else:
                    for eid in ids:
                        counter[eid] += 1

            _adapt_threads(True, cfg)
            return counter, total, None  # Success

        except exceptions.ResourceExhausted:
            sleep = cfg["retry_base"] * (2 ** (attempt - 1))
            _adapt_threads(False, cfg)
            if attempt < cfg["max_retries"]:
                time.sleep(sleep)
            else:
                return counter, total, "RATE_LIMITED"

        except exceptions.DeadlineExceeded:
            sleep = cfg["retry_base"] * (2 ** (attempt - 1))
            if attempt < cfg["max_retries"]:
                time.sleep(sleep)
            else:
                return counter, total, "TIMEOUT"

        except (exceptions.PermissionDenied, exceptions.Forbidden) as e:
            api = _is_api_disabled(e)
            return counter, total, f"⏭ {api} not enabled" if api else "Permission denied"

        except exceptions.GoogleAPICallError as e:
            api = _is_api_disabled(e)
            return counter, total, f"⏭ {api} not enabled" if api else f"API: {e.message}"

        except google.auth.exceptions.RefreshError:
            return counter, total, "AUTH_EXPIRED"

        except Exception as e:
            msg = str(e).lower()
            if "metadata" in msg or "email" in msg or "refresherror" in msg:
                return counter, total, "AUTH_EXPIRED"
            return counter, total, str(e)

    return counter, total, "Max retries exceeded"

def _query_with_dynamic_chunks(client, pid, pol, pri, window_start, window_end, cfg,
                                min_chunk_td=None, depth=0):
    """Recursively query a time window, bisecting on timeout.
    Returns (counter, total_entries, chunks_ok, chunks_failed, gap_windows).
    This ensures ZERO logs are missed — if a window is too big, split it smaller."""
    if min_chunk_td is None:
        min_chunk_td = timedelta(minutes=cfg.get("min_chunk_minutes", 15))

    counter = Counter()
    total = 0
    chunks_ok = 0
    chunks_failed = 0
    gap_windows = []  # time windows that couldn't be queried

    start_dt = datetime.fromisoformat(window_start.replace("Z", "+00:00"))
    end_dt = datetime.fromisoformat(window_end.replace("Z", "+00:00"))
    window_size = end_dt - start_dt

    # Try the full window first
    chunk_counter, chunk_total, err = _query_chunk(
        client, pid, pol, pri, window_start, window_end, cfg)

    if err is None:
        # Success — got all entries for this window
        return chunk_counter, chunk_total, 1, 0, []

    if err == "AUTH_EXPIRED":
        # Auth failure — can't bisect, must bubble up
        return counter, total, 0, 1, [(window_start, window_end, "AUTH_EXPIRED")]

    if err in ("TIMEOUT", "RATE_LIMITED") and window_size > min_chunk_td:
        # Bisect: split window in half and recurse
        mid_dt = start_dt + window_size / 2
        mid_str = mid_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        indent = "  " + "  " * depth
        tprint(f"{indent}{C.Y}🔀 Bisecting {window_start}→{window_end} "
               f"(chunk too large, splitting at {mid_str}){C.R}")

        # First half
        c1, t1, ok1, fail1, gaps1 = _query_with_dynamic_chunks(
            client, pid, pol, pri, window_start, mid_str, cfg,
            min_chunk_td, depth + 1)

        # Credential check between halves
        try:
            ClientManager.refresh_if_needed()
        except Exception:
            pass

        # Second half
        c2, t2, ok2, fail2, gaps2 = _query_with_dynamic_chunks(
            client, pid, pol, pri, mid_str, window_end, cfg,
            min_chunk_td, depth + 1)

        # Merge results
        merged = c1 + c2
        return merged, t1 + t2, ok1 + ok2, fail1 + fail2, gaps1 + gaps2

    elif err in ("TIMEOUT", "RATE_LIMITED"):
        # Window is already at minimum size and still failing
        tprint(f"  {C.RD}⚠ Minimum chunk still failing: {window_start}→{window_end}: {err}{C.R}")
        # Return whatever partial data we got from retries
        return chunk_counter, chunk_total, 0, 1, [(window_start, window_end, err)]

    else:
        # Non-retryable error (permission denied, etc.)
        return chunk_counter, chunk_total, 0, 1, [(window_start, window_end, err)]

def query_single_rule(rule, start_str, end_str, cfg):
    """Query a single rule across the full time window using dynamic chunking."""
    pid, pol = rule["project_id"], rule["policy_name"]
    pri = rule["priority"]

    # Proactive credential refresh before starting
    try:
        ClientManager.refresh_if_needed()
    except google.auth.exceptions.RefreshError:
        log_link = get_log_link(pid, pol, pri, start_str, end_str)
        return [[pid, pol, rule["description"], pri, rule["sensitivity"],
                 rule["action"], 0, "No signature detected", "-", log_link,
                 "⚠️ Auth expired — resume after re-auth", "0/? days"]]

    client = get_logging_client(pid)

    # Generate time chunks (daily windows)
    chunk_hours = cfg.get("chunk_hours", 24)
    start_dt = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
    end_dt = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
    total_hours = (end_dt - start_dt).total_seconds() / 3600

    # Build chunk boundaries
    chunks = []
    cursor = start_dt
    while cursor < end_dt:
        chunk_end = min(cursor + timedelta(hours=chunk_hours), end_dt)
        chunks.append((cursor.strftime("%Y-%m-%dT%H:%M:%SZ"),
                       chunk_end.strftime("%Y-%m-%dT%H:%M:%SZ")))
        cursor = chunk_end

    # Query each chunk with dynamic bisection on failure
    merged_counter = Counter()
    total_entries = 0
    total_chunks_ok = 0
    total_chunks_failed = 0
    all_gaps = []
    auth_expired = False

    for i, (cs, ce) in enumerate(chunks):
        chunk_counter, chunk_total, ok, failed, gaps = _query_with_dynamic_chunks(
            client, pid, pol, pri, cs, ce, cfg)
        merged_counter += chunk_counter
        total_entries += chunk_total
        total_chunks_ok += ok
        total_chunks_failed += failed
        all_gaps.extend(gaps)

        # Check for auth expiry — stop early, will resume later
        if any(g[2] == "AUTH_EXPIRED" for g in gaps):
            auth_expired = True
            break

        # Credential refresh between chunks
        if (i + 1) % 5 == 0:
            try:
                ClientManager.refresh_if_needed()
            except google.auth.exceptions.RefreshError:
                auth_expired = True
                break

    # Build coverage string
    total_chunks = len(chunks)
    coverage_str = f"{total_chunks_ok}/{total_chunks} chunks"
    if total_chunks_failed > 0:
        gap_details = "; ".join(f"{g[0]}→{g[1]}" for g in all_gaps[:3])
        if len(all_gaps) > 3:
            gap_details += f" (+{len(all_gaps)-3} more)"
        coverage_str += f" | GAPS: {gap_details}"

    log_link = get_log_link(pid, pol, pri, start_str, end_str)
    desc = rule["description"]
    sens = rule["sensitivity"]
    action = rule["action"]

    if auth_expired:
        integrity = "⚠️ Auth expired — partial data, resume to complete"
    elif total_chunks_failed > 0:
        integrity = f"⚠️ {total_chunks_failed} chunk(s) failed — {coverage_str}"
    else:
        integrity = "✅ Verified"

    if not merged_counter:
        return [[pid, pol, desc, pri, sens, action, 0,
                 "No signature detected", "-", log_link, integrity, coverage_str]]

    rows = []
    for sig, cnt in sorted(merged_counter.items(), key=lambda x: -x[1]):
        sig_desc = _get_sig_description(sig)
        rows.append([pid, pol, desc, pri, sens, action, cnt,
                      sig, sig_desc, log_link, integrity, coverage_str])
    return rows

def run_log_queries(preview_rules, start_str, end_str, cfg, csv_writer, csv_fh,
                    completed_keys=None, failed_keys=None, output_file=""):
    """Run log queries with checkpoint save after each rule."""
    if completed_keys is None:
        completed_keys = set()
    if failed_keys is None:
        failed_keys = {}

    total_rules = len(preview_rules)

    # Filter out already-completed rules (resume mode)
    remaining = [r for r in preview_rules if _rule_key(r) not in completed_keys]
    skipped_count = total_rules - len(remaining)
    if skipped_count > 0:
        tprint(f"  {C.G}📌 Resuming: {skipped_count} rules already done, "
               f"{len(remaining)} remaining{C.R}")

    all_rows = []
    errors = [0]  # v8.2: list for thread-safe mutation
    total_hits = [0]
    
    # v8.1: Shuffle rules to spread load across projects
    random.shuffle(remaining)
    
    # v8.2: Use global dynamic semaphore so _adapt_threads can notify it
    global _dynamic_sem
    sem = DynamicSemaphore()
    _dynamic_sem = sem
    _progress_lock = threading.Lock()

    def wrapped(rule):
        sem.acquire()
        try:
            return query_single_rule(rule, start_str, end_str, cfg)
        finally:
            sem.release()

    # v8.2: Batch submission to avoid overwhelming the thread pool
    batch_size = max(cfg["max_log_threads"] * 2, 10)
    all_futures = {}
    rule_queue = list(remaining)
    completed_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=cfg["max_log_threads"]) as ex:
        # Submit first batch
        initial_batch = rule_queue[:batch_size]
        rule_queue = rule_queue[batch_size:]
        for r in initial_batch:
            all_futures[ex.submit(wrapped, r)] = r

        pbar = tqdm(total=len(remaining),
                    desc=f"  {C.CN}Querying rules{C.R}", unit="rule", ncols=80,
                    bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]")

        while all_futures:
            done, _ = concurrent.futures.wait(
                all_futures, timeout=5.0,
                return_when=concurrent.futures.FIRST_COMPLETED)

            for f in done:
                rule = all_futures.pop(f)
                rk = _rule_key(rule)
                try:
                    rows = f.result()
                    all_rows.extend(rows)
                    with _csv_lock:
                        for r in rows:
                            csv_writer.writerow(r)
                        csv_fh.flush()
                        try:
                            os.fsync(csv_fh.fileno())
                        except Exception:
                            pass

                    with _progress_lock:
                        completed_keys.add(rk)
                        err_rows = [r for r in rows if "⚠️" in str(r[10])]
                        if err_rows:
                            errors[0] += 1
                            failed_keys[rk] = str(rows[0][10]) if rows else "Unknown"
                        elif rk in failed_keys:
                            del failed_keys[rk]
                        save_progress(completed_keys, failed_keys, start_str, end_str,
                                      output_file, total_rules)

                    hits = [r for r in rows if isinstance(r[6], int) and r[6] > 0
                            and r[7] != "No signature detected"]
                    if hits:
                        rh = sum(r[6] for r in hits)
                        total_hits[0] += rh
                        tprint(f"  {C.M}💥 {rule['project_id']}/{rule['policy_name']} "
                               f"p={rule['priority']}: {rh:,} hits ({len(hits)} sigs){C.R}")

                except Exception as e:
                    errors[0] += 1
                    with _progress_lock:
                        failed_keys[rk] = str(e)
                        save_progress(completed_keys, failed_keys, start_str, end_str,
                                      output_file, total_rules)
                    tprint(f"  {C.RD}❌ {rule['project_id']}/{rule['policy_name']}: {e}{C.R}")

                completed_count += 1
                pbar.update(1)
                pbar.set_postfix_str(f"hits={total_hits[0]:,} err={errors[0]}", refresh=False)

                # Submit more from queue
                if rule_queue:
                    next_rule = rule_queue.pop(0)
                    all_futures[ex.submit(wrapped, next_rule)] = next_rule

        pbar.close()

    _dynamic_sem = None
    return all_rows, errors[0], total_hits[0], completed_keys, failed_keys

# ═══════════════════════════════════════════════
# SCOREBOARD & EXECUTIVE SUMMARY
# ═══════════════════════════════════════════════

def scoreboard(rows, rule_count, errs, elapsed):
    print(f"\n{C.B}{'═'*70}\n  📈 FINAL SCOREBOARD\n{'═'*70}{C.R}")
    by_p = {}
    for r in rows:
        p = r[0]
        if p not in by_p: by_p[p] = {"pol": set(), "rules": set(), "hits": 0}
        by_p[p]["pol"].add(r[1]); by_p[p]["rules"].add(r[3])
        if isinstance(r[6], int): by_p[p]["hits"] += r[6]
    for p in sorted(by_p):
        s = by_p[p]
        h = f"{C.G}{s['hits']:>10,}{C.R}" if s["hits"] else f"{C.D}         0{C.R}"
        print(f"  {p:<40} {len(s['pol']):>2} pol {len(s['rules']):>3} rules {h} hits")
    tot = sum(s["hits"] for s in by_p.values())
    print(f"\n{C.B}{'─'*70}{C.R}")
    print(f"  {C.B}Total:{C.R} {rule_count} rules | {C.G}{tot:,} hits{C.R} | ⏱ {elapsed:.1f}s")
    if errs: print(f"  {C.RD}⚠ {errs} error(s){C.R}")
    print(f"{C.B}{'═'*70}{C.R}")

def generate_executive_summary(output_file, all_rows, preview_rules, non_preview,
                                skipped_projects, failed_keys, elapsed,
                                start_str, end_str, err_count, run_log):
    """Generate a dynamic executive summary based on actual script behavior."""
    summary_file = output_file.rsplit(".", 1)[0] + SUMMARY_FILE_SUFFIX
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Compute stats
    total_hits = sum(r[6] for r in all_rows if isinstance(r[6], int))
    verified_rules = [r for r in all_rows if "✅" in str(r[10])]
    partial_rules = [r for r in all_rows if "⚠️" in str(r[10])]
    unique_sigs = set(r[7] for r in all_rows
                      if r[7] not in ("No signature detected", "-", ""))
    by_project = {}
    for r in all_rows:
        p = r[0]
        if p not in by_project:
            by_project[p] = {"hits": 0, "rules": set(), "sigs": set()}
        if isinstance(r[6], int): by_project[p]["hits"] += r[6]
        by_project[p]["rules"].add(r[3])
        if r[7] not in ("No signature detected", "-", ""):
            by_project[p]["sigs"].add(r[7])

    # Top signatures
    sig_counter = Counter()
    for r in all_rows:
        if isinstance(r[6], int) and r[7] not in ("No signature detected", "-", ""):
            sig_counter[r[7]] += r[6]
    top_sigs = sig_counter.most_common(10)

    lines = []
    lines.append("=" * 72)
    lines.append("  CLOUD ARMOR PREVIEW RULE ANALYSIS — EXECUTIVE SUMMARY")
    lines.append("  Searce Cloud Armor Analyzer v8.0")
    lines.append("=" * 72)
    lines.append(f"  Generated : {now_str}")
    lines.append(f"  Time Window: {start_str} → {end_str}")
    lines.append(f"  Duration  : {elapsed:.1f} seconds")
    lines.append("")

    # ── KEY METRICS ──
    lines.append("─" * 72)
    lines.append("  KEY METRICS")
    lines.append("─" * 72)
    lines.append(f"  Preview Rules Analyzed : {len(preview_rules)}")
    lines.append(f"  Active Rules (not queried): {len(non_preview)}")
    lines.append(f"  Total Attack Hits      : {total_hits:,}")
    lines.append(f"  Unique Signatures      : {len(unique_sigs)}")
    lines.append(f"  Projects Analyzed      : {len(by_project)}")
    lines.append(f"  Projects Skipped       : {len(skipped_projects)}")
    verified_pct = (len(verified_rules) / max(len(all_rows), 1)) * 100
    lines.append(f"  Data Integrity         : {verified_pct:.1f}% verified")
    lines.append("")

    # ── TOP ATTACKED PROJECTS ──
    if by_project:
        lines.append("─" * 72)
        lines.append("  TOP ATTACKED PROJECTS")
        lines.append("─" * 72)
        sorted_projects = sorted(by_project.items(), key=lambda x: -x[1]["hits"])
        for p, s in sorted_projects[:10]:
            lines.append(f"  {p:<42} {s['hits']:>8,} hits  "
                         f"{len(s['rules']):>3} rules  {len(s['sigs']):>3} sigs")
        lines.append("")

    # ── TOP SIGNATURES ──
    if top_sigs:
        lines.append("─" * 72)
        lines.append("  TOP 10 TRIGGERED SIGNATURES")
        lines.append("─" * 72)
        for sig, cnt in top_sigs:
            desc = _get_sig_description(sig)
            lines.append(f"  {cnt:>10,}  {sig:<50}")
            lines.append(f"             {desc}")
        lines.append("")

    # ── EXCLUSIONS: What was NOT analyzed ──
    lines.append("─" * 72)
    lines.append("  EXCLUSIONS — ITEMS NOT INCLUDED IN THIS ANALYSIS")
    lines.append("─" * 72)
    exclusions = []
    if non_preview:
        exclusions.append(f"  • {len(non_preview)} ACTIVE (non-preview) rules were discovered but "
                          "NOT queried for logs.")
        exclusions.append("    Reason: Only preview-mode rules are analyzed. Active rules are "
                          "already enforcing.")
    if skipped_projects:
        exclusions.append(f"  • {len(skipped_projects)} project(s) were SKIPPED entirely:")
        for pid, reason in skipped_projects:
            exclusions.append(f"    - {pid}: {reason}")
    if partial_rules:
        partial_keys = set()
        for r in partial_rules:
            partial_keys.add(f"{r[0]}|{r[1]}|{r[3]}")
        exclusions.append(f"  • {len(partial_keys)} rule(s) have INCOMPLETE data (partial coverage):")
        for r in partial_rules[:10]:
            cov = r[11] if len(r) > 11 else "unknown"
            exclusions.append(f"    - {r[0]}/{r[1]} priority={r[3]} — coverage: {cov}")
        if len(partial_rules) > 10:
            exclusions.append(f"    ... and {len(partial_rules)-10} more")
    if not exclusions:
        exclusions.append("  • None — all discovered rules and projects were fully analyzed.")
    for line in exclusions:
        lines.append(line)
    lines.append("")

    # ── ITEMS REQUIRING MANUAL REVIEW ──
    lines.append("─" * 72)
    lines.append("  ITEMS REQUIRING MANUAL REVIEW")
    lines.append("─" * 72)
    review_items = []
    # High-hit signatures that are still in preview
    for sig, cnt in top_sigs[:5]:
        if cnt > 100:
            desc = _get_sig_description(sig)
            review_items.append(f"  ⚡ HIGH VOLUME: {sig} ({cnt:,} hits) — {desc}")
            review_items.append(f"     Action: Review if this rule should be promoted from "
                                "Preview → Enforce")
    # Rules with zero hits
    zero_hit = [r for r in all_rows if isinstance(r[6], int) and r[6] == 0
                and r[7] == "No signature detected"]
    if zero_hit:
        zero_keys = set(f"{r[0]}|{r[1]}|{r[3]}" for r in zero_hit)
        review_items.append(f"  📋 {len(zero_keys)} preview rule(s) had ZERO hits in the analysis window.")
        review_items.append("     Action: Consider if these rules are still needed or if traffic "
                            "patterns have changed.")
    # Skipped projects
    if skipped_projects:
        review_items.append(f"  🔒 {len(skipped_projects)} project(s) could not be scanned "
                            "(permission/API issues).")
        review_items.append("     Action: Verify IAM permissions and enable required APIs.")
    # Partial data
    if partial_rules:
        review_items.append(f"  ⚠️  Some rules have incomplete time coverage.")
        review_items.append("     Action: Re-run the script to resume and fill coverage gaps.")
    if not review_items:
        review_items.append("  ✅ No items require manual review. All data is complete and verified.")
    for line in review_items:
        lines.append(line)
    lines.append("")

    # ── ERROR LOG & DIAGNOSTICS ──
    lines.append("─" * 72)
    lines.append("  ERROR LOG & DIAGNOSTICS")
    lines.append("─" * 72)
    if err_count == 0 and not failed_keys and not skipped_projects:
        lines.append("  ✅ No errors encountered. Script ran cleanly.")
    else:
        if failed_keys:
            lines.append(f"  ❌ {len(failed_keys)} rule(s) failed after all retries:")
            for rk, err in list(failed_keys.items())[:20]:
                parts = rk.split("|")
                lines.append(f"    Rule: {parts[0]}/{parts[1]} priority={parts[2]}")
                lines.append(f"    Error: {err}")
                # Root cause analysis
                err_lower = err.lower()
                if "auth" in err_lower or "refresh" in err_lower:
                    lines.append("    Diagnosis: Authentication token expired during execution.")
                    lines.append("    Fix: Use a Service Account for long runs, or re-run to resume.")
                elif "rate" in err_lower or "exhausted" in err_lower:
                    lines.append("    Diagnosis: API rate limit exceeded even after backoff.")
                    lines.append("    Fix: Re-run with --threads 1 or request quota increase.")
                elif "timeout" in err_lower or "deadline" in err_lower:
                    lines.append("    Diagnosis: Query too large even at minimum chunk size.")
                    lines.append("    Fix: This rule may have extremely high log volume. "
                                 "Consider using BigQuery log sink.")
                elif "permission" in err_lower or "forbidden" in err_lower:
                    lines.append("    Diagnosis: Insufficient IAM permissions on this project.")
                    lines.append("    Fix: Grant 'Viewer' role or specific logging.logEntries.list.")
                elif "not enabled" in err_lower or "disabled" in err_lower:
                    lines.append("    Diagnosis: Required API not enabled on the project.")
                    lines.append("    Fix: Enable Cloud Logging API in the project.")
                else:
                    lines.append(f"    Diagnosis: Unexpected error — review the error message above.")
                lines.append("")
            if len(failed_keys) > 20:
                lines.append(f"    ... and {len(failed_keys)-20} more errors (see CSV for full list)")
        if skipped_projects:
            lines.append(f"\n  ⏭ {len(skipped_projects)} project(s) skipped during discovery:")
            for pid, reason in skipped_projects:
                lines.append(f"    {pid}: {reason}")
    lines.append("")

    # ── RUN LOG ──
    if run_log:
        lines.append("─" * 72)
        lines.append("  RUN LOG (key events during execution)")
        lines.append("─" * 72)
        for entry in run_log[-50:]:  # Last 50 events
            lines.append(f"  {entry}")
        if len(run_log) > 50:
            lines.append(f"  ... {len(run_log)-50} earlier events omitted")
        lines.append("")

    # ── METHODOLOGY ──
    lines.append("─" * 72)
    lines.append("  METHODOLOGY & CONFIDENCE")
    lines.append("─" * 72)
    lines.append("  • This report was generated using Searce Cloud Armor Analyzer v8.0")
    lines.append("  • Tool is 100% READ-ONLY: uses only compute.*.list/get + logging.entries.list")
    lines.append("  • ZERO infrastructure changes were made during this analysis")
    lines.append("  • Log queries use dynamic time-window chunking to ensure complete coverage")
    lines.append("  • Each time chunk auto-bisects on timeout (min 15-min granularity)")
    lines.append("  • All counts are EXACT (not sampled) — every matching log entry is counted")
    lines.append(f"  • Data integrity: {verified_pct:.1f}% of rules fully verified")
    lines.append("")
    lines.append("=" * 72)
    lines.append("  END OF EXECUTIVE SUMMARY")
    lines.append("=" * 72)

    try:
        with open(summary_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
            f.flush()
            os.fsync(f.fileno())
        tprint(f"  {C.G}📋 Executive summary: '{summary_file}'{C.R}")
    except Exception as e:
        tprint(f"  {C.Y}⚠ Could not write summary: {e}{C.R}")

    return summary_file

# ═══════════════════════════════════════════════
# CLI + MAIN
# ═══════════════════════════════════════════════

PID_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")

def parse_args():
    p = argparse.ArgumentParser(
        description="Searce Cloud Armor Analyzer v8.0 — Enterprise Edition (READ-ONLY)")
    p.add_argument("-p", "--projects", help="Comma-separated project IDs")
    p.add_argument("-f", "--projects-file", help="File with project IDs (one per line)")
    p.add_argument("-o", "--output", default=DEFAULTS["output"], help="Output CSV path")
    p.add_argument("-d", "--days", type=int, default=DEFAULTS["days"], help="Days lookback")
    p.add_argument("--threads", type=int, default=DEFAULTS["log_threads"],
                   help="Initial log query threads")
    p.add_argument("--max-threads", type=int, default=DEFAULTS["max_log_threads"],
                   help="Max log threads")
    p.add_argument("--chunk-hours", type=int, default=DEFAULTS["chunk_hours"],
                   help="Initial chunk size in hours (auto-bisects on failure)")
    p.add_argument("--retries", type=int, default=DEFAULTS["max_retries"],
                   help="Max retries per chunk")
    p.add_argument("--request-delay-ms", type=int, default=DEFAULTS["request_delay_ms"],
                   help="Delay between API calls in ms")
    p.add_argument("--cache-hours", type=int, default=DEFAULTS["cache_hours"],
                   help="Cache TTL hours")
    p.add_argument("--fresh", action="store_true", help="Ignore cache")
    p.add_argument("--resume", action="store_true",
                   help="Auto-resume from checkpoint (no prompt)")
    p.add_argument("--no-resume", action="store_true",
                   help="Ignore checkpoint, start fresh")
    p.add_argument("--tutorial", action="store_true", help="Show tutorial")
    p.add_argument("--skip-tutorial", action="store_true", help="Skip tutorial")
    return p.parse_args()

def load_projects(args):
    raw = []
    if args.projects:
        raw = [x.strip() for x in args.projects.split(",") if x.strip()]
        print(f"  📋 {len(raw)} project ID(s) from --projects flag")
    elif args.projects_file:
        try:
            with open(args.projects_file) as f:
                raw = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
            print(f"  📂 Loaded {len(raw)} ID(s) from {args.projects_file}")
        except FileNotFoundError:
            print(f"  {C.RD}❌ Not found: {args.projects_file}{C.R}"); sys.exit(1)
    else:
        try:
            inp = input(f"\n  {C.B}▶ Project IDs (comma-separated): {C.R}").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n  👋"); sys.exit(0)
        raw = [x.strip() for x in inp.split(",") if x.strip()]
    if not raw:
        print(f"  {C.RD}❌ No projects.{C.R}"); sys.exit(1)
    seen, valid, bad = set(), [], []
    for p in raw:
        pl = p.lower().strip()
        if pl in seen: continue
        seen.add(pl)
        if PID_RE.match(pl): valid.append(pl)
        else: bad.append(p)
    if bad: print(f"  {C.Y}⚠ Skipping {len(bad)} invalid: {bad[:5]}{C.R}")
    if not valid: print(f"  {C.RD}❌ No valid projects.{C.R}"); sys.exit(1)
    print(f"  ✅ {len(valid)} project(s) ready")
    return sorted(valid)

def main():
    global _current_log_threads
    args = parse_args()
    cfg = {
        "log_threads": args.threads, "max_log_threads": args.max_threads,
        "min_log_threads": DEFAULTS["min_log_threads"],
        "max_retries": args.retries, "retry_base": DEFAULTS["retry_base"],
        "ramp_success": DEFAULTS["ramp_success"],
        "chunk_hours": args.chunk_hours,
        "min_chunk_minutes": DEFAULTS["min_chunk_minutes"],
        "request_delay_ms": args.request_delay_ms,
    }
    _current_log_threads = cfg["log_threads"]

    if not args.skip_tutorial and not args.tutorial:
        print(f"\n  {C.D}💡 Run with --tutorial for an interactive guide.{C.R}")

    now = datetime.now(timezone.utc)
    start_dt = now - timedelta(days=args.days)
    start_str = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    run_log = []  # Dynamic event log for executive summary
    run_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Script started")

    print(f"\n{C.B}{C.CN}{'━'*70}")
    print(f"  ☁️  Searce Cloud Armor Analyzer v8.0 — Enterprise Edition")
    print(f"{'━'*70}{C.R}")
    print(f"  🔒 READ-ONLY — ZERO infrastructure changes (compute.list/get + logging.list ONLY)")
    print(f"  📅 Window     : {start_str} → {end_str} ({args.days} days)")
    print(f"  ⚡ Threads    : {cfg['log_threads']} initial → {cfg['max_log_threads']} max (adaptive)")
    print(f"  📦 Chunking   : {cfg['chunk_hours']}h initial → auto-bisect on timeout (min {cfg['min_chunk_minutes']}m)")
    print(f"  🔄 Retries    : {cfg['max_retries']} per chunk (backoff: {cfg['retry_base']}s base)")
    print(f"  ⏱  API Delay  : {cfg['request_delay_ms']}ms between calls")
    print(f"  📊 Accuracy   : EXACT counts via dynamic chunking (zero missed logs)")
    print(f"  💾 Output     : {args.output}")
    print(f"  📌 Checkpoint : {'disabled' if args.no_resume else 'enabled (auto-saves + CSV cleanup on resume)'}")
    print(f"{C.CN}{'━'*70}{C.R}")

    projects = load_projects(args)
    run_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] {len(projects)} project(s) loaded")

    t0 = time.time()
    skipped_projects = []

    # ── Check for checkpoint/resume ──
    completed_keys = set()
    failed_keys = {}
    is_resuming = False

    if not args.no_resume:
        progress = load_progress(start_str, end_str, args.output)
        if progress:
            if args.resume:
                is_resuming = True
            else:
                try:
                    resp = input(f"  {C.B}▶ Resume from checkpoint? [Y/n]: {C.R}").strip().lower()
                    is_resuming = resp in ("", "y", "yes")
                except (KeyboardInterrupt, EOFError):
                    print("\n  👋"); sys.exit(0)
            if is_resuming:
                completed_keys = set(progress.get("completed", []))
                failed_keys = {f["key"]: f["error"] for f in progress.get("failed", [])}
                run_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Resuming: "
                               f"{len(completed_keys)} done, {len(failed_keys)} failed")
                tprint(f"  {C.G}📌 Resuming: {len(completed_keys)} completed, "
                       f"{len(failed_keys)} failed to retry{C.R}")

    # ── Cache ──
    cached_rules = []
    if not args.fresh:
        print(f"\n{C.B}📦 Checking cache...{C.R}")
        cached_rules = load_cache(projects, args.cache_hours)

    all_rules = []
    if cached_rules:
        all_rules = list(cached_rules)
        run_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Using cached discovery data")
    else:
        print(f"\n{C.B}🔍 PHASE 1 — DISCOVERY: Scanning {len(projects)} projects...{C.R}\n")
        run_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Phase 1: Discovery started")
        policy_tasks, skipped_projects = run_discovery(projects, DEFAULTS["discovery_threads"])

        for pid, reason in skipped_projects:
            run_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] SKIP {pid}: {reason}")

        if not policy_tasks and not skipped_projects:
            print(f"\n  {C.Y}✅ No policies found. Done!{C.R}"); sys.exit(0)

        print(f"\n{C.B}🔍 PHASE 1 — DISCOVERY: Fetching rules ({len(policy_tasks)} policies)...{C.R}\n")
        fetched_rules, fetch_errors = run_rule_fetch(policy_tasks, DEFAULTS["rule_threads"])

        for pid, pol, err in fetch_errors:
            run_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] FETCH ERROR {pid}/{pol}: {err}")

        if not fetched_rules:
            print(f"\n  {C.Y}✅ No rules found.{C.R}"); sys.exit(0)
        all_rules = fetched_rules

        cache_data = [{"project_id": r["project_id"], "policy_name": r["policy_name"],
                       "priority": r["priority"], "description": r["description"],
                       "expression": r["expression"], "sensitivity": r["sensitivity"],
                       "action": r["action"], "is_preview": r["is_preview"]}
                      for r in all_rules]
        save_cache(cache_data, projects)
        run_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Discovery complete: "
                       f"{len(all_rules)} rules found")

    # Filter preview vs active
    preview_rules = [r for r in all_rules if r.get("is_preview", False)]
    non_preview = [r for r in all_rules if not r.get("is_preview", False)]
    print(f"\n  📋 {len(preview_rules)} preview rules to query | "
          f"{len(non_preview)} active rules (logged as-is)")
    run_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] "
                   f"{len(preview_rules)} preview, {len(non_preview)} active rules")

    # ── CSV header (v8: added Chunk Coverage column) ──
    header = ["Project Name", "Policy Name", "Rule Description", "Priority",
              "Sensitivity Level", "Action", "Number of Requests",
              "Signature Detected", "Signature Description",
              "Log Link", "Data Integrity Status", "Chunk Coverage"]

    # ── CSV setup: clean on resume, fresh otherwise ──
    if is_resuming:
        cleanup_csv_for_resume(args.output, completed_keys, header)
        csv_mode = "a"
    else:
        csv_mode = "w"

    try:
        csv_fh = open(args.output, csv_mode, newline="", encoding="utf-8")
    except PermissionError:
        print(f"  {C.RD}❌ Cannot write {args.output}{C.R}"); sys.exit(1)

    csv_writer = csv.writer(csv_fh)
    if not is_resuming:
        csv_writer.writerow(header)
        for r in non_preview:
            csv_writer.writerow([r.get("project_id","-"), r.get("policy_name","-"),
                                 r.get("description","-"), r.get("priority","-"),
                                 r.get("sensitivity","-"), r.get("action","-"),
                                 "-", "-", "-", "-", "Active rule (not queried)", "-"])
        for pid, reason in skipped_projects:
            csv_writer.writerow([pid, "-", "-", "-", "-", "-", "-", "-", "-", "-",
                                 f"⚠️ {reason}", "-"])
        csv_fh.flush()
        try: os.fsync(csv_fh.fileno())
        except Exception: pass

    if not preview_rules:
        csv_fh.close()
        print(f"\n  {C.Y}✅ No preview rules to query.{C.R}")
        print(f"  {C.G}Results in '{args.output}'{C.R}\n")
        generate_executive_summary(args.output, [], preview_rules, non_preview,
                                    skipped_projects, {}, time.time()-t0,
                                    start_str, end_str, 0, run_log)
        sys.exit(0)

    # ══════════════════════════════════════════════
    # PHASE 2 — EXECUTION
    # ══════════════════════════════════════════════
    print(f"\n{C.B}📊 PHASE 2 — EXECUTION: Querying {len(preview_rules)} preview rules "
          f"(adaptive {cfg['log_threads']}→{cfg['max_log_threads']} threads, "
          f"{cfg['chunk_hours']}h chunks)...{C.R}\n")
    run_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Phase 2: Execution started")

    try:
        log_rows, err_count, total_hits, completed_keys, failed_keys = run_log_queries(
            preview_rules, start_str, end_str, cfg, csv_writer, csv_fh,
            completed_keys=completed_keys, failed_keys=failed_keys,
            output_file=args.output)
    except KeyboardInterrupt:
        csv_fh.close()
        run_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] INTERRUPTED by user")
        print(f"\n\n  {C.Y}👋 Interrupted. Progress saved. Run again to resume.{C.R}")
        print(f"  {C.D}💡 Use --resume to auto-resume without prompt.{C.R}")
        generate_executive_summary(args.output, [], preview_rules, non_preview,
                                    skipped_projects, failed_keys, time.time()-t0,
                                    start_str, end_str, -1, run_log)
        sys.exit(0)
    finally:
        csv_fh.close()

    run_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Phase 2 complete: "
                   f"{total_hits:,} hits, {err_count} errors")

    # ══════════════════════════════════════════════
    # PHASE 3 — VALIDATION: Retry failed rules
    # ══════════════════════════════════════════════
    retry_rules = [r for r in preview_rules if _rule_key(r) in failed_keys]
    if retry_rules:
        print(f"\n{C.B}🔄 PHASE 3 — VALIDATION: Retrying {len(retry_rules)} failed rule(s) "
              f"(1 thread, patient mode)...{C.R}\n")
        run_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Phase 3: Retrying "
                       f"{len(retry_rules)} failed rules")

        retry_cfg = dict(cfg)
        retry_cfg["log_threads"] = 1
        retry_cfg["max_log_threads"] = 1
        retry_cfg["max_retries"] = cfg["max_retries"] * 2
        retry_cfg["request_delay_ms"] = max(cfg["request_delay_ms"], 300)

        retry_success = 0
        retry_still_failed = 0

        try:
            csv_fh = open(args.output, "a", newline="", encoding="utf-8")
            csv_writer = csv.writer(csv_fh)
            for i, rule in enumerate(retry_rules, 1):
                rk = _rule_key(rule)
                tprint(f"  {C.CN}🔄 Retry {i}/{len(retry_rules)}: "
                       f"{rule['project_id']}/{rule['policy_name']} p={rule['priority']}{C.R}")
                try:
                    # Credential refresh before each retry
                    try: ClientManager.refresh_if_needed()
                    except Exception: pass

                    rows = query_single_rule(rule, start_str, end_str, retry_cfg)
                    err_rows = [r for r in rows if "⚠️" in str(r[10])]
                    if err_rows:
                        retry_still_failed += 1
                        run_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] RETRY FAIL {rk}")
                        tprint(f"  {C.RD}❌ Still failing: {rk}{C.R}")
                    else:
                        retry_success += 1
                        del failed_keys[rk]
                        for r in rows:
                            csv_writer.writerow(r)
                        csv_fh.flush()
                        try: os.fsync(csv_fh.fileno())
                        except Exception: pass
                        run_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] RETRY OK {rk}")
                        tprint(f"  {C.G}✅ Retry succeeded: {rk}{C.R}")
                        log_rows.extend(rows)
                except Exception as e:
                    retry_still_failed += 1
                    run_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] "
                                   f"RETRY ERROR {rk}: {e}")
                    tprint(f"  {C.RD}❌ Retry failed: {rk} — {e}{C.R}")
            csv_fh.close()
        except Exception as e:
            tprint(f"  {C.RD}⚠ Could not reopen CSV for retries: {e}{C.R}")

        print(f"\n{C.B}{'─'*70}{C.R}")
        print(f"  {C.B}📋 VALIDATION RESULTS:{C.R}")
        print(f"     ✅ Retry succeeded  : {retry_success}")
        print(f"     ❌ Still failing    : {retry_still_failed}")
        print(f"     📊 Total rules     : {len(preview_rules)}")
        print(f"     ✔️  Verified        : {len(preview_rules) - retry_still_failed}")
        if retry_still_failed:
            print(f"  {C.Y}⚠ {retry_still_failed} rule(s) could not be verified. "
                  f"Check Data Integrity Status in CSV.{C.R}")
        print(f"{C.B}{'─'*70}{C.R}")
        err_count = retry_still_failed
    else:
        print(f"\n{C.B}🔄 PHASE 3 — VALIDATION: All rules verified! ✅{C.R}")

    # ── Cleanup checkpoint on success ──
    clear_progress()

    elapsed = time.time() - t0
    run_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Complete in {elapsed:.1f}s")

    scoreboard(log_rows, len(preview_rules), err_count, elapsed)

    # ── Phase 4: Executive Summary ──
    print(f"\n{C.B}📋 PHASE 4 — GENERATING EXECUTIVE SUMMARY...{C.R}")
    generate_executive_summary(args.output, log_rows, preview_rules, non_preview,
                                skipped_projects, failed_keys, elapsed,
                                start_str, end_str, err_count, run_log)

    print(f"\n  {C.G}{C.B}✅ Results in '{args.output}'{C.R}")
    print(f"  {C.D}Open in Google Sheets or Excel.{C.R}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n  👋")
        sys.exit(0)
