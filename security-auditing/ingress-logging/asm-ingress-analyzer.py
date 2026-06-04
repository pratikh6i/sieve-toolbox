#!/usr/bin/env python3
"""
GCP Ingress Threat Analysis Tool — Production Hardened Edition

STRICTLY READ-ONLY: only uses Cloud Logging list_entries (read API).
Never writes/creates/deletes/modifies any GCP resource or configuration.

Production hardening fixes:
- GLOBAL rate limiter (Cloud Logging quota is per CONSUMER project, not target)
- High-water-mark on retries → no duplicate counting on transient errors
- Resume scrubs partial data from incomplete projects → no double counting across runs
- IPinfo 3-strike retry loop with Retry-After honored
- Cache only stores successful enrichments; purges expired/error entries
- URL counter capped per IP → no memory explosion in fuzzing/botnet scenarios
- snake_case + camelCase fallback in dict field extraction
"""

# ============================================================
# IMPORTS & CONSTANTS
# ============================================================
import os, sys, json, time, signal, ipaddress, logging, threading, tempfile, re, csv
import urllib.request, urllib.error, getpass
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from collections import defaultdict, Counter
from urllib.parse import quote

try:
    from google.cloud.logging_v2 import Client as LoggingClient
    from google.api_core import exceptions as gax_exceptions
    from google.auth import default as google_auth_default
except ImportError:
    sys.stderr.write("Missing deps. Run: pip install --user google-cloud-logging\n")
    sys.exit(1)

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
IST         = timezone(timedelta(hours=5, minutes=30))
RUN_TIME    = datetime.now(IST)
OUTPUT_DIR  = os.path.join(SCRIPT_DIR, RUN_TIME.strftime("%Y-%m-%d"), RUN_TIME.strftime("%H-%M"))
os.makedirs(OUTPUT_DIR, exist_ok=True)

REPORT_CSV      = os.path.join(OUTPUT_DIR, "Security_Analysis_Data.csv")
REPORT_MD       = os.path.join(OUTPUT_DIR, "Security_Analysis_Report.md")
DEBUG_LOG       = os.path.join(OUTPUT_DIR, "debug.log")
CHECKPOINT_FILE = os.path.join(SCRIPT_DIR, ".asm_checkpoint.json")
IP_CACHE_FILE   = os.path.join(SCRIPT_DIR, ".ip_enrichment_cache.json")

PAGE_SIZE             = 1000
CHUNK_FLUSH           = 500
LOCAL_FLUSH_THRESH    = 2000
GLOBAL_RATE_PER_MIN   = 55       # SHARED across all workers (consumer-level quota is 60/min)
MAX_PROJECT_WORKERS   = 3        # Workers share the global quota; more workers ≠ faster
MAX_ENRICH_BATCH_SIZE = 50       # Conservative for IPinfo free tier
MAX_ENRICH_RETRIES    = 3
MAX_BACKOFF_SEC       = 120
INITIAL_BACKOFF       = 15
ENRICH_TIMEOUT        = 30
ENRICH_TTL_DAYS       = 7
MAX_URLS_PER_IP       = 50       # Prevents memory explosion in fuzzing/botnet scenarios
COMMON_METHODS        = ["GET", "POST", "PUT", "DELETE"]
IPINFO_BATCH_URL      = "https://api.ipinfo.io/batch/lite"

SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL = 0, 1, 2, 3, 4
SEV_LABELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

DEFAULT_ASM_WHITELIST = [
    "129.212.216.123", "129.212.216.90", "129.212.216.89", "139.59.218.177",
    "209.38.58.164",   "129.212.209.128","167.99.30.114",  "129.212.216.92",
    "129.212.209.139", "129.212.216.93", "209.38.59.242",  "209.38.59.244",
    "129.212.209.120", "129.212.209.184","129.212.209.236","129.212.209.242",
    "167.99.28.222",   "209.38.59.247",  "129.212.209.244","129.212.209.246",
    "209.38.59.248",   "129.212.209.250","139.59.217.230", "129.212.216.91",
    "163.47.9.62",     "209.38.59.241",  "146.190.203.249","209.38.59.249",
    "129.212.216.99",  "129.212.209.252","129.212.209.255",
]

HOSTING_PATTERNS = [
    "amazon", "amazonaws", "amazon technologies", "amazon data services",
    "google llc", "google cloud", "microsoft", "azure",
    "digitalocean", "digital ocean", "linode", "vultr", "ovh", "hetzner",
    "leaseweb", "contabo", "alibaba", "tencent cloud", "scaleway",
    "softlayer", "ibm cloud", "fastly", "akamai", "cloudflare",
    "oracle cloud", "rackspace", "hostgator", "godaddy", "namecheap",
    "datacenter", "data center", "vps", "vds", "dedicated server",
    "cloud server", "hosting", "host europe", "choopa", "psychz", "quadranet",
]

# ============================================================
# LOGGING SETUP
# ============================================================
logging.basicConfig(filename=DEBUG_LOG, filemode="a", level=logging.DEBUG,
                    format="%(asctime)s [%(levelname)s] %(message)s")
for noisy in ("google.auth", "google.auth.transport", "urllib3", "google.api_core"):
    logging.getLogger(noisy).setLevel(logging.WARNING)
log = logging.getLogger("asm")

# ============================================================
# GLOBAL RATE LIMITER (single shared instance)
# ============================================================
class GlobalRateLimiter:
    """
    Cloud Logging quota is enforced at the CONSUMER project level (60 reads/min),
    not at the target project level. When using user ADC credentials, ALL parallel
    workers share one quota bucket. A per-worker limiter does not work — confirmed
    empirically by the 429 storm logs.

    This limiter is a single shared instance enforcing GLOBAL_RATE_PER_MIN across
    all concurrent workers. With GLOBAL_RATE_PER_MIN=55, interval=1.09s between
    any two API calls — safely below the 60/min quota.
    """
    def __init__(self, calls_per_min=GLOBAL_RATE_PER_MIN):
        self._interval = 60.0 / calls_per_min
        self._last = 0.0
        self._lock = threading.Lock()
        self.total_acquires = 0

    def wait(self):
        with self._lock:
            now = time.time()
            gap = self._interval - (now - self._last)
            if gap > 0:
                time.sleep(gap)
                self._last = time.time()
            else:
                self._last = now
            self.total_acquires += 1

# ============================================================
# DASHBOARD
# ============================================================
class Dashboard:
    SPIN = "|/-\\"
    def __init__(self):
        self.lock = threading.Lock()
        self.active = {}; self.backoffs = {}
        self.done = 0; self.total = 0
        self.t_scanned = 0; self.t_matched = 0
        self.rate = 0.0; self.status = "starting"
        self._t0 = time.time(); self._stop = False; self._spin_i = 0
        self._t = threading.Thread(target=self._loop, daemon=True)
    def start(self): self._t.start()
    def stop(self):
        self._stop = True; time.sleep(0.25)
        sys.stdout.write("\n"); sys.stdout.flush()
    def set_total(self, n):
        with self.lock: self.total = n; self._t0 = time.time()
    def register_project(self, pid):
        with self.lock: self.active[pid] = {"scanned": 0, "matched": 0}
    def update_project(self, pid, scanned, matched):
        with self.lock:
            if pid in self.active:
                self.active[pid]["scanned"] += scanned
                self.active[pid]["matched"] += matched
            self.t_scanned += scanned; self.t_matched += matched
            self.rate = self.t_scanned / max(time.time() - self._t0, 0.001)
    def set_backoff(self, pid, secs):
        with self.lock: self.backoffs[pid] = time.time() + secs
    def clear_backoff(self, pid):
        with self.lock: self.backoffs.pop(pid, None)
    def finish_project(self, pid):
        with self.lock: self.active.pop(pid, None); self.backoffs.pop(pid, None); self.done += 1
    def set_status(self, s):
        with self.lock: self.status = s
    def _loop(self):
        while not self._stop:
            with self.lock:
                spin = self.SPIN[self._spin_i % len(self.SPIN)]; self._spin_i += 1
                now = time.time()
                parts = []
                for pid, info in list(self.active.items())[:3]:
                    bo_left = max(0, int(self.backoffs.get(pid, 0) - now))
                    suffix = f" ⏸{bo_left}s" if bo_left > 0 else ""
                    parts.append(f"{pid[:14]}{suffix}:{info['matched']:,}")
                if len(self.active) > 3:
                    parts.append(f"+{len(self.active)-3}more")
                active_str = "  ".join(parts) if parts else "idle"
                progress = f"done={self.done}/{self.total}" if self.total else ""
                sys.stdout.write(
                    f"\r{spin} {progress}  matched={self.t_matched:,}  "
                    f"{self.rate:,.0f}/s  [{active_str}]  {self.status}   "
                )
                sys.stdout.flush()
            time.sleep(0.2)

dash = Dashboard()

# ============================================================
# INTERACTIVE INPUT
# ============================================================
def parse_timeframe():
    print("\nTimeframe options:")
    print("  [1] Relative — e.g. '2d' for last 2 days, '10d' for last 10 days")
    print("  [2] Absolute — start/end timestamps in IST")
    choice = input("Choose [1/2, Default: 1]: ").strip() or "1"
    if choice == "1":
        raw = input("Enter how many days back (e.g. 2d, 10d): ").strip().lower()
        m = re.fullmatch(r"(\d+)d", raw)
        if not m: sys.exit("Bad format. Use like '2d' or '10d'.")
        days = int(m.group(1))
        if days <= 0 or days > 30: sys.exit("Days must be 1–30.")
        end_utc = datetime.now(timezone.utc)
        start_utc = end_utc - timedelta(days=days)
        print(f"  → Range (IST): {start_utc.astimezone(IST).strftime('%Y-%m-%d %H:%M:%S')}  →  {end_utc.astimezone(IST).strftime('%Y-%m-%d %H:%M:%S')}")
        return start_utc, end_utc
    s = input("Enter Start IST (YYYY-MM-DD HH:MM:SS): ").strip()
    e = input("Enter End   IST (YYYY-MM-DD HH:MM:SS): ").strip()
    try:
        s_l = datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=IST)
        e_l = datetime.strptime(e, "%Y-%m-%d %H:%M:%S").replace(tzinfo=IST)
    except ValueError: sys.exit("Bad timestamp format.")
    if e_l <= s_l: sys.exit("End must be after start.")
    return s_l.astimezone(timezone.utc), e_l.astimezone(timezone.utc)

def prompt_inputs():
    print("=" * 76)
    print(" GCP INGRESS SECURITY ANALYZER  —  Hardened Edition  —  READ-ONLY")
    print("=" * 76)
    print(f"  Output : {OUTPUT_DIR}")
    print(f"  Quota  : GLOBAL {GLOBAL_RATE_PER_MIN}/min shared across all workers")
    print(f"           (Cloud Logging quota is consumer-level, not per target project)")
    print("-" * 76)
    raw = input("Enter comma-separated GCP Project IDs: ").strip()
    projects = [p.strip() for p in raw.split(",") if p.strip()]
    if not projects: sys.exit("No projects provided.")

    print(f"\nUsing {len(DEFAULT_ASM_WHITELIST)} hardcoded ASM whitelisted IPs.")
    extra = input("Add any additional ASM IPs/CIDRs? (comma-separated, blank = none): ").strip()
    raw_list = list(DEFAULT_ASM_WHITELIST)
    if extra: raw_list.extend([w.strip() for w in extra.split(",") if w.strip()])
    whitelist = []
    for ent in raw_list:
        try: whitelist.append(ipaddress.ip_network(ent, strict=False))
        except ValueError: print(f"  ! Skipping invalid: {ent}")

    start_utc, end_utc = parse_timeframe()

    workers_in = input(f"\nConcurrent project workers [1–{MAX_PROJECT_WORKERS+2}, Default: {MAX_PROJECT_WORKERS}]: ").strip()
    try: num_workers = max(1, min(MAX_PROJECT_WORKERS+2, int(workers_in))) if workers_in else MAX_PROJECT_WORKERS
    except ValueError: num_workers = MAX_PROJECT_WORKERS

    url_flag = input("\nCapture exact request URLs? [Y/N, Default: N]: ").strip().lower()
    capture_urls = url_flag in ("y", "yes")

    print("\nIP enrichment via IPinfo Lite (FREE tier — https://ipinfo.io/signup)")
    print("Token is held in memory only; never written to disk.")
    token = getpass.getpass("Enter IPinfo API token (hidden; blank = skip enrichment): ").strip()
    if not token:
        print("  ! No token provided — enrichment will be skipped for uncached IPs.")
    else:
        print(f"  ✓ Token captured ({len(token)} chars).")

    return {
        "projects": projects, "whitelist": whitelist, "whitelist_raw": raw_list,
        "start_utc": start_utc, "end_utc": end_utc,
        "capture_urls": capture_urls, "num_workers": num_workers,
        "ipinfo_token": token,
    }

# ============================================================
# CHECKPOINT (atomic + scrub on resume)
# ============================================================
def atomic_save(path, data):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".ckpt_", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, default=str); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp): os.unlink(tmp)
        raise

def load_checkpoint():
    if not os.path.exists(CHECKPOINT_FILE): return None
    try:
        with open(CHECKPOINT_FILE) as f: return json.load(f)
    except Exception as e:
        log.warning(f"Cannot read checkpoint: {e}"); return None

def maybe_resume():
    """FIXED: Scrubs any partial data from projects that did NOT fully complete."""
    ck = load_checkpoint()
    if not ck or not ck.get("completed"): return None
    print(f"\nFound checkpoint from {ck.get('saved_at')}")
    print(f"  Completed projects: {ck.get('completed')}")
    ans = input("Resume from last successful project? [Y/n, n=fresh start]: ").strip().lower()
    if ans not in ("", "y", "yes"):
        try: os.unlink(CHECKPOINT_FILE)
        except OSError: pass
        return None

    # ▶ Scrub data from non-completed projects to prevent duplicate accumulation
    completed = set(ck["completed"])
    cleaned_agg = {}
    for k_str, data in (ck.get("agg") or {}).items():
        parts = k_str.split("|", 1)
        if len(parts) != 2: continue
        if parts[0] in completed:
            cleaned_agg[k_str] = data
    scrubbed = len(ck.get("agg") or {}) - len(cleaned_agg)
    if scrubbed > 0:
        print(f"  ⚙ Scrubbed {scrubbed} partial row(s) from non-completed projects (prevents double-counting)")
        log.info(f"Resume: scrubbed {scrubbed} partial rows from non-completed projects")
    ck["agg"] = cleaned_agg
    return ck

# ============================================================
# IPINFO LITE BATCH ENRICHER (hardened)
# ============================================================
class IPinfoEnricher:
    """
    HARDENED:
    - Retry loop (3 attempts) for 429/5xx with exponential backoff + Retry-After honored
    - Error responses are NOT cached (so they retry next run)
    - Cache save purges expired entries and any stray error entries
    - Cache load filters out error entries from prior runs
    """
    def __init__(self, cache_file, token):
        self.cache_file = cache_file
        self.token = token
        self._lock = threading.Lock()
        self.cache = self._load_cache_clean()

    def _load_cache_clean(self):
        """Load and immediately drop any error entries from prior runs."""
        if not os.path.exists(self.cache_file): return {}
        try:
            with open(self.cache_file) as f:
                raw = json.load(f)
            # Filter out error entries → they get retried this run
            cleaned = {
                ip: entry for ip, entry in raw.items()
                if isinstance(entry, dict)
                and "error" not in (entry.get("data") or {})
            }
            removed = len(raw) - len(cleaned)
            if removed > 0:
                log.info(f"IP cache: dropped {removed} stale error entries on load (will retry)")
            return cleaned
        except Exception:
            return {}

    def _save_cache(self):
        """Purge expired & error entries from BOTH memory and disk before persisting."""
        now = time.time()
        with self._lock:
            cleaned = {}
            for ip, entry in self.cache.items():
                data = entry.get("data") or {}
                if "error" in data:
                    continue  # never persist errors
                age_days = (now - entry.get("ts", 0)) / 86400
                if age_days >= ENRICH_TTL_DAYS:
                    continue  # purge expired
                cleaned[ip] = entry
            self.cache = cleaned  # purge in-memory too
            try:
                d = os.path.dirname(self.cache_file) or "."
                fd, tmp = tempfile.mkstemp(prefix=".cache_", dir=d)
                with os.fdopen(fd, "w") as f:
                    json.dump(self.cache, f, indent=2, default=str)
                os.replace(tmp, self.cache_file)
            except Exception as e:
                log.warning(f"Cache save failed: {e}")

    def _cached_valid(self, ip):
        if ip not in self.cache: return False
        data = self.cache[ip].get("data") or {}
        if "error" in data: return False
        age_days = (time.time() - self.cache[ip].get("ts", 0)) / 86400
        return age_days < ENRICH_TTL_DAYS

    def _check_private(self, ip):
        try:
            o = ipaddress.ip_address(ip)
            if o.is_private or o.is_reserved or o.is_loopback:
                return {"country": "Internal", "country_code": "",
                        "asn": "", "as_name": "Internal/Private",
                        "as_domain": "", "continent": "", "continent_code": ""}
        except ValueError:
            return {"error": "invalid_ip"}
        return None

    def enrich_all(self, ips):
        results = {}
        need_api = []
        for ip in ips:
            priv = self._check_private(ip)
            if priv is not None:
                if "error" not in priv:
                    with self._lock:
                        self.cache[ip] = {"ts": time.time(), "data": priv}
                results[ip] = priv
                continue
            if self._cached_valid(ip):
                results[ip] = self.cache[ip]["data"]
            else:
                need_api.append(ip)
        log.info(f"Enrichment: {len(results)} cached/private, {len(need_api)} need API")

        if not need_api:
            return results
        if not self.token:
            log.warning("No IPinfo token — uncached IPs unavailable for enrichment")
            for ip in need_api:
                results[ip] = {"error": "no_token"}
            return results

        total_batches = (len(need_api) + MAX_ENRICH_BATCH_SIZE - 1) // MAX_ENRICH_BATCH_SIZE
        batch_idx = 0
        success_batches = 0
        for i in range(0, len(need_api), MAX_ENRICH_BATCH_SIZE):
            batch = need_api[i:i + MAX_ENRICH_BATCH_SIZE]
            batch_idx += 1
            dash.set_status(f"IPinfo batch {batch_idx}/{total_batches} ({len(batch)} IPs)")
            response = self._call_batch_with_retry(batch)
            if response is None:
                # All retries exhausted - mark these IPs as failed BUT don't cache the error
                for ip in batch:
                    results[ip] = {"error": "api_failed_after_retries"}
                continue
            success_batches += 1
            for ip in batch:
                ip_data = response.get(ip)
                if ip_data and isinstance(ip_data, dict) and "error" not in ip_data:
                    norm = {
                        "country":        ip_data.get("country") or "",
                        "country_code":   ip_data.get("country_code") or "",
                        "asn":            (ip_data.get("asn") or "").replace("AS", ""),
                        "as_name":        ip_data.get("as_name") or "",
                        "as_domain":      ip_data.get("as_domain") or "",
                        "continent":      ip_data.get("continent") or "",
                        "continent_code": ip_data.get("continent_code") or "",
                    }
                    # ▶ Only cache successful enrichments
                    with self._lock:
                        self.cache[ip] = {"ts": time.time(), "data": norm}
                    results[ip] = norm
                else:
                    results[ip] = {"error": "not_in_response"}
            # Persist progress periodically (also purges expired/errors)
            if batch_idx % 5 == 0:
                self._save_cache()
            time.sleep(0.3)

        self._save_cache()
        log.info(f"Enrichment complete: {success_batches}/{total_batches} batches OK")
        return results

    def _call_batch_with_retry(self, ip_list):
        """3-strike retry loop, honors Retry-After header on 429."""
        backoff = 10
        for attempt in range(1, MAX_ENRICH_RETRIES + 1):
            try:
                data = json.dumps(ip_list).encode("utf-8")
                req = urllib.request.Request(
                    IPINFO_BATCH_URL,
                    data=data,
                    headers={
                        "Authorization": f"Bearer {self.token}",
                        "Content-Type": "application/json",
                        "User-Agent": "gcp-asm-analyzer/4.0",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=ENRICH_TIMEOUT) as resp:
                    return json.loads(resp.read())

            except urllib.error.HTTPError as e:
                err_body = ""
                try: err_body = e.read().decode()[:200]
                except Exception: pass
                if e.code == 429:
                    # Honor Retry-After header if present
                    retry_after = e.headers.get("Retry-After") if hasattr(e, "headers") and e.headers else None
                    if retry_after:
                        try:
                            wait = min(int(retry_after), 120)
                            log.warning(f"IPinfo 429 attempt {attempt}/{MAX_ENRICH_RETRIES}: Retry-After={wait}s")
                            time.sleep(wait)
                        except ValueError:
                            time.sleep(backoff)
                    else:
                        log.warning(f"IPinfo 429 attempt {attempt}/{MAX_ENRICH_RETRIES}: sleeping {backoff}s")
                        time.sleep(backoff)
                    backoff = min(backoff * 2, 120)
                    continue
                elif e.code in (401, 403):
                    log.error(f"IPinfo auth error {e.code} (will not retry): {err_body}")
                    return None
                elif 500 <= e.code < 600:
                    log.warning(f"IPinfo {e.code} attempt {attempt}/{MAX_ENRICH_RETRIES}: sleeping {backoff}s")
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 120)
                    continue
                else:
                    log.error(f"IPinfo HTTP {e.code}: {err_body}")
                    return None
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                log.warning(f"IPinfo network error attempt {attempt}/{MAX_ENRICH_RETRIES}: {e}")
                time.sleep(backoff)
                backoff = min(backoff * 2, 120)
                continue
            except Exception as e:
                log.error(f"IPinfo unexpected error attempt {attempt}/{MAX_ENRICH_RETRIES}: {e}")
                time.sleep(backoff)
                backoff = min(backoff * 2, 120)
                continue
        log.error(f"IPinfo batch failed after {MAX_ENRICH_RETRIES} attempts; will retry on next run (errors NOT cached)")
        return None

# ============================================================
# ANALYSIS HELPERS
# ============================================================
def is_hosting_origin(enr):
    if not enr or "error" in enr: return False
    text = f"{enr.get('as_name', '')} {enr.get('as_domain', '')}".lower()
    return any(p in text for p in HOSTING_PATTERNS)

def has_valid_enrichment(enrichments, ips):
    if not enrichments: return False
    for ip in ips:
        d = enrichments.get(ip, {})
        if not d or "error" in d: continue
        if d.get("country") and d["country"] != "Internal":
            return True
    return False

def status_bucket(s):
    if 200 <= s < 300: return "2xx"
    if 300 <= s < 400: return "3xx"
    if 400 <= s < 500: return "4xx"
    if 500 <= s < 600: return "5xx"
    return "other"

def primary_rule_label(flags):
    if not flags: return "Normal"
    priority = [
        ("waf_majority_blocked", "WAF Majority Block"),
        ("path_scanning",        "Path Scanning"),
        ("auth_probing",         "Auth Probing"),
        ("waf_blocks",           "WAF Blocks"),
        ("very_high_volume",     "Sustained Very High Volume"),
        ("high_volume",          "High Volume"),
        ("high_error_rate",      "High Error Rate"),
        ("hosting_ip",           "Hosting/Datacenter Origin"),
        ("post_heavy",           "POST-Heavy Traffic"),
        ("404_anomaly",          "404 Anomaly"),
        ("elevated_error_rate",  "Elevated Errors"),
        ("elevated_volume",      "Elevated Volume"),
        ("asm_whitelisted",      "ASM Whitelisted"),
        ("normal_traffic",       "Normal Activity"),
    ]
    for prefix, label in priority:
        if any(f.startswith(prefix) for f in flags):
            return label
    return flags[0]

def security_state(agg):
    total = agg["hits"]
    if total == 0: return "❔ No Data"
    s_known = sum(c for s, c in agg["statuses"].items() if s > 0)
    if s_known == 0: return "❔ Unknown"
    s2xx = sum(c for s, c in agg["statuses"].items() if 200 <= s < 300)
    if s2xx / s_known >= 0.10:
        return "🔴 Allowed"
    return "🛡️ Blocked"

def categorize_finding(agg, sev):
    if sev < SEV_HIGH: return None
    total = agg["hits"]
    s2xx  = sum(c for s, c in agg["statuses"].items() if 200 <= s < 300)
    s401  = agg["statuses"].get(401, 0)
    if s2xx >= 10:      return "A"
    if s401 >= 20:      return "A"
    if total >= 10000:  return "A"
    return "B"

def status_mix_str(agg, top=5):
    items = sorted(agg["statuses"].items(), key=lambda x: -x[1])[:top]
    return "; ".join(f"{s}= {c:,}" for s, c in items)

def operational_status(global_agg, analyses):
    has_threats = False; action_required = False
    for key, (sev, label, flags) in analyses.items():
        agg = global_agg[key]
        if agg["category"] != "Threat" or sev < SEV_HIGH: continue
        has_threats = True
        s2xx = sum(c for s, c in agg["statuses"].items() if 200 <= s < 300)
        s401 = agg["statuses"].get(401, 0)
        if s2xx >= 10 or s401 >= 20 or agg["hits"] >= 10000:
            action_required = True
            break
    if action_required:
        return ("🔴 ACTION REQUIRED",
                "Active threats with allowed responses, credential probing, or sustained very high volume detected. Immediate review required.")
    elif has_threats:
        return ("🟢 DEFENDED / NOMINAL",
                "Threats observed but successfully blocked by WAF / Cloud Armor. Defenses operating as designed.")
    else:
        return ("🟢 NOMINAL",
                "No critical threat activity in this window. Normal traffic patterns observed.")

# ============================================================
# THREAT ANALYZER (unchanged)
# ============================================================
def analyze_threat(agg, enr):
    if agg["category"] == "ASM":
        return SEV_INFO, "INFO", ["asm_whitelisted"]
    sev = SEV_INFO; flags = []
    hits = agg["hits"]; st = agg["statuses"]
    s2xx = sum(c for s, c in st.items() if 200 <= s < 300)
    s3xx = sum(c for s, c in st.items() if 300 <= s < 400)
    s4xx = sum(c for s, c in st.items() if 400 <= s < 500)
    s5xx = sum(c for s, c in st.items() if 500 <= s < 600)
    s403 = st.get(403, 0); s404 = st.get(404, 0); s401 = st.get(401, 0)
    total_known = s2xx + s3xx + s4xx + s5xx
    if hits >= 10000:    flags.append(f"very_high_volume:{hits}"); sev = max(sev, SEV_CRITICAL)
    elif hits >= 1000:   flags.append(f"high_volume:{hits}");      sev = max(sev, SEV_HIGH)
    elif hits >= 100:    flags.append(f"elevated_volume:{hits}");  sev = max(sev, SEV_MEDIUM)
    if s403 >= 100 and total_known > 0 and (s403 / total_known) >= 0.5:
        flags.append(f"waf_majority_blocked:{s403}"); sev = max(sev, SEV_CRITICAL)
    elif s403 >= 50:
        flags.append(f"waf_blocks:{s403}"); sev = max(sev, SEV_HIGH)
    if s404 >= 50 and total_known > 0 and (s404 / total_known) >= 0.3:
        flags.append(f"path_scanning:{s404}"); sev = max(sev, SEV_HIGH)
    elif s404 >= 20:
        flags.append(f"404_anomaly:{s404}"); sev = max(sev, SEV_MEDIUM)
    if s401 >= 20:
        flags.append(f"auth_probing:{s401}"); sev = max(sev, SEV_MEDIUM)
    if total_known >= 100:
        err_rate = (s4xx + s5xx) / total_known
        if err_rate >= 0.8:   flags.append(f"high_error_rate:{err_rate:.0%}"); sev = max(sev, SEV_HIGH)
        elif err_rate >= 0.5: flags.append(f"elevated_error_rate:{err_rate:.0%}"); sev = max(sev, SEV_MEDIUM)
    if is_hosting_origin(enr):
        flags.append("hosting_ip"); sev = max(sev, SEV_MEDIUM)
    m = agg["methods"]
    if m.get("POST", 0) >= 100 and m.get("POST", 0) > m.get("GET", 0) * 2:
        flags.append(f"post_heavy:{m['POST']}"); sev = max(sev, SEV_MEDIUM)
    if not flags: flags = ["normal_traffic"]
    return sev, SEV_LABELS[sev], flags

# ============================================================
# FIELD EXTRACTION (with snake_case fallback)
# ============================================================
def _hr_get(http_req, k_camel, k_snake):
    """Robust dict-or-object getter. For dicts, tries camelCase first then snake_case."""
    if http_req is None: return None
    if isinstance(http_req, dict):
        if k_camel in http_req: return http_req[k_camel]
        if k_snake in http_req: return http_req[k_snake]
        return None
    # Object form
    return getattr(http_req, k_snake, None) or getattr(http_req, k_camel, None)

def extract_remote_ip(entry):
    http_req = getattr(entry, "http_request", None)
    ip = _hr_get(http_req, "remoteIp", "remote_ip")
    if ip: return ip
    payload = getattr(entry, "payload", None)
    if isinstance(payload, dict):
        ip = payload.get("remoteIp") or payload.get("remote_ip")
        if ip: return ip
        xff = payload.get("X-Forwarded-For") or payload.get("x-forwarded-for")
        if xff:
            first = str(xff).split(",")[0].strip()
            if first: return first
    return None

def extract_http_fields(entry):
    http_req = getattr(entry, "http_request", None)
    method = _hr_get(http_req, "requestMethod", "request_method") or "UNKNOWN"
    raw_status = _hr_get(http_req, "status", "status")
    try: status = int(raw_status) if raw_status else 0
    except (TypeError, ValueError): status = 0
    url = _hr_get(http_req, "requestUrl", "request_url") or ""
    if method == "UNKNOWN" or status == 0 or not url:
        payload = getattr(entry, "payload", None)
        if isinstance(payload, dict):
            if method == "UNKNOWN":
                method = payload.get("requestMethod") or payload.get("request_method") or method
            if status == 0:
                try: status = int(payload.get("statusCode") or payload.get("status") or 0)
                except (TypeError, ValueError): pass
            if not url:
                url = payload.get("requestUrl") or payload.get("request_url") or url
    return method, status, url

def extract_timestamp(entry):
    ts = getattr(entry, "timestamp", None)
    if ts is None: return None
    if isinstance(ts, datetime):
        return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts
    if isinstance(ts, str):
        try: return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError: return None
    return None

def classify_ip(ip_str, whitelist):
    try: ip = ipaddress.ip_address(ip_str)
    except ValueError: return "Threat"
    for net in whitelist:
        if ip in net: return "ASM"
    return "Threat"

# ============================================================
# AGGREGATION
# ============================================================
def new_agg():
    return {
        "category": None, "hits": 0,
        "methods": defaultdict(int), "statuses": defaultdict(int),
        "urls": defaultdict(int), "first_seen": None, "last_seen": None,
        "validation": "OK",
    }

def merge_chunk(target, src):
    """Associative merge — same result regardless of order. Critical for parallel correctness."""
    for key, d in src.items():
        g = target.setdefault(key, new_agg())
        g["category"] = d["category"]
        g["hits"] += d["hits"]
        for m, c in d["methods"].items():  g["methods"][m] += c
        for s, c in d["statuses"].items(): g["statuses"][s] += c
        # URL cap maintained during merge as well
        for u, c in d["urls"].items():
            if u in g["urls"] or len(g["urls"]) < MAX_URLS_PER_IP:
                g["urls"][u] += c
        if d["first_seen"] and (g["first_seen"] is None or d["first_seen"] < g["first_seen"]):
            g["first_seen"] = d["first_seen"]
        if d["last_seen"] and (g["last_seen"] is None or d["last_seen"] > g["last_seen"]):
            g["last_seen"] = d["last_seen"]

# ============================================================
# STREAMING (high-water-mark prevents duplicate counting on retries)
# ============================================================
def stream_project(client, project_id, start_utc, end_utc, whitelist, capture_urls, rate_lim):
    """
    HARDENED:
    - order_by="timestamp asc" → entries come oldest-first → high-water mark is monotonic
    - On transient error, retry from max_seen_ts + 1us (no double counting)
    - URL counter capped per IP (MAX_URLS_PER_IP)
    """
    backoff = INITIAL_BACKOFF
    debug_logged = False
    max_seen_ts = None  # high-water mark — last successfully processed entry's timestamp

    while True:
        # Build filter from current high-water mark (or original start on first attempt)
        if max_seen_ts is not None:
            # Advance past the last seen entry (microsecond precision)
            effective_start = max_seen_ts + timedelta(microseconds=1)
            ts_fmt = effective_start.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            log.info(f"[{project_id}] resuming stream from {ts_fmt}")
        else:
            effective_start = start_utc
            ts_fmt = effective_start.strftime("%Y-%m-%dT%H:%M:%SZ")
        log_filter = (
            '(resource.type="http_load_balancer" OR resource.type="cloud_armor_security_policy") '
            f'timestamp>="{ts_fmt}" '
            f'timestamp<="{end_utc.strftime("%Y-%m-%dT%H:%M:%SZ")}"'
        )
        if max_seen_ts is None:
            log.info(f"[{project_id}] filter: {log_filter}")

        try:
            rate_lim.wait()  # Global rate limiter — shared across all workers
            entries_iter = client.list_entries(
                resource_names=[f"projects/{project_id}"],
                filter_=log_filter,
                page_size=PAGE_SIZE,
                order_by="timestamp asc",  # ▶ ascending for monotonic high-water mark
            )
            chunk_agg = {}; chunk_scanned = 0; chunk_matched = 0; entries_seen = 0

            for entry in entries_iter:
                chunk_scanned += 1; entries_seen += 1
                if entries_seen % PAGE_SIZE == 0:
                    rate_lim.wait()  # Throttle at each page boundary

                if not debug_logged:
                    try:
                        hr = getattr(entry, "http_request", None)
                        log.debug(f"[{project_id}] http_request type={type(hr).__name__}")
                        if isinstance(hr, dict):
                            log.debug(f"[{project_id}] http_request keys={list(hr.keys())}")
                    except Exception: pass
                    debug_logged = True

                # ▶ Update high-water mark BEFORE the entry could be processed
                ts = extract_timestamp(entry)
                if ts and (max_seen_ts is None or ts > max_seen_ts):
                    max_seen_ts = ts

                ip = extract_remote_ip(entry)
                if ip:
                    method, status, url = extract_http_fields(entry)
                    cat = classify_ip(ip, whitelist)
                    key = (project_id, ip)
                    a = chunk_agg.setdefault(key, new_agg())
                    a["category"] = cat
                    a["hits"] += 1
                    a["methods"][method] += 1
                    a["statuses"][status] += 1
                    if ts:
                        if a["first_seen"] is None or ts < a["first_seen"]: a["first_seen"] = ts
                        if a["last_seen"]  is None or ts > a["last_seen"]:  a["last_seen"]  = ts
                    # ▶ URL cap to prevent memory explosion
                    if capture_urls and url:
                        if url in a["urls"] or len(a["urls"]) < MAX_URLS_PER_IP:
                            a["urls"][url] += 1
                    chunk_matched += 1

                if chunk_scanned >= CHUNK_FLUSH:
                    dash.update_project(project_id, chunk_scanned, chunk_matched)
                    if chunk_agg: yield chunk_agg, False
                    chunk_agg = {}; chunk_scanned = 0; chunk_matched = 0

            if chunk_scanned > 0: dash.update_project(project_id, chunk_scanned, chunk_matched)
            if chunk_agg: yield chunk_agg, False
            yield {}, False
            return

        except gax_exceptions.ResourceExhausted as e:
            log.warning(f"[{project_id}] 429 quota (consumer-level shared limit): backoff {backoff}s")
            dash.set_backoff(project_id, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, MAX_BACKOFF_SEC)
            dash.clear_backoff(project_id)
            continue
        except (gax_exceptions.DeadlineExceeded, gax_exceptions.ServiceUnavailable,
                gax_exceptions.InternalServerError) as e:
            resume_from = max_seen_ts.isoformat() if max_seen_ts else "start"
            log.warning(f"[{project_id}] transient: {e}; backoff {backoff}s (will resume from {resume_from})")
            dash.set_backoff(project_id, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, MAX_BACKOFF_SEC)
            dash.clear_backoff(project_id)
            continue
        except gax_exceptions.PermissionDenied as e:
            log.error(f"[{project_id}] PermissionDenied: {e}"); yield {}, True; return
        except Exception as e:
            log.exception(f"[{project_id}] unrecoverable: {e}"); yield {}, True; return

# ============================================================
# PROJECT WORKER (uses shared global rate limiter; scrubs partial data on failure)
# ============================================================
def scan_project_worker(project_id, cfg, creds, shared, global_rate_lim):
    """
    HARDENED:
    - Uses SHARED global rate limiter (Cloud Logging quota is consumer-level)
    - On failure/incomplete, removes its partial data from shared agg before checkpoint
    - This means resume retries the project from scratch without double-counting
    """
    dash.register_project(project_id)
    log.info(f"[{project_id}] worker started")
    try:
        client = LoggingClient(project=project_id, credentials=creds)
    except Exception as e:
        log.error(f"[{project_id}] client creation failed: {e}")
        dash.finish_project(project_id); return project_id, False

    local_agg = {}; local_hits = 0
    project_incomplete = False; project_failed = False
    try:
        for chunk_agg, incomplete in stream_project(
            client, project_id, cfg["start_utc"], cfg["end_utc"],
            cfg["whitelist"], cfg["capture_urls"], global_rate_lim
        ):
            if chunk_agg:
                merge_chunk(local_agg, chunk_agg)
                local_hits += sum(v["hits"] for v in chunk_agg.values())
                if local_hits >= LOCAL_FLUSH_THRESH:
                    with shared["lock"]:
                        merge_chunk(shared["agg"], local_agg)
                    local_agg = {}; local_hits = 0
            if incomplete: project_incomplete = True
    except Exception as e:
        log.exception(f"[{project_id}] worker stream failed: {e}")
        project_failed = True

    # Final flush (only if successful — otherwise this would corrupt next-resume state)
    success = not project_failed and not project_incomplete
    if success and local_agg:
        try:
            with shared["lock"]:
                merge_chunk(shared["agg"], local_agg)
        except Exception as e:
            log.exception(f"[{project_id}] FINAL FLUSH FAILED: {e}")
            success = False

    # ▶ If this project failed/incomplete, SCRUB any partial data we contributed
    if not success:
        with shared["lock"]:
            keys_to_remove = [k for k in list(shared["agg"].keys()) if k[0] == project_id]
            for k in keys_to_remove:
                del shared["agg"][k]
            if keys_to_remove:
                log.warning(f"[{project_id}] failed — scrubbed {len(keys_to_remove)} partial rows so resume re-scans cleanly")

    with shared["lock"]:
        if success:
            shared["completed"].add(project_id)
        atomic_save(CHECKPOINT_FILE, {
            "saved_at":  datetime.now(timezone.utc).isoformat(),
            "completed": sorted(shared["completed"]),
            "agg":       serialize_agg(shared["agg"]),
        })
    dash.finish_project(project_id)
    log.info(f"[{project_id}] worker {'OK' if success else 'INCOMPLETE/FAILED — partial data scrubbed'}")
    return project_id, success

# ============================================================
# URL BUILDER
# ============================================================
def build_log_url(project_id, ip, start_utc, end_utc):
    hours = max(1, int((end_utc - start_utc).total_seconds() / 3600))
    query = (
        f'resource.type="http_load_balancer" AND '
        f'(jsonPayload.remoteIp="{ip}" OR httpRequest.remoteIp="{ip}")'
    )
    return (
        f"https://console.cloud.google.com/logs/query"
        f";query={quote(query, safe='')}"
        f";timeRange=PT{hours}H"
        f"?project={quote(project_id, safe='')}"
    )

# ============================================================
# CHECKPOINT SIGNAL
# ============================================================
def serialize_agg(global_agg):
    return {
        f"{k[0]}|{k[1]}": {
            "category": a["category"], "hits": a["hits"],
            "methods": dict(a["methods"]),
            "statuses": {str(s): c for s, c in a["statuses"].items()},
            "urls": dict(a["urls"]),
            "first_seen": a["first_seen"].isoformat() if a["first_seen"] else None,
            "last_seen":  a["last_seen"].isoformat()  if a["last_seen"]  else None,
            "validation": a["validation"],
        } for k, a in global_agg.items()
    }

def deserialize_agg(stored):
    out = {}
    for k_str, d in stored.items():
        parts = k_str.split("|", 1)
        if len(parts) != 2: continue
        key = (parts[0], parts[1])
        g = new_agg()
        g["category"]   = d.get("category")
        g["hits"]       = d.get("hits", 0)
        g["methods"]    = defaultdict(int, d.get("methods", {}))
        g["statuses"]   = defaultdict(int, {int(k): v for k, v in d.get("statuses", {}).items()})
        g["urls"]       = defaultdict(int, d.get("urls", {}))
        g["validation"] = d.get("validation", "OK")
        if d.get("first_seen"):
            try: g["first_seen"] = datetime.fromisoformat(d["first_seen"])
            except ValueError: pass
        if d.get("last_seen"):
            try: g["last_seen"] = datetime.fromisoformat(d["last_seen"])
            except ValueError: pass
        out[key] = g
    return out

# ============================================================
# CSV REPORT
# ============================================================
def fmt_eq(items, top=None):
    if top: items = items[:top]
    return "; ".join(f"{k}= {v}" for k, v in items)

def build_csv(global_agg, cfg, enrichments, analyses):
    start_utc, end_utc = cfg["start_utc"], cfg["end_utc"]
    total_hits  = sum(a["hits"] for a in global_agg.values())
    asm_hits    = sum(a["hits"] for a in global_agg.values() if a["category"] == "ASM")
    threat_hits = sum(a["hits"] for a in global_agg.values() if a["category"] == "Threat")
    metadata = [
        ["GCP INGRESS THREAT ANALYSIS — DATA EXPORT"], [],
        ["Field", "Value"],
        ["Report Generated (IST)",  datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")],
        ["Scan Window Start (IST)", start_utc.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S")],
        ["Scan Window End (IST)",   end_utc.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S")],
        ["Scan Duration (hours)",   str(round((end_utc - start_utc).total_seconds() / 3600, 2))],
        ["Projects Scanned",        ", ".join(cfg["projects"])],
        ["ASM Whitelist Count",     str(len(cfg["whitelist_raw"]))],
        ["ASM Whitelist (raw)",     ", ".join(cfg["whitelist_raw"])],
        ["Total Hits",              str(total_hits)],
        ["ASM Hits",                str(asm_hits)],
        ["Threat Hits",             str(threat_hits)],
        ["Unique (Project, IP) Rows", str(len(global_agg))],
        [],
    ]
    header = [
        "Project ID", "Remote IP", "Category", "Severity", "Threat Flags",
        "Country", "Country Code", "AS Name", "AS Domain", "ASN",
        "Total Hits", "GET", "POST", "PUT", "DELETE", "Other Methods",
        "2xx", "3xx", "4xx", "5xx", "Other Status",
        "Method Breakdown", "Status Breakdown",
        "First Seen (IST)", "Last Seen (IST)",
        "Security State", "Primary Rule", "GCP Log Link", "Validation Status",
    ]
    sorted_keys = sorted(global_agg.keys(), key=lambda k: (-analyses[k][0], -global_agg[k]["hits"]))
    with open(REPORT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=",", quotechar='"', quoting=csv.QUOTE_ALL)
        for row in metadata: w.writerow(row)
        w.writerow(header)
        for key in sorted_keys:
            pid, ip = key; a = global_agg[key]
            sev_int, sev_label, flags = analyses[key]
            enr = enrichments.get(ip, {}) or {}
            enr_ok = "error" not in enr
            mc = {m: a["methods"].get(m, 0) for m in COMMON_METHODS}
            other_m = sum(c for m, c in a["methods"].items() if m not in COMMON_METHODS)
            sb = defaultdict(int)
            for s, c in a["statuses"].items(): sb[status_bucket(s)] += c
            w.writerow([
                pid, ip, a["category"] or "Unknown", sev_label, " | ".join(flags),
                enr.get("country","") if enr_ok else "",
                enr.get("country_code","") if enr_ok else "",
                enr.get("as_name","") if enr_ok else "",
                enr.get("as_domain","") if enr_ok else "",
                enr.get("asn","") if enr_ok else "",
                a["hits"], mc["GET"], mc["POST"], mc["PUT"], mc["DELETE"], other_m,
                sb["2xx"], sb["3xx"], sb["4xx"], sb["5xx"], sb["other"],
                fmt_eq(sorted(a["methods"].items(),  key=lambda x: -x[1])),
                fmt_eq(sorted(a["statuses"].items(), key=lambda x: -x[1])),
                a["first_seen"].astimezone(IST).strftime("%Y-%m-%d %H:%M:%S") if a["first_seen"] else "",
                a["last_seen"].astimezone(IST).strftime("%Y-%m-%d %H:%M:%S")  if a["last_seen"]  else "",
                security_state(a), primary_rule_label(flags),
                build_log_url(pid, ip, start_utc, end_utc), a["validation"],
            ])

# ============================================================
# EXECUTIVE MARKDOWN REPORT
# ============================================================
def build_md(global_agg, cfg, enrichments, analyses):
    start_utc, end_utc = cfg["start_utc"], cfg["end_utc"]
    delta = end_utc - start_utc
    dur_str = f"{int(delta.total_seconds()/3600)} hours" if delta.days < 2 else f"{delta.days} days"

    total_hits  = sum(a["hits"] for a in global_agg.values())
    asm_hits    = sum(a["hits"] for a in global_agg.values() if a["category"] == "ASM")
    threat_hits = sum(a["hits"] for a in global_agg.values() if a["category"] == "Threat")
    sev_counts  = Counter(analyses[k][0] for k in global_agg)
    unique_ips  = len(set(k[1] for k in global_agg))
    asm_keys    = [k for k in global_agg if global_agg[k]["category"] == "ASM"]
    threat_keys = [k for k in global_agg if global_agg[k]["category"] == "Threat"]
    threat_ips  = set(k[1] for k in threat_keys)

    cat_a, cat_b = [], []
    for key in threat_keys:
        sev_i, _, _ = analyses[key]
        c = categorize_finding(global_agg[key], sev_i)
        if   c == "A": cat_a.append(key)
        elif c == "B": cat_b.append(key)
    cat_a.sort(key=lambda k: (-analyses[k][0], -global_agg[k]["hits"]))
    cat_b.sort(key=lambda k: (-analyses[k][0], -global_agg[k]["hits"]))

    total_403 = sum(a["statuses"].get(403, 0) for k, a in global_agg.items() if a["category"] == "Threat")
    total_4xx = sum(sum(c for s,c in a["statuses"].items() if 400<=s<500) for k,a in global_agg.items() if a["category"]=="Threat")
    enrichment_ok = has_valid_enrichment(enrichments, threat_ips)
    hosting_ips = set()
    if enrichment_ok:
        for key in threat_keys:
            if is_hosting_origin(enrichments.get(key[1])): hosting_ips.add(key[1])
    op_status, op_desc = operational_status(global_agg, analyses)

    L = []
    L.append("# 🛡️ INGRESS THREAT ANALYSIS")
    L.append("## Executive Security Report\n")
    L.append(f"# {op_status}")
    L.append(f"**{op_desc}**\n")
    L.append("| | |")
    L.append("|---|---|")
    L.append(f"| **Classification** | Internal — Security Operations |")
    L.append(f"| **Generated** | {RUN_TIME.strftime('%Y-%m-%d %H:%M IST')} |")
    L.append(f"| **Scan Window** | {start_utc.astimezone(IST).strftime('%Y-%m-%d %H:%M IST')} → {end_utc.astimezone(IST).strftime('%Y-%m-%d %H:%M IST')} ({dur_str}) |")
    L.append(f"| **Scope** | {', '.join(cfg['projects'])} ({len(cfg['projects'])} project{'s' if len(cfg['projects'])!=1 else ''}) |")
    L.append("\n---\n")

    L.append("## 1. Executive Summary\n")
    if total_hits == 0:
        L.append("_No ingress traffic recorded. Verify HTTP(S) Load Balancer logging is enabled for scoped projects._\n")
    else:
        L.append(f"During the {dur_str} reporting period, the production HTTP(S) Load Balancer fronting {len(cfg['projects'])} project(s) processed **{total_hits:,} requests** from **{unique_ips:,} unique source IPs**.\n")
        L.append(f"- **Authorized ASM scanners:** {asm_hits:,} requests ({asm_hits/max(total_hits,1)*100:.1f}%) from {len(set(k[1] for k in asm_keys))} whitelisted scanner IP(s).")
        L.append(f"- **External / unidentified traffic:** {threat_hits:,} requests ({threat_hits/max(total_hits,1)*100:.1f}%) from {len(threat_ips)} distinct source IPs.")
        if total_403 > 0:
            L.append(f"- **Cloud Armor / WAF** returned `403 Forbidden` to **{total_403:,} requests**, confirming active perimeter defense.")
        L.append(f"- **{len(cat_a)}** finding(s) require immediate action ({'see §3' if cat_a else 'none'}); **{len(cat_b)}** finding(s) were successfully mitigated by automated defenses ({'see §4' if cat_b else 'none'}).\n")
    L.append("\n---\n")

    L.append("## 2. Key Metrics\n")
    L.append("| Metric | Value | Security Context / Interpretation |")
    L.append("|---|---|---|")
    L.append(f"| Total Ingress Requests | **{total_hits:,}** | Total traffic reaching the load balancer in this window |")
    L.append(f"| Unique Source IPs | {unique_ips:,} | Source diversity baseline; high diversity from threats may indicate distributed attack |")
    L.append(f"| Authorized ASM Hits | {asm_hits:,} | Expected scanning activity from InfoSec — confirms ASM coverage is operational |")
    L.append(f"| External / Threat Hits | {threat_hits:,} | Traffic from non-whitelisted sources requiring scrutiny |")
    L.append(f"| CRITICAL Severity IPs | {sev_counts.get(SEV_CRITICAL,0)} | Sources demanding immediate triage and response |")
    L.append(f"| HIGH Severity IPs | {sev_counts.get(SEV_HIGH,0)} | Sources requiring review within current sprint |")
    L.append(f"| WAF Blocks (403) | {total_403:,} | Volume successfully denied at the perimeter — higher is better |")
    L.append(f"| 4xx Error Responses | {total_4xx:,} | Failed requests, often probing attempts; pattern indicator for reconnaissance |")
    if enrichment_ok:
        L.append(f"| Hosting/Datacenter Origin IPs | {len(hosting_ips)} | Threats from cloud/datacenter ASNs — legitimate end-users rarely originate here |")
    L.append("\n---\n")

    L.append("## 3. Critical Exposure Escalations — Action Required\n")
    L.append("_Threats where requests were allowed (2xx), authentication probing occurred (401), or sustained very high volume (≥10k) indicates persistent targeting. Each finding below requires Security Operations review._\n")
    if not cat_a:
        L.append("✅ **No critical exposures detected.** All severe threat activity was successfully contained by automated defenses.\n")
    else:
        for i, key in enumerate(cat_a[:10], 1):
            pid, ip = key; a = global_agg[key]; sev_i, sev_l, flags = analyses[key]
            enr = enrichments.get(ip, {}) or {}; enr_ok = enrichment_ok and "error" not in enr
            s2xx = sum(c for s, c in a["statuses"].items() if 200 <= s < 300)
            s4xx = sum(c for s, c in a["statuses"].items() if 400 <= s < 500)
            s401 = a["statuses"].get(401, 0)
            reasons = []
            if s2xx >= 10: reasons.append(f"**{s2xx:,} allowed responses (2xx)** — potential bypass")
            if s401 >= 20: reasons.append(f"**{s401:,} auth probes (401)** — credential attack pattern")
            if a["hits"] >= 10000: reasons.append(f"**{a['hits']:,} requests** — sustained targeting")
            L.append(f"### 🔴 Finding A-{i}: `{ip}` in `{pid}`  [{sev_l}]\n")
            L.append(f"**Why this requires action:** " + "; ".join(reasons) + "\n")
            L.append("| Attribute | Value |")
            L.append("|---|---|")
            L.append(f"| Source IP | `{ip}` |")
            L.append(f"| Project | `{pid}` |")
            if enr_ok:
                L.append(f"| Geolocation | {enr.get('country','Unknown')} |")
                asn = enr.get('asn',''); as_name = enr.get('as_name','Unknown')
                L.append(f"| ASN / Organization | AS{asn} — {as_name} |")
            L.append(f"| Total Requests | {a['hits']:,} |")
            L.append(f"| Allowed (2xx) | **{s2xx:,}** |")
            L.append(f"| Blocked (4xx) | {s4xx:,} ({s4xx/max(a['hits'],1)*100:.0f}%) |")
            L.append(f"| Auth Probes (401) | {s401:,} |")
            L.append(f"| WAF Blocks (403) | {a['statuses'].get(403,0):,} |")
            L.append(f"| Status Distribution | {status_mix_str(a)} |")
            first = a['first_seen'].astimezone(IST).strftime('%Y-%m-%d %H:%M') if a['first_seen'] else '?'
            last  = a['last_seen'].astimezone(IST).strftime('%Y-%m-%d %H:%M')  if a['last_seen']  else '?'
            L.append(f"| Activity Window (IST) | {first} → {last} |")
            L.append(f"| Triggered Rules | {', '.join(f'`{f}`' for f in flags)} |")
            L.append(f"| Investigate | [Open in GCP Logs Explorer]({build_log_url(pid, ip, start_utc, end_utc)}) |\n")
        if len(cat_a) > 10:
            L.append(f"_Additional {len(cat_a) - 10} action-required finding(s) available in the raw CSV._\n")
    L.append("\n---\n")

    L.append("## 4. Automated Defenses & Mitigations — Nominal Activity\n")
    L.append("_Threats successfully contained by WAF / Cloud Armor. These findings demonstrate that automated defenses operated as designed and required no human intervention._\n")
    if not cat_b:
        L.append("_No significant blocked-threat activity recorded in this window._\n")
    else:
        L.append("| Source IP | Project | Total Requests | WAF Blocks (403) | Block Rate | Origin | Triggered Rule |")
        L.append("|---|---|---|---|---|---|---|")
        for key in cat_b[:15]:
            pid, ip = key; a = global_agg[key]; _, _, flags = analyses[key]
            enr = enrichments.get(ip, {}) or {}
            s403 = a["statuses"].get(403, 0)
            s4xx = sum(c for s, c in a["statuses"].items() if 400 <= s < 500)
            block_rate = s4xx / max(a["hits"], 1) * 100
            if enrichment_ok and "error" not in enr:
                origin = f"{enr.get('country','?')} / {(enr.get('as_name') or 'Unknown')[:30]}"
            else:
                origin = "—"
            L.append(f"| `{ip}` | `{pid}` | {a['hits']:,} | {s403:,} | {block_rate:.0f}% | {origin} | {primary_rule_label(flags)} |")
        if len(cat_b) > 15:
            L.append(f"\n_Additional {len(cat_b) - 15} blocked-threat finding(s) in raw CSV._\n")
    L.append("\n---\n")

    L.append("## 5. Recommended Actions\n")
    L.append("### 🔴 Immediate (next 24 hours)\n")
    imm = []
    if cat_a:
        imm.append(f"**Review all {len(cat_a)} Action Required finding(s) in §3** — investigate IPs with allowed responses, auth probing, or sustained volume")
    if total_403 > 1000:
        imm.append(f"Audit the {total_403:,} WAF-blocked requests for IOC patterns (paths, user-agents, payloads)")
    if not asm_keys:
        imm.append("⚠️ **No ASM scanner activity detected** — verify scanner schedule and connectivity to scoped projects")
    if hosting_ips:
        imm.append(f"Investigate {len(hosting_ips)} threat IP(s) from cloud hosting/datacenter ASNs")
    if not imm:
        imm.append("No immediate action required. Continue routine monitoring.")
    for x in imm: L.append(f"- {x}")
    L.append("\n### 🟡 Short-term (next 7 days)\n")
    L.append("- Validate ASM whitelist accuracy; remove decommissioned scanner IPs")
    L.append("- Add Cloud Armor block rules for top threat ASNs (see §6)")
    L.append("- Evaluate geo-blocking for high-volume non-business countries")
    L.append("- Cross-reference Action Required IPs against external threat intel (AbuseIPDB, GreyNoise)")
    L.append("\n### 🟢 Strategic (next 30 days)\n")
    L.append("- Establish rolling 30-day traffic baseline for anomaly detection")
    L.append("- Integrate this report into SIEM/SOAR for automated CRITICAL alerting")
    L.append("- Enable Cloud Armor Adaptive Protection (ML-based L7 attack detection)")
    L.append("\n---\n")

    L.append("## 6. Threat Intelligence — Geographic & ASN Distribution\n")
    if not enrichment_ok or not threat_keys:
        L.append("⚠️ **Geolocation / ASN enrichment telemetry unavailable for this scan window.**\n")
    else:
        country_hits = defaultdict(int); country_ips_set = defaultdict(set)
        asn_hits = defaultdict(int);     asn_ips_set = defaultdict(set)
        for key in threat_keys:
            ip = key[1]; a = global_agg[key]
            enr = enrichments.get(ip, {}) or {}
            if "error" in enr or not enr.get("country"): continue
            c = enr["country"]
            country_hits[c] += a["hits"]; country_ips_set[c].add(ip)
            asn = enr.get("asn",""); as_name = enr.get("as_name","Unknown")
            ak = f"AS{asn} — {as_name}" if asn else f"— {as_name}"
            asn_hits[ak] += a["hits"]; asn_ips_set[ak].add(ip)
        if country_hits:
            L.append("### Geographic Distribution\n")
            L.append("| Country | Unique IPs | Total Requests | % of External Traffic |")
            L.append("|---|---|---|---|")
            for c, h in sorted(country_hits.items(), key=lambda x:-x[1])[:15]:
                L.append(f"| {c} | {len(country_ips_set[c])} | {h:,} | {h/max(threat_hits,1)*100:.1f}% |")
            L.append("")
        if asn_hits:
            L.append("### Top Threat ASNs / Providers\n")
            L.append("| ASN — Organization | Unique IPs | Total Requests |")
            L.append("|---|---|---|")
            for ak, h in sorted(asn_hits.items(), key=lambda x:-x[1])[:15]:
                L.append(f"| {ak} | {len(asn_ips_set[ak])} | {h:,} |")
        if not country_hits and not asn_hits:
            L.append("⚠️ **No usable enrichment data for threat IPs in this scan window.**\n")
    L.append("\n---\n")

    L.append("## 7. Project-Specific Top IP Breakdown\n")
    L.append("_Top 10 highest-volume source IPs per project. Use this for granular per-project review and engineering investigation._\n")
    by_project = defaultdict(list)
    for key in global_agg.keys():
        by_project[key[0]].append(key)
    for project_id in cfg["projects"]:
        keys_for_proj = by_project.get(project_id, [])
        L.append(f"### Project: `{project_id}`")
        if not keys_for_proj:
            L.append("\n_No ingress traffic recorded for this project in the scan window._\n")
            continue
        top = sorted(keys_for_proj, key=lambda k: -global_agg[k]["hits"])[:10]
        L.append("\n| Source IP | Total Requests | Status Mix | Primary Triggered Rule | Security State |")
        L.append("|---|---|---|---|---|")
        for key in top:
            ip = key[1]; a = global_agg[key]
            _, _, flags = analyses[key]
            L.append(f"| `{ip}` | {a['hits']:,} | {status_mix_str(a, top=4)} | {primary_rule_label(flags)} | {security_state(a)} |")
        L.append("")
    L.append("\n---\n")

    if asm_keys:
        L.append("### Appendix: Authorized ASM Activity\n")
        L.append(f"_{len(asm_keys)} session(s) totaling {asm_hits:,} requests — normal operational baseline._\n")
        L.append("| Project | Scanner IP | Requests | First Seen (IST) | Last Seen (IST) |")
        L.append("|---|---|---|---|---|")
        for key in sorted(asm_keys, key=lambda k: -global_agg[k]["hits"])[:15]:
            pid, ip = key; a = global_agg[key]
            first = a['first_seen'].astimezone(IST).strftime('%m-%d %H:%M') if a['first_seen'] else ''
            last  = a['last_seen'].astimezone(IST).strftime('%m-%d %H:%M')  if a['last_seen']  else ''
            L.append(f"| {pid} | `{ip}` | {a['hits']:,} | {first} | {last} |")
        L.append("")

    L.append("\n---")
    L.append(f"\n_Generated {RUN_TIME.strftime('%Y-%m-%d %H:%M:%S IST')} — STRICTLY READ-ONLY analysis_\n")

    with open(REPORT_MD, "w") as f:
        f.write("\n".join(L))

# ============================================================
# MAIN
# ============================================================
def main():
    signal.signal(signal.SIGINT, lambda *_: (dash.stop(), sys.exit(130)))

    cfg = prompt_inputs()
    resume = maybe_resume()
    completed_set = set(resume["completed"]) if resume else set()
    global_agg   = deserialize_agg(resume["agg"]) if (resume and "agg" in resume) else {}

    creds, detected = google_auth_default()
    log.info(f"Authenticated. ADC project: {detected}")

    pending = [p for p in cfg["projects"] if p not in completed_set]
    dash.set_total(len(cfg["projects"]))
    dash.done = len(cfg["projects"]) - len(pending)
    dash.start()

    # ▶ ONE shared rate limiter for ALL workers (consumer-level quota)
    global_rate_lim = GlobalRateLimiter(GLOBAL_RATE_PER_MIN)

    try:
        if pending:
            n_workers = min(cfg["num_workers"], len(pending))
            dash.set_status(f"scanning ({n_workers} workers, shared {GLOBAL_RATE_PER_MIN}/min)")
            log.info(f"Extraction: {len(pending)} projects × {n_workers} workers sharing global {GLOBAL_RATE_PER_MIN}/min")
            shared = {
                "agg":       global_agg,
                "completed": completed_set,
                "lock":      threading.Lock(),
            }
            with ThreadPoolExecutor(max_workers=n_workers) as ex:
                futures = {ex.submit(scan_project_worker, pid, cfg, creds, shared, global_rate_lim): pid
                           for pid in pending}
                for future in as_completed(futures):
                    pid = futures[future]
                    try:
                        _, ok = future.result()
                        if not ok:
                            log.warning(f"{pid}: completed with failures/incomplete (data scrubbed)")
                    except Exception as e:
                        log.exception(f"Worker future error for {pid}: {e}")
        else:
            log.info("All projects already completed in checkpoint; skipping extraction")

        # ▶ ENRICHMENT (parallel-safe, with retries + cache hygiene)
        enrichments = {}
        if global_agg:
            unique_ips = sorted(set(k[1] for k in global_agg.keys()))
            dash.set_status(f"enriching {len(unique_ips)} IPs")
            log.info(f"Enrichment: {len(unique_ips)} unique IPs")
            enricher = IPinfoEnricher(IP_CACHE_FILE, cfg["ipinfo_token"])
            enrichments = enricher.enrich_all(unique_ips)

        # ▶ ANALYSIS
        dash.set_status("running threat analysis")
        analyses = {key: analyze_threat(agg, enrichments.get(key[1], {}))
                    for key, agg in global_agg.items()}

        # ▶ Accuracy validation
        tot = sum(a["hits"] for a in global_agg.values())
        sum_cat = sum(a["hits"] for a in global_agg.values() if a["category"] in ("ASM", "Threat"))
        if tot != sum_cat:
            log.error(f"ACCURACY WARNING: total={tot} != by_category={sum_cat}")
        else:
            log.info(f"Accuracy check OK: {tot:,} hits across {len(global_agg)} (project, IP) rows")
        log.info(f"Global rate limiter: {global_rate_lim.total_acquires} API calls made")

        # ▶ REPORTING
        dash.set_status("writing reports")
        build_csv(global_agg, cfg, enrichments, analyses)
        build_md(global_agg, cfg, enrichments, analyses)

        dash.set_status("done")
    finally:
        dash.stop()

    total  = sum(a["hits"] for a in global_agg.values())
    asm    = sum(a["hits"] for a in global_agg.values() if a["category"] == "ASM")
    threat = sum(a["hits"] for a in global_agg.values() if a["category"] == "Threat")
    sc     = Counter(analyses[k][0] for k in global_agg)
    op_status, _ = operational_status(global_agg, analyses)

    print()
    print("=" * 76)
    print(f"  {op_status}")
    print("=" * 76)
    print(f"  Executive Report  : {REPORT_MD}")
    print(f"  Raw Data CSV      : {REPORT_CSV}")
    print(f"  Debug Log         : {DEBUG_LOG}")
    print(f"  Checkpoint        : {CHECKPOINT_FILE}")
    print(f"  IP Cache          : {IP_CACHE_FILE}")
    print("-" * 76)
    print(f"  Total hits        : {total:,}  (ASM: {asm:,}  |  Threat: {threat:,})")
    print(f"  Unique (Proj, IP) : {len(global_agg)}")
    print(f"  CRITICAL / HIGH   : {sc.get(SEV_CRITICAL,0)} / {sc.get(SEV_HIGH,0)}")
    print(f"  API calls made    : {global_rate_lim.total_acquires}")
    print("=" * 76)
    print("\nCSV: open directly in Sheets (standard comma format, no custom delimiter needed)")
    print(f"MD:  cat '{REPORT_MD}' | less -R\n")

if __name__ == "__main__":
    main()
