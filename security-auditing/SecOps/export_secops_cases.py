#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
 Google SecOps (Chronicle) Case Exporter — v3 "Fast-Forward"
===============================================================================
 STRICTLY READ-ONLY: performs GET requests only. Never mutates SecOps data.

 What changed vs v2:
   1. RESUME FAST-FORWARD .... resume mode now computes a create-time watermark
                               from the existing CSV and only scans the
                               UNCOVERED time range (+2h safety overlap).
                               No more 198 pages of "0 new cases found".
   2. GAP-AWARE SCANNING ..... if you widen the window (90d -> 180d), the older
                               never-exported range is scanned too. Use
                               --full-rescan to force a complete re-scan.
   3. LIVE DASHBOARD ......... single-line spinner / progress bar with rates,
                               ETA and throttle/token counters instead of
                               per-page log spam. Plain periodic lines when
                               output is piped to a file.
   4. CRASH-SAFE WRITES ...... CSV is written to a temp file then atomically
                               renamed (a crash mid-write can no longer destroy
                               the file you are resuming from). Periodic
                               checkpoints during hydration + clean Ctrl+C
                               handling mean long runs lose (almost) nothing.
   5. BUG FIXES .............. re-hydrating a resumed row no longer wipes its
                               Title/Priority/Status columns; empty "Alert
                               Count" cells no longer crash resume; a 200
                               response containing the text RESOURCE_EXHAUSTED
                               no longer causes an infinite retry loop; network
                               outages no longer retry forever; zero-alert
                               cases are no longer re-hydrated on every resume
                               (new sentinel: "[no alerts]"); missing risk
                               scores show "N/A" instead of silently dragging
                               the average down with fake zeros; ISO-8601 and
                               micro/nanosecond timestamps parse correctly;
                               resume auto-detects the CSV delimiter.

 Sentinels in the "Alert Risk Scores" column:
   "[]"          -> hydration not yet done / failed  (will retry on resume)
   "[no alerts]" -> hydrated successfully, case genuinely has zero alerts
===============================================================================
"""

import argparse
import concurrent.futures
import csv
import glob
import json
import os
import random
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

# Ensure required HTTP networking library is available
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[*] Installing required 'requests' package...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Default GCP Environment Configuration
# ---------------------------------------------------------------------------
DEFAULT_PROJECT_ID = "YOUR_PROJECT_ID"
DEFAULT_INSTANCE_ID = "YOUR_INSTANCE_ID"
DEFAULT_REGION = "us"

# Performance & tuning constants
DEFAULT_NUM_SLICES = 6          # Parallel streams for Phase 1 time-slicing
DEFAULT_HYDRATION_WORKERS = 40  # Parallel worker threads for Phase 2
HTTP_POOL_SIZE = 100            # HTTP socket connection pool size
PAGE_MICRO_PAUSE = 0.01         # 10ms micro-pause between page fetches
DEFAULT_OVERLAP_HOURS = 2       # Safety overlap around the resume watermark
DEFAULT_CHECKPOINT_EVERY = 2000 # Auto-save CSV every N hydrated cases (0=off)

UNHYDRATED_SENTINELS = ("", "[]")
NO_ALERTS_SENTINEL = "[no alerts]"

IST_TZ = timezone(timedelta(hours=5, minutes=30))


# =============================================================================
# TERMINAL COLORS & LIVE DASHBOARD
# =============================================================================
_COLOR = {"on": sys.stdout.isatty() and os.environ.get("NO_COLOR") is None}

def _paint(code, s):
    return f"\033[{code}m{s}\033[0m" if _COLOR["on"] else str(s)

def bold(s):   return _paint("1", s)
def dim(s):    return _paint("2", s)
def red(s):    return _paint("31", s)
def green(s):  return _paint("32", s)
def yellow(s): return _paint("33", s)
def mag(s):    return _paint("35", s)
def cyan(s):   return _paint("36", s)

def human(n):
    try:
        return f"{int(n):,}"
    except (ValueError, TypeError):
        return str(n)

def fmt_dur(secs):
    secs = max(0, int(secs))
    if secs < 60:
        return f"{secs}s"
    m, s = divmod(secs, 60)
    if m < 60:
        return f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m"


class Dashboard:
    """
    Renders a single, in-place-updating status line (spinner + counters)
    on interactive terminals. Falls back to throttled plain log lines when
    stdout is piped (cron / tee / redirect), so logs stay readable either way.
    """
    SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self):
        self.lock = threading.Lock()
        self.live = sys.stdout.isatty()
        self.active = False
        self.frame = 0
        self._last_live = 0.0
        self._last_plain = 0.0

    def _clear_line(self):
        if self.live and self.active:
            sys.stdout.write("\r\033[K")

    def log(self, msg):
        """Print a permanent line without corrupting the live status line."""
        with self.lock:
            self._clear_line()
            print(msg, flush=True)
            self.active = False

    def status(self, text, force=False):
        """Update the transient status line (throttled to ~8 fps)."""
        now = time.time()
        with self.lock:
            if self.live:
                if not force and (now - self._last_live) < 0.12:
                    return
                self._last_live = now
                self.frame = (self.frame + 1) % len(self.SPIN)
                sys.stdout.write("\r\033[K" + cyan(self.SPIN[self.frame]) + " " + text)
                sys.stdout.flush()
                self.active = True
            else:
                if not force and (now - self._last_plain) < 5.0:
                    return
                self._last_plain = now
                print("  " + re.sub(r"\033\[[0-9;]*m", "", text), flush=True)

    def done(self, final=None):
        with self.lock:
            self._clear_line()
            self.active = False
            if final:
                print(final, flush=True)


class Stats:
    """Thread-safe global counters (API calls, throttles, token refreshes)."""
    def __init__(self):
        self._lock = threading.Lock()
        self._d = {}

    def inc(self, key, n=1):
        with self._lock:
            self._d[key] = self._d.get(key, 0) + n

    def get(self, key):
        with self._lock:
            return self._d.get(key, 0)


# =============================================================================
# THREAD-SAFE ATOMIC TOKEN MANAGER
# =============================================================================
class AtomicTokenManager:
    """
    Manages gcloud OAuth tokens safely across high-concurrency worker threads.
    A cooldown ensures that N threads hitting HTTP 401 simultaneously trigger
    only ONE `gcloud auth print-access-token` subprocess.
    """
    def __init__(self, stats, cooldown_seconds=5.0):
        self.token = None
        self.last_refreshed_at = 0.0
        self.cooldown = cooldown_seconds
        self.lock = threading.Lock()
        self.stats = stats
        self.refresh(force=True)

    def refresh(self, force=False):
        with self.lock:
            now = time.time()
            # If another thread refreshed moments ago, reuse its token.
            if not force and (now - self.last_refreshed_at) < self.cooldown and self.token:
                return self.token
            # Even on force, a refresh within the cooldown window is pointless
            # (the "expired" 401 was raced by a refresh that already happened).
            if self.token and (now - self.last_refreshed_at) < self.cooldown:
                return self.token
            try:
                new_token = subprocess.check_output(
                    ["gcloud", "auth", "print-access-token"], text=True
                ).strip()
                if not new_token:
                    raise ValueError("gcloud returned an empty access token string.")
                self.token = new_token
                self.last_refreshed_at = time.time()
                self.stats.inc("token_refresh")
                return self.token
            except Exception as e:
                print(f"\n[!] AUTH ERROR: Failed to refresh token via gcloud: {e}", flush=True)
                if not self.token:
                    sys.exit(1)
                return self.token

    def get_token(self):
        return self.token


# =============================================================================
# NETWORKING & SESSION POOLING
# =============================================================================
def create_pooled_session():
    session = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=HTTP_POOL_SIZE,
        pool_maxsize=HTTP_POOL_SIZE,
        max_retries=Retry(total=2, backoff_factor=0.2, status_forcelist=[502, 503, 504]),
    )
    session.mount("https://", adapter)
    return session


# =============================================================================
# PARSING & FORMATTING HELPERS
# =============================================================================
def safe_int(val, default=0):
    """int() that survives '', None, '3.0', and garbage."""
    try:
        if val is None:
            return default
        if isinstance(val, str):
            val = val.strip()
            if not val:
                return default
        return int(float(val))
    except (ValueError, TypeError):
        return default


def parse_ist_to_epoch(ist_str):
    """Parses the exporter's IST display format back to epoch milliseconds."""
    if not ist_str:
        return 0
    try:
        dt = datetime.strptime(str(ist_str).strip(), "%d %B %Y, %H:%M IST").replace(tzinfo=IST_TZ)
        return int(dt.timestamp() * 1000)
    except Exception:
        return 0


def epoch_from_any(val):
    """
    Best-effort conversion of ANY timestamp representation to epoch ms:
    epoch seconds / ms / µs / ns, ISO-8601 strings, or this exporter's own
    IST display format. Returns 0 when unparseable.
    (Fixes v2 crash/zero-sort when the API returns RFC-3339 strings.)
    """
    if val in (None, ""):
        return 0
    if isinstance(val, (int, float)) or (
        isinstance(val, str) and re.fullmatch(r"\d+(\.\d+)?", val.strip())
    ):
        try:
            v = float(val)
        except (ValueError, TypeError):
            return 0
        if v <= 0:
            return 0
        while v > 1e14:      # µs / ns -> ms
            v /= 1000.0
        if v < 1e11:         # seconds -> ms
            v *= 1000.0
        return int(v)
    s = str(val).strip()
    try:                     # ISO-8601 / RFC-3339
        s2 = s[:-1] + "+00:00" if s.endswith("Z") else s
        dt = datetime.fromisoformat(s2)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except Exception:
        pass
    return parse_ist_to_epoch(s)


def format_epoch_ms(val):
    """Converts any timestamp representation into the IST display format."""
    ep = epoch_from_any(val)
    if not ep:
        return "" if val in (None, "") else str(val)
    dt = datetime.fromtimestamp(ep / 1000.0, tz=timezone.utc).astimezone(IST_TZ)
    return dt.strftime("%d %B %Y, %H:%M IST")


_HEADER_MEMO = {}

def format_header_name(key):
    """camelCase / snake_case / dot.notation -> Title Case (memoized)."""
    if not key:
        return ""
    cached = _HEADER_MEMO.get(key)
    if cached is not None:
        return cached
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
    s = re.sub(r"[\._\-]+", " ", s)
    out = " ".join(w.capitalize() for w in s.split())
    _HEADER_MEMO[key] = out
    return out


def parse_datetime(dt_str, is_end=False):
    dt_str = dt_str.strip()
    if len(dt_str) == 10:  # YYYY-MM-DD
        dt_str += "T23:59:59Z" if is_end else "T00:00:00Z"
    if dt_str.endswith("Z"):
        dt_str = dt_str[:-1] + "+00:00"
    dt = datetime.fromisoformat(dt_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def parse_time_input(time_str):
    """'15d' / '24h' / '30m' relative strings, or exact dates -> UTC datetimes."""
    time_str = time_str.strip()
    now_utc = datetime.now(timezone.utc)
    match = re.match(r"^(\d+)\s*([dDhHmMsS])$", time_str)
    if match:
        amount, unit = int(match.group(1)), match.group(2).lower()
        delta = {"d": timedelta(days=amount), "h": timedelta(hours=amount),
                 "m": timedelta(minutes=amount), "s": timedelta(seconds=amount)}[unit]
        return now_utc - delta, now_utc, True
    return parse_datetime(time_str, is_end=False), None, False


def generate_time_slices(start_dt, end_dt, slices):
    """
    Splits a window into N contiguous chunks. Non-final chunk ends are pulled
    back 1ms so adjacent slices no longer double-fetch boundary cases
    (v2 used >= AND <= on both sides of every boundary).
    """
    total = (end_dt - start_dt).total_seconds()
    if total <= 0:
        return [(start_dt, end_dt)]
    slices = max(1, int(slices))
    # Don't bother splitting tiny windows into 6 streams: min ~30min per slice.
    slices = min(slices, max(1, int(total // 1800)) or 1)
    step = total / slices
    out = []
    for i in range(slices):
        c_start = start_dt + timedelta(seconds=i * step)
        if i == slices - 1:
            c_end = end_dt
        else:
            c_end = start_dt + timedelta(seconds=(i + 1) * step) - timedelta(milliseconds=1)
        out.append((c_start, c_end))
    return out


def flatten_json(nested_data, parent_key="", sep="."):
    """Recursively flattens nested dict/list structures into dot-notation keys."""
    items = {}
    if isinstance(nested_data, dict):
        for key, value in nested_data.items():
            new_key = f"{parent_key}{sep}{key}" if parent_key else key
            items.update(flatten_json(value, new_key, sep=sep))
    elif isinstance(nested_data, list):
        if not nested_data:
            items[parent_key] = ""
        elif all(isinstance(x, (str, int, float, bool)) for x in nested_data):
            items[parent_key] = ", ".join(map(str, nested_data))
        else:
            items[parent_key] = json.dumps(nested_data, ensure_ascii=False)
    else:
        items[parent_key] = nested_data
    return items


def extract_alert_risk_score(alert_obj):
    """
    Extracts the numeric risk score from an alert object.
    Returns None when the alert genuinely has no score, so missing scores are
    reported as 'N/A' instead of being averaged in as fake zeros (v2 bug).
    """
    score = alert_obj.get("riskScore")
    if score is None:
        score = alert_obj.get("score")
    if score is None:
        add_props = alert_obj.get("additionalProperties", "")
        if isinstance(add_props, str) and add_props.strip():
            try:
                parsed = json.loads(add_props)
                score = parsed.get("RiskScore") or parsed.get("riskScore")
            except Exception:
                pass
    if score is None:
        return None
    try:
        num = float(score)
        return int(num) if num.is_integer() else num
    except (ValueError, TypeError):
        return None


def summarize_alert_scores(alerts):
    """Builds the '[id: score, id2: score2]' string + average over known scores."""
    entries, nums = [], []
    for idx, alert in enumerate(alerts, 1):
        alert_id = (
            alert.get("siemAlertId")
            or alert.get("ticketId")
            or alert.get("identifier")
            or (alert.get("name", "").split("/")[-1] if alert.get("name") else f"alert_{idx}")
        )
        score = extract_alert_risk_score(alert)
        if score is None:
            entries.append(f"{alert_id}: N/A")
        else:
            nums.append(score)
            entries.append(f"{alert_id}: {score}")
    if not entries:
        return "[]", 0
    scores_str = "[" + ", ".join(entries) + "]"
    if nums:
        mean = sum(nums) / len(nums)
        avg = int(mean) if float(mean).is_integer() else round(mean, 2)
    else:
        avg = ""  # every alert lacked a score: unknown, not zero
    return scores_str, avg


# =============================================================================
# SUB-RESOURCE FETCHERS (PAGINATED & RATE-LIMIT RESILIENT)
# =============================================================================
def fetch_case_alerts_paginated(session, token_mgr, host, case_name, stats,
                                stop_event=None, max_retries=5):
    """
    Fetches all caseAlerts for a case with full pagination.
    Returns (alerts, complete): complete=False means at least one page failed,
    so the caller can leave the case marked un-hydrated for a later retry
    instead of silently exporting partial data (v2 bug).
    """
    alerts_url = f"{host}/v1beta/{case_name}/caseAlerts"
    all_alerts = []
    page_token = ""
    seen_page_tokens = set()
    max_pages = 20  # 2,000 alerts per case cap: infinite-loop guard

    for _ in range(max_pages):
        if stop_event is not None and stop_event.is_set():
            return all_alerts, False
        params = {"pageSize": 100}
        if page_token:
            if page_token in seen_page_tokens:
                break
            seen_page_tokens.add(page_token)
            params["pageToken"] = page_token

        got_page = False
        c401 = 0
        for attempt in range(max_retries):
            headers = {"Authorization": f"Bearer {token_mgr.get_token()}"}
            try:
                stats.inc("api")
                resp = session.get(alerts_url, headers=headers, params=params, timeout=12)
            except requests.RequestException:
                time.sleep(0.4 * (2 ** attempt))
                continue

            if resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError:
                    time.sleep(0.4 * (2 ** attempt))
                    continue
                all_alerts.extend(data.get("caseAlerts", []))
                page_token = data.get("nextPageToken", "")
                got_page = True
                break
            elif resp.status_code == 401:
                c401 += 1
                if c401 > 4:
                    break
                token_mgr.refresh(force=True)
                continue
            elif resp.status_code == 429 or "RESOURCE_EXHAUSTED" in (resp.text or ""):
                stats.inc("throttle")
                time.sleep(min(15.0, (1.5 ** (attempt + 1)) + random.uniform(0.2, 0.8)))
                continue
            elif resp.status_code in (500, 502, 503, 504):
                time.sleep(0.5 * (2 ** attempt))
                continue
            else:
                return all_alerts, False  # non-retryable error: partial

        if not got_page:
            return all_alerts, False
        if not page_token:
            break

    return all_alerts, True


def fetch_custom_fields(session, token_mgr, host, case_name, stats):
    """Fetches dynamic custom field values for a case sub-resource."""
    custom_url = f"{host}/v1beta/{case_name}/customFieldValues"
    headers = {"Authorization": f"Bearer {token_mgr.get_token()}"}
    try:
        stats.inc("api")
        resp = session.get(custom_url, headers=headers, timeout=8)
        if resp.status_code == 401:
            token_mgr.refresh(force=True)
            headers = {"Authorization": f"Bearer {token_mgr.get_token()}"}
            stats.inc("api")
            resp = session.get(custom_url, headers=headers, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("customFieldValues", data)
    except Exception:
        pass
    return {}


# =============================================================================
# WORKER PIPELINE PHASES
# =============================================================================
def pre_process_case(case):
    """Phase 1 worker: fast in-memory transformation of raw case attributes."""
    raw_case_name = case.get("name", "")
    case["_sort_time"] = epoch_from_any(case.get("createTime"))

    if raw_case_name and "/" in raw_case_name:
        case["name"] = raw_case_name.split("/")[-1]
    if "createTime" in case:
        case["createTime"] = format_epoch_ms(case["createTime"])
    if "updateTime" in case:
        case["updateTime"] = format_epoch_ms(case["updateTime"])
    if isinstance(case.get("priority"), str):
        case["priority"] = case["priority"].replace("PRIORITY_", "")

    if isinstance(case.get("products"), list):
        formatted = []
        for item in case["products"]:
            if isinstance(item, dict):
                alert_name = item.get("alert", "")
                disp_name = item.get("displayName", "")
                if alert_name and disp_name:
                    formatted.append(f"[{disp_name}] {alert_name}")
                elif alert_name or disp_name:
                    formatted.append(alert_name or disp_name)
            elif isinstance(item, str):
                formatted.append(item)
        case["products"] = "; ".join(formatted)

    if "alertCount" not in case:
        case["alertCount"] = len(case.get("alerts", [])) or len(case.get("caseAlerts", []))

    case["_raw_name"] = raw_case_name
    return case


def hydrate_new_case(session, token_mgr, host, case, fetch_custom, stats, stop_event):
    """Phase 2 worker (new cases): fetch alert risk scores + custom fields."""
    raw_name = case.get("_raw_name", "")
    alert_cnt = safe_int(case.get("alertCount", 0), 0)
    raw_alerts = case.get("alerts") or case.get("caseAlerts") or []
    complete = True

    if not raw_alerts and raw_name and alert_cnt > 0:
        raw_alerts, complete = fetch_case_alerts_paginated(
            session, token_mgr, host, raw_name, stats, stop_event
        )

    if raw_alerts:
        case["alertRiskScores"], case["avgRiskScore"] = summarize_alert_scores(raw_alerts)
    elif alert_cnt == 0 or complete:
        case["alertRiskScores"] = NO_ALERTS_SENTINEL
        case["avgRiskScore"] = 0
    else:
        # Fetch failed: keep the un-hydrated sentinel so resume retries it.
        case["alertRiskScores"] = "[]"
        case["avgRiskScore"] = ""

    flat = flatten_json(case)

    if fetch_custom and raw_name and not stop_event.is_set():
        custom = fetch_custom_fields(session, token_mgr, host, raw_name, stats)
        if custom:
            flat.update(flatten_json(custom, parent_key="customFields"))

    flat.pop("_raw_name", None)
    return flat


def hydrate_existing_row(session, token_mgr, host, row, case_path_prefix, stats, stop_event):
    """
    Phase 2 worker (resumed rows): fetch alerts and update ONLY the risk-score
    columns, preserving every other column of the original row.
    (v2 rebuilt these rows from a 4-field stub, wiping Title/Priority/Status.)
    """
    out = dict(row)
    out.pop(None, None)  # DictReader restkey from ragged rows
    out["_sort_time"] = epoch_from_any(out.get("Create Time") or out.get("createTime") or 0)

    cid = None
    for key in ("Name", "name", "ID", "Id", "id", "Case Id"):
        val = out.get(key)
        if val and str(val).strip():
            cid = str(val).strip()
            break

    scores_col = "Alert Risk Scores" if "Alert Risk Scores" in out else "alertRiskScores"
    avg_col = "Avg Risk Score" if "Avg Risk Score" in out else "avgRiskScore"

    if not cid:
        return out  # cannot hydrate a row without an identifier; keep as-is

    alert_cnt = safe_int(out.get("Alert Count", out.get("alertCount")), None)
    if alert_cnt == 0:
        out[scores_col] = NO_ALERTS_SENTINEL
        out[avg_col] = out.get(avg_col) or 0
        return out

    case_name = f"{case_path_prefix}/cases/{cid}"
    alerts, complete = fetch_case_alerts_paginated(
        session, token_mgr, host, case_name, stats, stop_event
    )
    if alerts:
        out[scores_col], out[avg_col] = summarize_alert_scores(alerts)
    elif complete:
        out[scores_col] = NO_ALERTS_SENTINEL
        out[avg_col] = 0
    # else: leave "[]" so the next resume retries this case
    return out


def fetch_slice_cases_fast(session, token_mgr, host, base_url, slice_id,
                           start_dt, end_dt, custom_filter, known_ids,
                           report, log, stop_event, stats):
    """Phase 1 stream worker: rapidly enumerates case metadata for one time slice."""
    start_ms = int(start_dt.timestamp() * 1000)
    end_ms = int(end_dt.timestamp() * 1000)
    filter_expr = f"CreateTime >= {start_ms} AND CreateTime <= {end_ms}"
    if custom_filter:
        filter_expr += f" AND ({custom_filter})"

    slice_cases = []
    page_token = ""
    pages = 0
    skipped = 0
    c429 = 0
    consec_err = 0
    consec_401 = 0

    while not stop_event.is_set():
        params = {"pageSize": 100, "expand": "tags,products,tasks", "filter": filter_expr}
        if page_token:
            params["pageToken"] = page_token
        headers = {
            "Authorization": f"Bearer {token_mgr.get_token()}",
            "Content-Type": "application/json",
        }

        try:
            stats.inc("api")
            resp = session.get(base_url, headers=headers, params=params, timeout=30)
        except requests.RequestException as e:
            consec_err += 1
            if consec_err >= 5:  # v2 retried network outages forever
                log(red(f"[!] Stream {slice_id}: giving up after repeated network errors: {e}"))
                break
            time.sleep(min(8, 2 ** consec_err))
            continue

        if resp.status_code == 401:
            consec_401 += 1
            if consec_401 > 5:
                log(red(f"[!] Stream {slice_id}: persistent 401 — aborting slice."))
                break
            token_mgr.refresh(force=True)
            continue

        # v2 bug: this text scan also ran on HTTP 200, so a case whose body
        # happened to contain "RESOURCE_EXHAUSTED" retried the same page forever.
        if resp.status_code == 429 or (
            resp.status_code != 200 and "RESOURCE_EXHAUSTED" in (resp.text or "")
        ):
            c429 += 1
            stats.inc("throttle")
            time.sleep(min(20.0, (1.5 ** c429) + random.uniform(0.2, 0.8)))
            continue

        if resp.status_code != 200:
            log(red(f"[!] Stream {slice_id}: HTTP {resp.status_code}: {resp.text[:160]}"))
            break

        consec_err = consec_401 = c429 = 0
        try:
            data = resp.json()
        except ValueError:
            consec_err += 1
            if consec_err >= 5:
                log(red(f"[!] Stream {slice_id}: repeated malformed JSON — aborting slice."))
                break
            time.sleep(1)
            continue

        pages += 1
        raw_cases = data.get("cases", [])
        for c in raw_cases:
            cid = c.get("name", "")
            cid = cid.split("/")[-1] if "/" in cid else cid
            if cid and cid in known_ids:
                skipped += 1
                continue
            slice_cases.append(pre_process_case(c))

        report(slice_id, pages, len(slice_cases), skipped)

        page_token = data.get("nextPageToken")
        if not raw_cases or not page_token:
            break
        time.sleep(PAGE_MICRO_PAUSE)

    report(slice_id, pages, len(slice_cases), skipped, done=True)
    return slice_cases


class Phase1Board:
    """Aggregates per-stream progress into one live status line."""
    def __init__(self, dash, total_streams, stats):
        self.dash = dash
        self.lock = threading.Lock()
        self.state = {}
        self.total = total_streams
        self.t0 = time.time()
        self.stats = stats

    def report(self, sid, pages, new, skipped, done=False):
        with self.lock:
            self.state[sid] = (pages, new, skipped, done)
            pages_t = sum(v[0] for v in self.state.values())
            new_t = sum(v[1] for v in self.state.values())
            skip_t = sum(v[2] for v in self.state.values())
            done_t = sum(1 for v in self.state.values() if v[3])
        elapsed = time.time() - self.t0
        rate = pages_t / elapsed if elapsed > 0 else 0.0
        self.dash.status(
            f"{bold('PHASE 1')} · streams {done_t}/{self.total} done · "
            f"{human(pages_t)} pages · {green(human(new_t) + ' new')} · "
            f"{dim(human(skip_t) + ' skipped')} · {rate:.0f} p/s · {fmt_dur(elapsed)}",
            force=done,
        )


# =============================================================================
# RESUME & CSV I/O UTILITIES
# =============================================================================
def detect_delimiter(csv_path, fallback="|"):
    """Auto-detects the delimiter so resuming a ','-file with -d '|' can't silently mangle it."""
    try:
        with open(csv_path, encoding="utf-8") as f:
            head = f.readline()
    except Exception:
        return fallback
    best = max(["|", ",", "\t", ";"], key=lambda d: head.count(d))
    return best if head.count(best) > 0 else fallback


def read_existing_csv(csv_path, delimiter):
    """
    Reads the existing CSV: rows, seen IDs, headers, and the create-time
    watermark (max) / earliest (min) used for resume fast-forward.
    """
    if not os.path.exists(csv_path):
        print(red(f"[!] Error: File '{csv_path}' not found."))
        candidates = sorted(glob.glob("secops_cases_export_*.csv"),
                            key=os.path.getmtime, reverse=True)[:3]
        if candidates:
            print(dim("    Did you mean: " + ", ".join(candidates)))
        sys.exit(1)

    existing_rows, seen_ids = [], set()
    wm_ms, earliest_ms = 0, 0
    try:
        with open(csv_path, mode="r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f, delimiter=delimiter)
            fieldnames = [h for h in (reader.fieldnames or []) if h is not None]

            id_header = None
            for h in fieldnames:
                if h.strip().lower() in ("name", "id", "case id"):
                    id_header = h
                    break
            if not id_header:
                id_header = fieldnames[0] if fieldnames else "Name"

            for row in reader:
                row.pop(None, None)  # ragged-row overflow from DictReader
                case_id = (row.get(id_header) or "").strip()
                if not case_id or case_id in seen_ids:
                    continue
                seen_ids.add(case_id)
                existing_rows.append(row)
                ep = epoch_from_any(row.get("Create Time") or row.get("createTime") or 0)
                if ep > 0:
                    wm_ms = max(wm_ms, ep)
                    earliest_ms = min(earliest_ms, ep) if earliest_ms else ep
        return existing_rows, seen_ids, fieldnames, wm_ms, earliest_ms
    except Exception as e:
        print(red(f"[!] Error reading existing CSV '{csv_path}': {e}"))
        sys.exit(1)


def generate_unique_filename():
    return f"secops_cases_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"


def row_id(row):
    for key in ("Name", "name", "ID", "Id", "id"):
        val = row.get(key)
        if val and str(val).strip():
            return str(val).strip()
    return None


def to_titled_row(flat):
    """Converts a raw-key flat dict into Title Case headers, keeping _sort_time."""
    row = {format_header_name(k): v for k, v in flat.items()
           if k not in ("_sort_time", "_raw_name")}
    row["_sort_time"] = flat.get("_sort_time", 0)
    return row


def merge_rows(*groups):
    """Deduplicates by case ID (first occurrence wins) and sorts newest-first."""
    seen, out = set(), []
    for group in groups:
        for row in group:
            rid = row_id(row)
            if rid:
                if rid in seen:
                    continue
                seen.add(rid)
            out.append(row)
    out.sort(key=lambda r: safe_int(r.get("_sort_time", 0), 0), reverse=True)
    return out


TITLE_PRIORITY = [
    "Name", "Id", "ID", "Title", "Display Name", "Create Time", "Update Time",
    "Alert Count", "Alert Risk Scores", "Avg Risk Score",
    "Priority", "Status", "Stage",
]

def build_headers(rows, extra_headers=None):
    keys = set(extra_headers or [])
    for row in rows:
        keys.update(k for k in row.keys() if k not in (None, "_sort_time"))
    return sorted(
        keys,
        key=lambda x: (0, TITLE_PRIORITY.index(x)) if x in TITLE_PRIORITY else (1, x),
    )


def atomic_write_csv(path, headers, rows, delimiter):
    """
    Writes to a temp file then renames into place, so a crash mid-write can
    never destroy the CSV being resumed (v2 opened the same file in 'w' mode).
    """
    tmp_path = path + ".tmp"
    with open(tmp_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=headers, delimiter=delimiter,
            quoting=csv.QUOTE_MINIMAL, extrasaction="ignore", restval="",
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    os.replace(tmp_path, path)


# =============================================================================
# MAIN CLI & EXECUTOR ENTRYPOINT
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Google SecOps Case Exporter v3 (read-only, resume fast-forward)",
        epilog=("examples:  %(prog)s -t 90d              new 90-day export\n"
                "           %(prog)s --resume file.csv    resume (auto fast-forward)\n"
                "           %(prog)s --resume file.csv --full-rescan   force complete re-scan"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-p", "--project", default=DEFAULT_PROJECT_ID, help="GCP Project ID")
    parser.add_argument("-i", "--instance", default=DEFAULT_INSTANCE_ID, help="SecOps Instance ID")
    parser.add_argument("-r", "--region", default=DEFAULT_REGION, help="SecOps Region (us, eu, ...)")
    parser.add_argument("-t", "--timeframe", help="Timeframe ('15d', '90d', '24h')")
    parser.add_argument("--start", help="Start Date (YYYY-MM-DD or ISO string)")
    parser.add_argument("--end", help="End Date (YYYY-MM-DD or ISO string)")
    parser.add_argument("-f", "--filter", default="", help="Optional additional API filter string")
    parser.add_argument("-o", "--output", help="Output CSV filename")
    parser.add_argument("-d", "--delimiter", default="|", help="CSV delimiter (default: '|')")
    parser.add_argument("-s", "--slices", type=int, default=DEFAULT_NUM_SLICES,
                        help="Parallel Phase 1 time streams (default: 6)")
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_HYDRATION_WORKERS,
                        help="Parallel Phase 2 hydration workers (default: 40)")
    parser.add_argument("-c", "--fetch-custom", action="store_true",
                        help="Fetch deep customFieldValues sub-resource per case")
    parser.add_argument("--resume", help="Resume export from existing CSV file path")
    parser.add_argument("--full-rescan", action="store_true",
                        help="Resume mode: disable watermark fast-forward, scan the whole window")
    parser.add_argument("--overlap-hours", type=float, default=DEFAULT_OVERLAP_HOURS,
                        help="Safety overlap around the resume watermark (default: 2)")
    parser.add_argument("--checkpoint-every", type=int, default=DEFAULT_CHECKPOINT_EVERY,
                        help="Auto-save CSV every N hydrated cases, 0 disables (default: 2000)")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if args.no_color:
        _COLOR["on"] = False

    dash = Dashboard()
    stats = Stats()
    stop_event = threading.Event()

    print()
    print(cyan("╔" + "═" * 73 + "╗"))
    print(cyan("║") + bold("   GOOGLE SECOPS CASE EXPORTER v3 — Fast-Forward Edition").ljust(81 if _COLOR["on"] else 73) + cyan("║"))
    print(cyan("║") + dim("   read-only · resume-aware · crash-safe · atomic writes").ljust(81 if _COLOR["on"] else 73) + cyan("║"))
    print(cyan("╚" + "═" * 73 + "╝"))

    project_id, instance_id, region = args.project, args.instance, args.region

    # ------------------------------------------------------------------ mode
    existing_rows, seen_case_ids, existing_headers = [], set(), []
    wm_ms = earliest_ms = 0
    is_resume_mode = bool(args.resume)
    resume_file = args.resume

    if not is_resume_mode and not args.timeframe and not args.start:
        print("\n[?] Select Execution Mode:")
        print("    [1] Start a brand new export (Default)")
        print("    [2] Resume / Re-hydrate an existing CSV export")
        if input("Enter choice [1/2]: ").strip() == "2":
            is_resume_mode = True
            candidates = sorted(glob.glob("secops_cases_export_*.csv"),
                                key=os.path.getmtime, reverse=True)[:3]
            if candidates:
                print(dim("    Recent exports: " + ", ".join(candidates)))
            resume_file = input("[?] Enter existing CSV filename to resume/re-hydrate: ").strip()

    read_delim = args.delimiter
    if is_resume_mode:
        read_delim = detect_delimiter(resume_file, args.delimiter)
        if read_delim != args.delimiter:
            print(yellow(f"[!] Detected delimiter '{read_delim}' in '{resume_file}' "
                         f"(overriding '-d {args.delimiter}')."))
        existing_rows, seen_case_ids, existing_headers, wm_ms, earliest_ms = \
            read_existing_csv(resume_file, read_delim)
        print(green(f"[+] Loaded {human(len(existing_rows))} existing cases from '{resume_file}'."))
        output_filename = resume_file
    else:
        output_filename = args.output if args.output else generate_unique_filename()
    write_delim = read_delim if is_resume_mode else args.delimiter

    # ------------------------------------------------------------ time window
    if not args.timeframe and not args.start:
        tf_input = input("\n[?] Enter timeframe (e.g. '15d', '30d', '90d') OR start date "
                         "(YYYY-MM-DD) [Default: 90d]: ").strip() or "90d"
        start_dt, end_dt, is_relative = parse_time_input(tf_input)
        if not is_relative:
            end_prompt = input("[?] Enter end date (YYYY-MM-DD) [Press Enter for NOW]: ").strip()
            end_dt = parse_datetime(end_prompt, is_end=True) if end_prompt \
                else datetime.now(timezone.utc)
    elif args.start:
        start_dt = parse_datetime(args.start, is_end=False)
        end_dt = parse_datetime(args.end, is_end=True) if args.end else datetime.now(timezone.utc)
    else:
        start_dt, end_dt, _ = parse_time_input(args.timeframe)

    if end_dt <= start_dt:
        print(red("[!] End of window is not after its start. Nothing to do."))
        sys.exit(1)

    fetch_custom = args.fetch_custom
    if not args.timeframe and not args.start and not args.fetch_custom:
        cf = input("\n[?] Fetch deep dynamic customFieldValues sub-resource? "
                   "(y/N) [Default N = 10x Faster]: ").strip().lower()
        fetch_custom = cf.startswith("y")

    # ----------------------------------------------- resume fast-forward plan
    requested_span = (end_dt - start_dt).total_seconds()
    scan_windows = []
    if is_resume_mode and not args.full_rescan and wm_ms > 0:
        overlap = timedelta(hours=max(0.0, args.overlap_hours))
        wm_dt = datetime.fromtimestamp(wm_ms / 1000.0, tz=timezone.utc)
        earliest_dt = (datetime.fromtimestamp(earliest_ms / 1000.0, tz=timezone.utc)
                       if earliest_ms > 0 else None)
        # Older gap: the requested window starts before anything ever exported.
        if earliest_dt and start_dt < earliest_dt - overlap:
            scan_windows.append((start_dt, min(earliest_dt + overlap, end_dt)))
        # New tail: everything after the newest exported case.
        ff_start = max(start_dt, wm_dt - overlap)
        if ff_start < end_dt:
            scan_windows.append((ff_start, end_dt))
    else:
        scan_windows.append((start_dt, end_dt))

    scanned_span = sum((e - s).total_seconds() for s, e in scan_windows)
    skipped_span = max(0.0, requested_span - scanned_span)

    # ---------------------------------------------------------------- slicing
    all_chunks = []
    if scan_windows and scanned_span > 0:
        for (ws, we) in scan_windows:
            frac = (we - ws).total_seconds() / scanned_span
            n = max(1, round(args.slices * frac))
            all_chunks.extend(generate_time_slices(ws, we, n))

    token_mgr = AtomicTokenManager(stats)
    host = f"https://{region}-chronicle.googleapis.com"
    base_url = (f"{host}/v1beta/projects/{project_id}/locations/{region}"
                f"/instances/{instance_id}/cases")
    case_prefix = f"projects/{project_id}/locations/{region}/instances/{instance_id}"

    # --------------------------------------------------------- config summary
    print("\n" + dim("─" * 75))
    print(bold(" EXPORT CONFIGURATION"))
    print(dim("─" * 75))
    print(f" {dim('Project / Instance')}   {project_id}  ·  {instance_id}  ·  {region}")
    print(f" {dim('Mode')}                 "
          + (yellow("RESUME / FAST-FORWARD") if is_resume_mode else green("NEW EXPORT")))
    if is_resume_mode:
        print(f" {dim('Existing cases')}       {human(len(existing_rows))} rows already in file")
    print(f" {dim('Requested window')}     {start_dt.strftime('%Y-%m-%dT%H:%M:%SZ')} → "
          f"{end_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}  ({requested_span / 86400:.1f}d)")
    if skipped_span > 0:
        print(f" {dim('Fast-forward')}         "
              + green(f"skipping {skipped_span / 86400:.1f}d already exported")
              + dim(f"  (scanning {scanned_span / 86400:.1f}d, ±{args.overlap_hours:g}h overlap)"))
    print(f" {dim('Parallelism')}          {len(all_chunks)} enumeration streams · "
          f"{args.workers} hydration workers")
    print(f" {dim('Custom fields')}        {'YES (slower)' if fetch_custom else 'no'}")
    print(f" {dim('Output')}               {output_filename}  (delimiter '{write_delim}', "
          f"checkpoint every {args.checkpoint_every or 'off'})")
    print(dim("─" * 75) + "\n")

    session = create_pooled_session()
    t_start = time.time()

    # -------------------------------------------------------------------------
    # PHASE 1: FAST CASE METADATA ENUMERATION
    # -------------------------------------------------------------------------
    raw_new_cases = []
    if all_chunks:
        board = Phase1Board(dash, len(all_chunks), stats)
        known_ids = frozenset(seen_case_ids)  # immutable snapshot: thread-safe reads
        p1_pool = concurrent.futures.ThreadPoolExecutor(max_workers=min(len(all_chunks), 8))
        futures = [
            p1_pool.submit(
                fetch_slice_cases_fast, session, token_mgr, host, base_url,
                idx + 1, cs, ce, args.filter, known_ids,
                board.report, dash.log, stop_event, stats,
            )
            for idx, (cs, ce) in enumerate(all_chunks)
        ]
        try:
            for fut in concurrent.futures.as_completed(futures):
                try:
                    for c in fut.result():
                        cid = c.get("name") or c.get("id") or ""
                        if cid and cid not in seen_case_ids:
                            seen_case_ids.add(cid)
                            raw_new_cases.append(c)
                except Exception as err:
                    dash.log(red(f"[!] Stream worker error: {err}"))
        except KeyboardInterrupt:
            stop_event.set()
            dash.done()
            print(yellow("\n[!] Interrupted during enumeration — nothing was written, "
                         "your CSV is untouched."))
            p1_pool.shutdown(wait=False, cancel_futures=True)
            sys.exit(130)
        p1_pool.shutdown(wait=True)
        dash.done(green(f"[+] PHASE 1 complete in {fmt_dur(time.time() - t_start)}: ")
                  + bold(f"{human(len(raw_new_cases))} new cases found."))
    else:
        print(green("[+] PHASE 1 skipped — requested window is already fully covered "
                    "by the existing export."))

    # -------------------------------------------------- build hydration queues
    pending_new = {}
    for case in raw_new_cases:
        cid = str(case.get("name") or case.get("id") or f"__new_{len(pending_new)}")
        pending_new[cid] = case

    hydrated_existing, pending_existing = [], {}
    if is_resume_mode:
        for i, row in enumerate(existing_rows):
            scores_val = (row.get("Alert Risk Scores",
                          row.get("alertRiskScores", "")) or "").strip()
            if scores_val in UNHYDRATED_SENTINELS:
                row["_sort_time"] = epoch_from_any(
                    row.get("Create Time") or row.get("createTime") or 0)
                pending_existing[row_id(row) or f"__anon_{i}"] = row
            else:
                row["_sort_time"] = epoch_from_any(
                    row.get("Create Time") or row.get("createTime") or 0)
                hydrated_existing.append(row)

    total_to_hydrate = len(pending_new) + len(pending_existing)
    if total_to_hydrate == 0:
        if is_resume_mode:
            print(green("\n[✔] Everything is up to date — 0 new cases, 0 pending "
                        "re-hydrations. File untouched."))
        else:
            print(yellow("\n[!] No cases found in the requested window. "
                         "No file was written."))
        return

    # ------------------------------------------------------- snapshot machinery
    done_rows = []

    def placeholder_row(case):
        """A not-yet-hydrated new case, exported with '[]' so resume re-queues it."""
        c = dict(case)
        c.pop("_raw_name", None)
        flat = flatten_json(c)
        flat["alertRiskScores"] = "[]"
        flat["avgRiskScore"] = ""
        flat["_sort_time"] = case.get("_sort_time", 0)
        return to_titled_row(flat)

    def write_snapshot():
        rows = merge_rows(
            done_rows,
            hydrated_existing,
            list(pending_existing.values()),
            [placeholder_row(c) for c in pending_new.values()],
        )
        headers = build_headers(rows, extra_headers=existing_headers)
        atomic_write_csv(output_filename, headers, rows, write_delim)
        return len(rows), len(headers)

    # -------------------------------------------------------------------------
    # PHASE 2: HIGH-CONCURRENCY ALERT HYDRATION
    # -------------------------------------------------------------------------
    print(f"\n[*] {bold('PHASE 2')}: hydrating alert risk scores for "
          f"{bold(human(total_to_hydrate))} cases "
          f"({human(len(pending_new))} new + {human(len(pending_existing))} re-queued) "
          f"on {args.workers} workers...")
    print(dim("    ⟳ = token refreshes · ⏳ = throttled retries · "
              "Ctrl+C saves a resumable checkpoint\n"))

    def job(item):
        kind, payload = item
        if kind == "new":
            return kind, hydrate_new_case(session, token_mgr, host, payload,
                                          fetch_custom, stats, stop_event)
        return kind, hydrate_existing_row(session, token_mgr, host, payload,
                                          case_prefix, stats, stop_event)

    work_items = ([("new", c) for c in pending_new.values()]
                  + [("existing", r) for r in pending_existing.values()])

    completed = 0
    new_done = rehydrated_done = 0
    p2_start = time.time()
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers))
    futures = [pool.submit(job, item) for item in work_items]

    def render_progress(force=False):
        elapsed = time.time() - p2_start
        rate = completed / elapsed if elapsed > 0 else 0.0
        pct = completed / total_to_hydrate * 100
        eta = (total_to_hydrate - completed) / rate if rate > 0 else 0
        filled = int(pct / 100 * 20)
        bar = mag("█" * filled) + dim("░" * (20 - filled))
        dash.status(
            f"{bold('PHASE 2')} {bar} {pct:5.1f}% · "
            f"{human(completed)}/{human(total_to_hydrate)} · {rate:.1f}/s · "
            f"ETA {fmt_dur(eta)} · "
            f"{dim('⟳' + str(stats.get('token_refresh')) + ' ⏳' + str(stats.get('throttle')))}",
            force=force,
        )

    try:
        for fut in concurrent.futures.as_completed(futures):
            try:
                kind, result = fut.result()
                if kind == "new":
                    cid = str(result.get("name") or result.get("id") or "")
                    pending_new.pop(cid, None)
                    done_rows.append(to_titled_row(result))
                    new_done += 1
                else:
                    pending_existing.pop(row_id(result) or "", None)
                    done_rows.append(result)
                    rehydrated_done += 1
            except Exception as err:
                dash.log(red(f"[!] Hydration error: {err}"))
            completed += 1
            render_progress(force=(completed == total_to_hydrate))

            if (args.checkpoint_every and completed % args.checkpoint_every == 0
                    and completed < total_to_hydrate):
                n_rows, _ = write_snapshot()
                dash.log(dim(f"    ✓ checkpoint saved — {human(n_rows)} rows on disk "
                             f"({human(completed)}/{human(total_to_hydrate)} hydrated)"))
    except KeyboardInterrupt:
        stop_event.set()
        dash.done()
        print(yellow("\n[!] Interrupted — cancelling workers and writing a resumable "
                     "checkpoint (in-flight requests may take a few seconds)..."))
        pool.shutdown(wait=False, cancel_futures=True)
        n_rows, _ = write_snapshot()
        print(green(f"[+] Checkpoint written: {human(n_rows)} rows in '{output_filename}'. "
                    f"Resume with:  --resume {output_filename}"))
        sys.exit(130)

    pool.shutdown(wait=True)
    dash.done()

    # -------------------------------------------------------------------------
    # FINAL MERGE, DEDUPLICATE, SORT, WRITE
    # -------------------------------------------------------------------------
    final_rows = merge_rows(done_rows, hydrated_existing,
                            list(pending_existing.values()),
                            [placeholder_row(c) for c in pending_new.values()])
    final_headers = build_headers(final_rows, extra_headers=existing_headers)

    try:
        atomic_write_csv(output_filename, final_headers, final_rows, write_delim)
    except Exception as e:
        print(red(f"\n[!] FILE WRITE ERROR: {e}\n"))
        sys.exit(1)

    total_dur = time.time() - t_start
    rate = completed / (time.time() - p2_start) if completed else 0.0
    print("\n" + dim("─" * 75))
    print(green(bold(f" ✔ EXPORT COMPLETE — {human(len(final_rows))} cases in {fmt_dur(total_dur)}")))
    print(dim("─" * 75))
    print(f"   {dim('New cases exported')}        {human(new_done)}")
    print(f"   {dim('Existing rows re-hydrated')} {human(rehydrated_done)}")
    print(f"   {dim('Carried over unchanged')}    {human(len(hydrated_existing))}")
    if skipped_span > 0:
        print(f"   {dim('Window fast-forwarded')}     {skipped_span / 86400:.1f} days skipped")
    print(f"   {dim('API calls / throttled')}     {human(stats.get('api'))} / "
          f"{human(stats.get('throttle'))}   {dim('(token refreshes: ' + str(stats.get('token_refresh')) + ')')}")
    print(f"   {dim('Hydration rate')}            {rate:.1f} cases/sec")
    print(f"   {dim('File')}                      {bold(output_filename)}  "
          f"({len(final_headers)} columns, '{write_delim}' delimited)")
    print(dim("─" * 75) + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(yellow("\n[!] Aborted."))
        sys.exit(130) 
