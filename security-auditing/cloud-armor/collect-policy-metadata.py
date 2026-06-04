#!/usr/bin/env python3
"""
Searce Cloud Armor Policy Audit Tool — v1.0
READ-ONLY audit of Cloud Armor policies, rules, and targets across GCP projects.
Replaces: working_get_armor_rules.sh
Why faster: Runs all projects in PARALLEL using threads.
              Bash script is sequential (one project at a time).
              This script scans 143 projects simultaneously.
Output CSV columns (identical to bash script):
  Project Name, Policy Name, Target Count, Target List (Pipe Separated),
  Adaptive Protection, Log Level, JSON Parsing, Rules active or in preview,
  Status (action), Match Expression, Rule Description, Priority
Usage:
  python3 armor_audit.py -f projects.txt
  python3 armor_audit.py -f projects.txt -o my_report.csv
  python3 armor_audit.py -f projects.txt --threads 20
Safety:
  - ZERO write/create/delete calls.
  - Uses compute.securityPolicies.get and compute.backendServices.aggregatedList only.
  - Will NOT enable any APIs — if API is disabled, the project is skipped cleanly.
"""
import sys, os, csv, re, json, time, logging, argparse, threading
import concurrent.futures
import zoneinfo
from datetime import datetime, timezone
from pathlib import Path

# Suppress gRPC / auth noise in stderr
logging.getLogger("google.auth.transport.grpc").setLevel(logging.CRITICAL)
logging.getLogger("grpc._plugin_wrapping").setLevel(logging.CRITICAL)
logging.basicConfig(level=logging.CRITICAL)

try:
    import google.auth
    import google.auth.exceptions
    from google.cloud import compute_v1
    from google.api_core import exceptions as gex
    from tqdm import tqdm
except ImportError as e:
    print(f"\n❌ Missing dependency: {e}")
    print("   Run: pip install google-cloud-compute tqdm\n")
    sys.exit(1)

# ═══════════════════════════════════════════════
# ANSI Color helpers (same as fast_armor_analyzer)
# ═══════════════════════════════════════════════
class C:
    B="\033[1m"; R="\033[0m"; G="\033[32m"; Y="\033[33m"
    RD="\033[31m"; D="\033[90m"; CN="\033[36m"; M="\033[35m"

_print_lock = threading.Lock()
def tprint(msg):
    with _print_lock:
        print(msg, flush=True)

# ═══════════════════════════════════════════════
# DEFAULTS (Updated with dynamic IST filename)
# ═══════════════════════════════════════════════
ist_tz = zoneinfo.ZoneInfo("Asia/Kolkata")
current_time = datetime.now(ist_tz)
time_prefix = current_time.strftime("%d-%b-%Y-%H:%M").lower()
custom_filename = f"{time_prefix}_ist_cloud_armor_audit.csv"

DEFAULTS = {
    "output": custom_filename,
    "threads": 10,
    "max_threads": 20,
}

PID_RE = re.compile(r"^[a-z][a-z0-9\-]{0,28}[a-z0-9]$")

# ═══════════════════════════════════════════════
# CREDENTIAL INIT (shared, thread-safe)
# ═══════════════════════════════════════════════
_creds = None
_creds_lock = threading.Lock()

def get_credentials():
    global _creds
    with _creds_lock:
        if _creds is None:
            try:
                _creds, _ = google.auth.default(
                    scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"]
                )
                print(f"  {C.G}✅ Credentials initialized.{C.R}")
            except google.auth.exceptions.DefaultCredentialsError:
                print(f"  {C.RD}❌ No credentials found.")
                print(f"     Run: gcloud auth application-default login{C.R}")
                sys.exit(1)
        return _creds

# ═══════════════════════════════════════════════
# CORE: Audit a single project
# ═══════════════════════════════════════════════
def audit_project(pid: str) -> list[list]:
    """
    Returns a list of CSV rows for this project.
    Each row = one rule in one policy.
    """
    rows = []
    creds = get_credentials()

    # ── Step 1: List policies ──
    try:
        sp_client = compute_v1.SecurityPoliciesClient(credentials=creds)
        policies = list(sp_client.list(project=pid))
    except gex.PermissionDenied as e:
        reason = "API_DISABLED" if "is disabled" in str(e) or "accessNotConfigured" in str(e) else "PERMISSION_DENIED"
        tprint(f"  {C.Y}⚠ {pid}: {reason}{C.R}")
        return [[pid, reason, "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"]]
    except gex.Forbidden as e:
        tprint(f"  {C.Y}⚠ {pid}: FORBIDDEN — {str(e)[:60]}{C.R}")
        return [[pid, "PERMISSION_DENIED", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"]]
    except google.auth.exceptions.RefreshError:
        tprint(f"  {C.RD}⚠ {pid}: Auth expired — run: gcloud auth application-default login{C.R}")
        return [[pid, "AUTH_ERROR", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"]]
    except Exception as e:
        msg = str(e).lower()
        if "metadata" in msg or "email" in msg:
            tprint(f"  {C.RD}⚠ {pid}: Metadata auth error — run: gcloud auth application-default login{C.R}")
        else:
            tprint(f"  {C.RD}⚠ {pid}: {str(e)[:80]}{C.R}")
        return [[pid, "ERROR", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"]]

    if not policies:
        return []  # No policies — skip, don't add empty row

    # ── Step 2: Build policy → backend map ──
    policy_targets: dict[str, list[str]] = {}
    try:
        bs_client = compute_v1.BackendServicesClient(credentials=creds)
        for scope, scoped_list in bs_client.aggregated_list(project=pid):
            if not scoped_list.backend_services:
                continue
            for bs in scoped_list.backend_services:
                if bs.security_policy:
                    pol = bs.security_policy.split("/")[-1]
                    policy_targets.setdefault(pol, []).append(bs.name)
    except Exception:
        pass  # Backend mapping is best-effort; API errors here don't block rule output

    # ── Step 3: Emit one row per rule ──
    for policy in policies:
        pol_name = policy.name
        # Adaptive Protection
        try:
            ap = str(policy.adaptive_protection_config.layer7_ddos_defense_config.enable)
        except Exception:
            ap = "Disabled"
        # Advanced Options
        try:
            log_level = policy.advanced_options_config.log_level or "Standard"
        except Exception:
            log_level = "Standard"
        try:
            json_parsing = policy.advanced_options_config.json_parsing or "Disabled"
        except Exception:
            json_parsing = "Disabled"
        # Targets
        targets = policy_targets.get(pol_name, [])
        target_count = len(targets)
        target_list = " | ".join(targets) if targets else "None"

        for rule in policy.rules:
            preview_status = "Preview" if rule.preview else "Active"
            action = rule.action or "N/A"
            priority = rule.priority
            # Match expression
            expr = "N/A"
            try:
                if rule.match.expr.expression:
                    expr = rule.match.expr.expression.replace("\r", " ").replace("\n", " ")
                elif rule.match.versioned_expr:
                    expr = rule.match.versioned_expr
            except Exception:
                pass
            description = (rule.description or "N/A").replace(",", "")

            rows.append([
                pid, pol_name,
                target_count, target_list,
                ap, log_level, json_parsing,
                preview_status, action,
                expr, description, priority,
            ])
    return rows

# ═══════════════════════════════════════════════
# PROJECT LOADING
# ═══════════════════════════════════════════════
def load_projects(args) -> list[str]:
    raw = []
    if args.projects_file:
        try:
            with open(args.projects_file) as f:
                raw = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
            print(f"  📂 Loaded {len(raw)} project IDs from {args.projects_file}")
        except FileNotFoundError:
            print(f"  {C.RD}❌ File not found: {args.projects_file}{C.R}"); sys.exit(1)
    else:
        try:
            raw = [x.strip() for x in input(f"\n  {C.B}▶ Project IDs (comma-separated): {C.R}").split(",") if x.strip()]
        except (KeyboardInterrupt, EOFError):
            print("\n  👋"); sys.exit(0)

    if not raw:
        print(f"  {C.RD}❌ No project IDs provided.{C.R}"); sys.exit(1)

    seen, valid, bad = set(), [], []
    for p in raw:
        pl = p.lower().strip()
        if pl in seen: continue
        seen.add(pl)
        if PID_RE.match(pl): valid.append(pl)
        else: bad.append(p)

    if bad:
        print(f"  {C.Y}⚠ Skipping {len(bad)} invalid IDs: {bad[:5]}...{C.R}")
    if not valid:
        print(f"  {C.RD}❌ No valid project IDs found.{C.R}"); sys.exit(1)

    print(f"  ✅ {len(valid)} valid project(s) ready.")
    return sorted(valid)

# ═══════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════
def parse_args():
    p = argparse.ArgumentParser(description="Searce Cloud Armor Audit Tool — v1.0")
    p.add_argument("-f", "--projects-file", help="File with project IDs (one per line)")
    p.add_argument("-o", "--output", default=DEFAULTS["output"], help="Output CSV path")
    p.add_argument("--threads", type=int, default=DEFAULTS["threads"], help="Parallel threads (default: 10)")
    return p.parse_args()

def main():
    args = parse_args()
    print(f"\n{C.B}{C.CN}{'━'*70}")
    print(f"  ☁️  Searce Cloud Armor Audit Tool v1.0")
    print(f"{'━'*70}{C.R}")
    print(f"  🔒 READ-ONLY — ZERO infrastructure changes")
    print(f"  ⚡ Threads    : {args.threads} parallel (vs. bash: 1 sequential)")
    print(f"  💾 Output     : {args.output}")
    print(f"{C.CN}{'━'*70}{C.R}")

    # Init credentials early (fail fast before project scan)
    get_credentials()

    projects = load_projects(args)
    t0 = time.time()

    # CSV Header — identical to bash script output
    header = [
        "Project Name", "Policy Name",
        "Target Count", "Target List (Pipe Separated)",
        "Adaptive Protection", "Log Level", "JSON Parsing",
        "Rules active or in preview", "Status",
        "Match Expression", "Rule Description", "Priority",
    ]

    try:
        csv_fh = open(args.output, "w", newline="", encoding="utf-8")
    except PermissionError:
        print(f"  {C.RD}❌ Cannot write to {args.output}{C.R}"); sys.exit(1)
    
    csv_writer = csv.writer(csv_fh, quoting=csv.QUOTE_ALL)
    csv_writer.writerow(header)
    
    _csv_lock = threading.Lock()
    total_rows = 0
    errors = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        fm = {ex.submit(audit_project, pid): pid for pid in projects}
        pbar = tqdm(
            concurrent.futures.as_completed(fm),
            total=len(projects),
            desc=f"  {C.CN}Scanning projects{C.R}",
            unit="project", ncols=80,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
        )
        for future in pbar:
            pid = fm[future]
            try:
                rows = future.result()
                if rows:
                    with _csv_lock:
                        for row in rows:
                            csv_writer.writerow(row)
                        csv_fh.flush()

                    rule_rows = [r for r in rows if "ERROR" not in str(r[1]) and "DENIED" not in str(r[1])]
                    if rule_rows:
                        nonlocal_hits = len(rule_rows)
                        tprint(f"  {C.G}✅ {pid}: {nonlocal_hits} rule(s) written{C.R}")
                        total_rows += nonlocal_hits
                    else:
                        errors += 1
            except Exception as e:
                errors += 1
                tprint(f"  {C.RD}❌ {pid}: {e}{C.R}")
    
    csv_fh.close()
    elapsed = time.time() - t0

    print(f"\n{C.B}{'═'*70}")
    print(f"  📈 AUDIT COMPLETE")
    print(f"{'═'*70}{C.R}")
    print(f"  ✅ Projects scanned : {len(projects)}")
    print(f"  📋 Rules written    : {total_rows}")
    print(f"  ⚠️  Errors/Skipped  : {errors}")
    print(f"  ⏱  Time taken      : {elapsed:.1f}s  (bash would take ~{len(projects)*3:.0f}s+)")
    print(f"  💾 Report saved to  : {args.output}")
    print(f"{C.CN}{'═'*70}{C.R}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n  👋 Interrupted.\n")
        sys.exit(0) 
