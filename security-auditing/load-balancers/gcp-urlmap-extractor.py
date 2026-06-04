#!/usr/bin/env python3
"""
GCP URL Map API Extractor — Simple, Fast, Read-Only.
Pulls every configured route from HTTP(S) Load Balancers,
shows the domain, path, backend service, and Cloud Armor policy.
"""
import subprocess
import json
import csv
import sys
import signal
import os

# ─────────────────────────────────────────────────────────────────────
OUTPUT_FILE = "url_map_inventory.csv"

def run(cmd):
    """Run a gcloud command. Returns parsed JSON or empty list."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode == 0 and r.stdout.strip():
            return json.loads(r.stdout.strip())
    except: pass
    return []

def short(url):
    """Extract resource name from a GCP self-link URL."""
    return url.split("/")[-1] if url else "—"

def main():
    print("\n  ══════════════════════════════════════════════")
    print("  \033[1m  🗺️  URL Map API Extractor  |  Read-Only\033[0m")
    print("  ══════════════════════════════════════════════\n")
    raw = input("  Enter GCP Project IDs (comma-separated): ")
    projects = [p.strip() for p in raw.split(",") if p.strip()]
    if not projects:
        print("\n  No project IDs provided.\n")
        sys.exit(1)
    
    all_rows = []
    for proj in projects:
        print(f"\n  \033[94m[*]\033[0m [{proj}] Fetching URL Maps & Backend Services...")
        # 1. Get all URL Maps
        url_maps = run(["gcloud", "compute", "url-maps", "list",
                        f"--project={proj}", "--format=json"])
        
        # 2. Get all Backend Services (for Cloud Armor policy lookup)
        backends = run(["gcloud", "compute", "backend-services", "list",
                        f"--project={proj}", "--format=json"])
        
        # Build backend name → Cloud Armor policy map
        armor_map = {}
        for bs in backends:
            name = bs.get("name", "")
            policy = short(bs.get("securityPolicy", "")) if bs.get("securityPolicy") else "None"
            armor_map[name] = policy
            # Also key by selfLink for direct URL matches
            armor_map[bs.get("selfLink", "")] = policy
            
        if not url_maps:
            print(f"  \033[93m[!]\033[0m [{proj}] No Load Balancers found.")
            continue
            
        count = 0
        for um in url_maps:
            lb = um.get("name", "?")
            # Map pathMatcher name → pathMatcher object
            pm_by_name = {}
            for pm in um.get("pathMatchers", []):
                pm_by_name[pm.get("name", "")] = pm
                
            # Default backend (catch-all when no host matches)
            default_svc = um.get("defaultService", "")
            default_name = short(default_svc)
            default_armor = armor_map.get(default_svc, armor_map.get(default_name, "—"))
            
            host_rules = um.get("hostRules", [])
            # If no host rules, everything goes to default
            if not host_rules:
                all_rows.append([proj, lb, "*", "/*", default_name, default_armor])
                count += 1
                continue
                
            for hr in host_rules:
                hosts = hr.get("hosts", ["*"])
                pm_name = hr.get("pathMatcher", "")
                pm = pm_by_name.get(pm_name, {})
                
                # PathMatcher's default service
                pm_default_svc = pm.get("defaultService", default_svc)
                pm_default_name = short(pm_default_svc)
                pm_default_armor = armor_map.get(pm_default_svc, armor_map.get(pm_default_name, "—"))
                
                # Explicit path rules
                path_rules = pm.get("pathRules", [])
                route_rules = pm.get("routeRules", [])
                
                for host in hosts:
                    # Path rules (e.g., /api/v1/*)
                    for pr in path_rules:
                        svc = pr.get("service", pm_default_svc)
                        svc_name = short(svc)
                        svc_armor = armor_map.get(svc, armor_map.get(svc_name, "—"))
                        for path in pr.get("paths", []):
                            all_rows.append([proj, lb, host, path, svc_name, svc_armor])
                            count += 1
                            
                    # Route rules (advanced matchers)
                    for rr in route_rules:
                        svc = ""
                        action = rr.get("routeAction", {})
                        weighted = action.get("weightedBackendServices", [])
                        if weighted:
                            svc = weighted[0].get("backendService", "")
                        if not svc:
                            svc = rr.get("service", pm_default_svc)
                        svc_name = short(svc)
                        svc_armor = armor_map.get(svc, armor_map.get(svc_name, "—"))
                        
                        matches = rr.get("matchRules", [])
                        for mr in matches:
                            path = (mr.get("prefixMatch")
                                    or mr.get("fullPathMatch")
                                    or mr.get("pathTemplateMatch")
                                    or "/*")
                            all_rows.append([proj, lb, host, path, svc_name, svc_armor])
                            count += 1
                        if not matches:
                            all_rows.append([proj, lb, host, "/*", svc_name, svc_armor])
                            count += 1
                            
                    # Default catch-all for this host
                    all_rows.append([proj, lb, host, "/* (default)", pm_default_name, pm_default_armor])
                    count += 1
                    
        print(f"  \033[92m[✓]\033[0m [{proj}] {count} routes extracted from {len(url_maps)} Load Balancer(s).")
        
    # ── Write CSV ──
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter="|")
        w.writerow(["Project ID", "Load Balancer", "Domain", "Path", "Backend Service", "Cloud Armor Policy"])
        for row in sorted(all_rows, key=lambda r: (r[0], r[1], r[2], r[3])):
            w.writerow(row)
            
    # ── Summary ──
    total = len(all_rows)
    domains = len(set(r[2] for r in all_rows))
    lbs = len(set((r[0], r[1]) for r in all_rows))
    protected = sum(1 for r in all_rows if r[5] not in ("None", "—"))
    unprotected = sum(1 for r in all_rows if r[5] in ("None", "—"))
    policies = sorted(set(r[5] for r in all_rows if r[5] not in ("None", "—")))
    
    print(f"\n  ══════════════════════════════════════════════")
    print(f"  \033[92m[✓]\033[0m \033[1mDONE\033[0m → \033[1m{OUTPUT_FILE}\033[0m")
    print(f"  ──────────────────────────────────────────────")
    print(f"    Load Balancers     : {lbs}")
    print(f"    Unique Domains     : {domains}")
    print(f"    Total Routes       : {total}")
    print(f"    🛡️  With Cloud Armor : \033[92m{protected}\033[0m")
    print(f"    ⚠️  No Cloud Armor   : \033[91m{unprotected}\033[0m")
    if policies:
        print(f"    Policies           : {', '.join(policies)}")
    print(f"  ══════════════════════════════════════════════\n")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    main()
