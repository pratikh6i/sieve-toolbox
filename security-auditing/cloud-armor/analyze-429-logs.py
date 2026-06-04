#!/usr/bin/env python3
import sys
import os
import csv
import re
import json
import time
import random
import subprocess
from datetime import datetime, timedelta, timezone
from collections import Counter, defaultdict

try:
    from google.cloud import logging
    from google.api_core.exceptions import ResourceExhausted, ServiceUnavailable, InternalServerError
    from ipwhois import IPWhois
except ImportError as e:
    print(f"❌ CRITICAL ERROR: Missing dependency: {e}")
    print("Please run: pip install google-cloud-logging ipwhois")
    sys.exit(1)

# --- CONFIGURATION ---
INPUT_CSV = "alerts_export.csv" 
OUTPUT_CSV = "Cloud_Armor_Master_Report.csv"
RULE_INVENTORY_PATH = os.getenv("RULE_INVENTORY_PATH", "armor-rule-inventory.json")
MAX_LOG_LIMIT = 50000 
TOP_N_IPS = 3
TOP_N_URLS = 5

class MasterArmorAnalyzer:
    def __init__(self):
        print("\n🛡️  Cloud Armor Master Analyzer (100% Precision Mode)")
        print("==========================================================")
        self.gcp_clients = {}
        self.ip_cache = {} # Drastically speeds up WHOIS lookups
        self.rule_inventory = self.load_inventory()
        
    def load_inventory(self):
        """Loads and maps the Cloud Armor JSON inventory for fast lookups."""
        print(f"🔄 Syncing Cloud Armor Rule Inventory...")
        inventory = {}
        try:
            with open(RULE_INVENTORY_PATH, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for entry in data:
                    pol = str(entry.get("Policy Name", "")).lower()
                    prio = str(entry.get("Priority", ""))
                    desc = entry.get("Rule Description", "N/A")
                    if pol and prio:
                        inventory[f"{pol}_{prio}"] = desc
            print(f"   ✅ Successfully mapped {len(inventory)} rules into memory.")
        except Exception as e:
            print(f"   ⚠️ Could not load inventory JSON ({e}). Will output raw Rule IDs.")
        return inventory

    def get_rule_description(self, policy_name, priority):
        """Fetches human-readable description from inventory."""
        if str(priority).lower() == "default" or str(priority) == "2147483647":
            return "Default Rule (Deny/Allow)"
        
        pol_clean = str(policy_name).split('/')[-1].lower() if policy_name else ""
        key = f"{pol_clean}_{priority}"
        return self.rule_inventory.get(key, "Unknown Custom Rule")

    def parse_duration(self, duration_str):
        days = hours = mins = secs = 0
        if d_match := re.search(r'(\d+)\s*day', duration_str): days = int(d_match.group(1))
        if h_match := re.search(r'(\d+)\s*hour', duration_str): hours = int(h_match.group(1))
        if m_match := re.search(r'(\d+)\s*min', duration_str): mins = int(m_match.group(1))
        if s_match := re.search(r'(\d+)\s*sec', duration_str): secs = int(s_match.group(1))
        return timedelta(days=days, hours=hours, minutes=mins, seconds=secs)

    def extract_email_data(self, body_text):
        try:
            p_match = re.search(r"project_id\s*:\s*([^\s]+)", body_text)
            project_id = p_match.group(1).strip() if p_match else None

            l_match = re.search(r"url_map_name\s*:\s*([^\s]+)", body_text)
            lb_name = l_match.group(1).strip() if l_match else None

            t_match = re.search(r"\*Start time\*\s*\n(.+?)(?:\s*\(|$)", body_text)
            raw_time = t_match.group(1).strip() if t_match else None

            d_match = re.search(r"duration\s*:\s*(.+?)\n", body_text)
            duration_str = d_match.group(1).strip() if d_match else None

            if not (project_id and lb_name and raw_time): return None

            clean_time = raw_time.replace(" at ", " ").replace("UTC", "").strip()
            incident_time = datetime.strptime(clean_time, "%B %d, %Y %I:%M%p").replace(tzinfo=timezone.utc)

            return {"project_id": project_id, "lb_name": lb_name, "start_time": incident_time, "duration_str": duration_str}
        except Exception: return None

    def load_and_pair_incidents(self, csv_filepath):
        print(f"📂 Loading alerts from {csv_filepath}...")
        incidents = {}

        try:
            with open(csv_filepath, mode='r', encoding='utf-8') as file:
                sample = file.read(2048)
                file.seek(0)
                delimiter = '||' if '||' in sample else ','
                lines = file.readlines()
        except FileNotFoundError:
            print(f"❌ ERROR: File '{csv_filepath}' not found.")
            sys.exit(1)

        for row in lines[1:]:
            cols = [c.strip().strip('"') for c in row.split(delimiter)]
            if len(cols) < 4: continue
            
            subject, body = cols[2], cols[3]
            data = self.extract_email_data(body)
            if not data: continue

            # Primary Key to link ALERT and RESOLVED emails together
            key = f"{data['project_id']}_{data['lb_name']}_{data['start_time'].isoformat()}"
            
            if key not in incidents:
                incidents[key] = {
                    "project_id": data['project_id'],
                    "lb_name": data['lb_name'],
                    "alert_start": data['start_time'],
                    "duration": timedelta(minutes=5) # Default fallback
                }

            if "[RESOLVED" in subject and data['duration_str']:
                incidents[key]["duration"] = self.parse_duration(data['duration_str'])

        print(f"✅ Paired into {len(incidents)} precise incident windows.")
        return incidents

    def fetch_logs_with_retry(self, project_id, lb_name, start, end, target_ips=None):
        if project_id not in self.gcp_clients:
            self.gcp_clients[project_id] = logging.Client(project=project_id)
        client = self.gcp_clients[project_id]

        filter_str = f'resource.type="http_load_balancer" AND resource.labels.url_map_name="{lb_name}" '
        if target_ips:
            ip_conditions = [f'jsonPayload.remoteIp="{ip}"' for ip in target_ips] + [f'httpRequest.remoteIp="{ip}"' for ip in target_ips]
            filter_str += f' AND ({" OR ".join(ip_conditions)})'
        else:
            filter_str += f' AND httpRequest.status=429'
        filter_str += f' AND timestamp >= "{start.isoformat()}" AND timestamp <= "{end.isoformat()}"'

        for attempt in range(5):
            try:
                return list(client.list_entries(filter_=filter_str, page_size=1000, max_results=MAX_LOG_LIMIT))
            except (ResourceExhausted, ServiceUnavailable, InternalServerError) as e:
                wait_time = (2 ** attempt) + random.uniform(1, 3)
                print(f"      ⚠️ GCP API Quota hit. Sleeping {wait_time:.1f}s...")
                time.sleep(wait_time)
            except Exception as e:
                print(f"      ❌ Unhandled GCP Error: {e}")
                return []
        return []

    def lookup_ip(self, ip):
        """Fetches Country/ISP with high-speed memory caching."""
        if ip in self.ip_cache: return self.ip_cache[ip]
        try:
            res = IPWhois(ip).lookup_rdap(depth=1)
            data = (res.get('asn_country_code', 'Unknown'), res.get('network', {}).get('name', 'Unknown'))
        except: data = ("Unknown", "Unknown")
        self.ip_cache[ip] = data
        return data

    def analyze_incident(self, incident):
        project, lb, start_time = incident['project_id'], incident['lb_name'], incident['alert_start']
        analysis_start = start_time - timedelta(minutes=20)
        analysis_end = start_time + incident['duration'] + timedelta(minutes=5)
        
        print(f"   -> Scope: -20m to +5m | {analysis_start.strftime('%H:%M')} to {analysis_end.strftime('%H:%M')} UTC")

        logs_p1 = self.fetch_logs_with_retry(project, lb, analysis_start, analysis_end)
        if not logs_p1: return []

        ip_counter = Counter()
        for entry in logs_p1:
            try:
                ip = (entry.payload or {}).get('remoteIp') or (entry.http_request or {}).get('remoteIp')
                if ip: ip_counter[ip] += 1
            except: pass 
            
        top_ips = [ip for ip, _ in ip_counter.most_common(TOP_N_IPS)]
        if not top_ips: return []

        print(f"      🕵️ Found bad actors: {top_ips}. Fetching full traffic...")

        logs_p2 = self.fetch_logs_with_retry(project, lb, analysis_start, analysis_end, target_ips=top_ips)
        data = {ip: {'total': 0, 'accepted': 0, 'denied': 0, 'rules': defaultdict(int), 'uris': Counter(), 'backend': 'Unknown'} for ip in top_ips}

        for entry in logs_p2:
            try:
                payload = entry.payload if isinstance(entry.payload, dict) else {}
                http_req = entry.http_request or {}
                ip = payload.get('remoteIp') or http_req.get('remoteIp')
                if ip not in data: continue
                
                data[ip]['total'] += 1
                status = http_req.get('status')
                uri = http_req.get('requestUrl')
                if uri: data[ip]['uris'][uri.split('?')[0]] += 1
                data[ip]['backend'] = (entry.resource.labels if entry.resource else {}).get('backend_service_name', 'Unknown')

                if status and 200 <= status < 300:
                    data[ip]['accepted'] += 1
                else:
                    data[ip]['denied'] += 1
                    pol_data = payload.get('enforcedSecurityPolicy', {})
                    pol_name = pol_data.get('name') or pol_data.get('policyName', 'Unknown')
                    rule = str(pol_data.get('priority', 'Default'))
                    desc = self.get_rule_description(pol_name, rule)
                    
                    # Store descriptive format for the report
                    data[ip]['rules'][f"ID {rule}: {desc}"] += 1
            except: pass

        results = []
        for ip, stats in data.items():
            if stats['total'] == 0: continue
            
            country, isp = self.lookup_ip(ip)

            # Format as clean multi-line strings for Google Sheets
            rules_formatted = "\n".join([f"• {rule} ({count} hits)" for rule, count in sorted(stats['rules'].items(), key=lambda item: item[1], reverse=True)])
            uris_formatted = "\n".join([f"• {u} ({c} hits)" for u, c in stats['uris'].most_common(TOP_N_URLS)])
            
            # Generate Link
            query = f'resource.type="http_load_balancer" resource.labels.url_map_name="{lb}" jsonPayload.remoteIp="{ip}"'
            encoded = __import__('urllib').parse.quote(query)
            log_link = f"https://console.cloud.google.com/logs/query;query={encoded};timeRange={analysis_start.strftime('%Y-%m-%dT%H:%M:%SZ')}/{analysis_end.strftime('%Y-%m-%dT%H:%M:%SZ')}?project={project}"

            results.append({
                'Incident Start': start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
                'Analysis Window': f"{analysis_start.strftime('%H:%M')} to {analysis_end.strftime('%H:%M')} UTC",
                'Project': project,
                'Load Balancer': lb,
                'Backend': stats['backend'],
                'IP Address': ip,
                'Location': f"{country} ({isp})",
                'Total Reqs': stats['total'],
                'Blocked': stats['denied'],
                'Allowed': stats['accepted'],
                'Top Rules Triggered': rules_formatted,
                'Top Targeted URIs': uris_formatted,
                'Logs Link': log_link
            })
        return results

    def run(self, input_csv):
        incidents = self.load_and_pair_incidents(input_csv)
        
        headers = ['Incident Start', 'Analysis Window', 'Project', 'Load Balancer', 'Backend', 'IP Address', 
                   'Location', 'Total Reqs', 'Blocked', 'Allowed', 'Top Rules Triggered', 'Top Targeted URIs', 'Logs Link']
        
        with open(OUTPUT_CSV, mode='w', newline='', encoding='utf-8') as out_file:
            writer = csv.DictWriter(out_file, fieldnames=headers)
            writer.writeheader()

            for i, (key, incident) in enumerate(incidents.items(), 1):
                print(f"\n⚙️  Processing Alert {i}/{len(incidents)}: {incident['project_id']} | {incident['lb_name']}")
                
                rows = self.analyze_incident(incident)
                if rows:
                    writer.writerows(rows)
                    out_file.flush() 
                    print(f"      ✅ Wrote {len(rows)} attacker IPs to report.")
                
                time.sleep(1.5) # Global rate limit buffer
        
        print(f"\n🎉 MASTER ANALYSIS COMPLETE! Open '{OUTPUT_CSV}' and import to Google Sheets.")

if __name__ == "__main__":
    csv_input = sys.argv[1] if len(sys.argv) > 1 else INPUT_CSV
    MasterArmorAnalyzer().run(csv_input) 
