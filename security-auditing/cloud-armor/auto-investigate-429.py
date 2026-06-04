#!/usr/bin/env python3
import sys
import os
import csv
import json
import requests
import urllib.parse
import re
import uuid
import time
import random
from datetime import datetime, timedelta, timezone
from collections import Counter, defaultdict

# Dependency Check
try:
    from google.cloud import logging
    from ipwhois import IPWhois
    import google.api_core.exceptions
except ImportError as e:
    print(f"❌ CRITICAL ERROR: Missing dependency: {e}")
    print("Please run: pip install google-cloud-logging requests ipwhois")
    sys.exit(1)

# --- CONFIGURATION ---
WEBHOOK_URL = os.getenv("GC_WEBHOOK_URL", "https://chat.googleapis.com/v1/spaces/YOUR_SPACE_ID/messages?key=YOUR_API_KEY&token=YOUR_TOKEN")
CSV_FILENAME = "cloud_armor_incident_log.csv"
RULE_INVENTORY_PATH = os.getenv("RULE_INVENTORY_PATH", "armor-rule-inventory.json")
MAX_LOG_LIMIT = 50000 

class IncidentAnalyzer:
    def __init__(self):
        print("\n🛡️  Cloud Armor Incident Auto-Investigator (v24.0 - Webhook Auto-Fix)")
        print("===================================================================")
        self.webhook_url = self.sanitize_webhook_url(WEBHOOK_URL) # Auto-fix logic
        self.rule_inventory = self.load_rule_inventory()
        self.inputs = self.get_user_inputs()
        self.client = self.init_gcp_client()

    def sanitize_webhook_url(self, url):
        """Removes Markdown brackets []() if the user pasted them by mistake."""
        clean_url = url.strip()
        # Regex to find a clean http/https URL inside a messy string
        match = re.search(r'(https?://[^\s\]\)"\']+)', clean_url)
        if match:
            return match.group(1)
        return clean_url

    def normalize_rule_id(self, rule_input):
        """Production-grade normalization for Rule IDs."""
        raw = str(rule_input).strip()
        if raw.lower() in ["default", "default rule"]:
            return "2147483647"
        try:
            return str(int(float(raw)))
        except ValueError:
            return raw

    def normalize_lookup_key(self, project, policy, priority):
        """Standardizes keys for Inventory Lookup."""
        c_proj = str(project).strip().lower()
        c_pol = str(policy).strip()
        if "/" in c_pol:
            c_pol = c_pol.split("/")[-1]
        c_pol = c_pol.lower()
        c_prio = self.normalize_rule_id(priority)
        return (c_proj, c_pol, c_prio)

    def load_rule_inventory(self):
        inventory = {}
        print(f"📂 Loading Rule Inventory from: {RULE_INVENTORY_PATH}...")
        try:
            with open(RULE_INVENTORY_PATH, mode='r', encoding='utf-8') as f:
                data = json.load(f)
                count = 0
                for entry in data:
                    raw_proj = entry.get('Project Name', '')
                    raw_pol = entry.get('Policy Name', '')
                    raw_prio = entry.get('Priority', '')
                    desc = str(entry.get('Rule Description', 'N/A')).strip()
                    
                    if raw_proj and raw_pol and raw_prio:
                        key = self.normalize_lookup_key(raw_proj, raw_pol, raw_prio)
                        inventory[key] = desc
                        count += 1
                print(f"   ✅ Loaded {count} rules from JSON.")
        except Exception as e:
            print(f"   ⚠️  Error loading inventory: {e}")
        return inventory

    def get_user_inputs(self):
        try:
            print("\n📝 Please extract details from your Alert Email:")
            project_id = input("▶ Project ID: ").strip().strip("'").strip('"')
            if not project_id: raise ValueError("Project ID cannot be empty.")

            lb_name = input("▶ Load Balancer Name: ").strip().strip("'").strip('"')
            if not lb_name: raise ValueError("Load Balancer Name cannot be empty.")

            print("▶ Start Time (Paste exactly from email, e.g Feb 1, 2026 at 4:00AM UTC):")
            raw_time = input("  Input Time: ").strip().strip("'").strip('"')
            
            clean_time = raw_time.replace(" at ", " ").replace("UTC", "")
            clean_time = re.sub(r'\(.*?\)', '', clean_time).strip() 
            
            incident_time = None
            formats = ["%b %d, %Y %I:%M%p", "%b %d, %Y %H:%M", "%Y-%m-%d %H:%M:%S"]
            
            for fmt in formats:
                try:
                    incident_time = datetime.strptime(clean_time, fmt)
                    break
                except ValueError:
                    continue
            
            if not incident_time:
                raise ValueError(f"Could not parse date: '{raw_time}'")

            incident_time = incident_time.replace(tzinfo=timezone.utc)
            
            ip_count_str = input("▶ Number of Top IPs to analyze? (Default 3): ").strip()
            top_n = 3
            if ip_count_str.isdigit():
                top_n = int(ip_count_str)

            url_count_str = input("▶ Number of Top URLs to display? (Default 5): ").strip()
            top_url_n = 5
            if url_count_str.isdigit():
                top_url_n = int(url_count_str)

            print(f"   -> Will analyze Top {top_n} IPs and Top {top_url_n} URLs.")

            return {
                "project_id": project_id,
                "lb_name": lb_name,
                "start_time": incident_time,
                "raw_time_str": raw_time,
                "top_n": top_n,
                "top_url_n": top_url_n
            }
        except Exception as e:
            print(f"\n❌ INPUT ERROR: {e}")
            sys.exit(1)

    def init_gcp_client(self):
        try:
            return logging.Client(project=self.inputs['project_id'])
        except Exception as e:
            print(f"❌ GCP ERROR: {e}")
            sys.exit(1)

    def run_analysis(self):
        lb = self.inputs['lb_name']
        start_time = self.inputs['start_time']
        start_window = start_time - timedelta(minutes=30)
        end_window = start_time + timedelta(minutes=15)
        
        print(f"\n🔍 Starting analysis for LB: {lb}")
        print(f"   Analysis Window: {start_window.strftime('%H:%M')} to {end_window.strftime('%H:%M')} UTC")
        
        print(f"📡 Phase 1: Scanning for Top {self.inputs['top_n']} Offenders...")
        logs_p1 = self.fetch_logs_with_retry(start_window, end_window, phase="Phase 1")
        
        if not logs_p1:
            print(f"\n❌ No 429 logs found. Exiting.")
            return

        top_ips = self.extract_top_ips(logs_p1)
        if not top_ips:
            print("⚠️ No IPs found in logs.")
            return

        print(f"   -> Identified Bad Actors: {top_ips}")

        print(f"🕵️  Phase 2: Fetching ALL traffic for these IPs...")
        logs_p2 = self.fetch_logs_with_retry(start_window, end_window, target_ips=top_ips, phase="Phase 2")

        print("🔄 Grouping logs by Backend Service...")
        backend_groups = self.group_logs_by_backend(logs_p2)
        print(f"   -> Found activity on {len(backend_groups)} Backend Services.")

        for backend, b_logs in backend_groups.items():
            print(f"\n⚙️  Analyzing Backend: {backend}")
            backend_analysis = self.analyze_backend_logs(b_logs, top_ips)
            enriched_data = self.enrich_with_whois(backend_analysis)
            
            log_link = self.generate_log_link(start_window, end_window, backend_filter=backend)
            self.save_to_csv(backend, enriched_data, log_link)
            self.send_single_backend_webhook(backend, enriched_data, log_link, len(b_logs))

        print("\n✅ Analysis Complete. Check Google Chat.")

    def fetch_logs_with_retry(self, start, end, target_ips=None, phase="Phase 1"):
        filter_str = (
            f'resource.type="http_load_balancer" '
            f'AND resource.labels.url_map_name="{self.inputs["lb_name"]}" '
        )
        if phase == "Phase 1":
            filter_str += f' AND httpRequest.status=429'
        elif phase == "Phase 2" and target_ips:
            ip_conditions = []
            for ip in target_ips:
                ip_conditions.append(f'jsonPayload.remoteIp="{ip}"')
                ip_conditions.append(f'httpRequest.remoteIp="{ip}"')
            ip_part = " OR ".join(ip_conditions)
            filter_str += f' AND ({ip_part})'

        filter_str += f' AND timestamp >= "{start.isoformat()}" AND timestamp <= "{end.isoformat()}"'

        max_retries = 3
        for attempt in range(max_retries):
            try:
                iterator = self.client.list_entries(filter_=filter_str, page_size=1000, max_results=MAX_LOG_LIMIT)
                results = list(iterator)
                return results
            except Exception as e:
                err_msg = str(e)
                if "503" in err_msg or "metadata" in err_msg or "Transport" in err_msg:
                    wait_time = (2 ** attempt) + random.uniform(0, 1)
                    print(f"⚠️  API Glitch ({err_msg}). Retrying in {wait_time:.1f}s...")
                    time.sleep(wait_time)
                else:
                    print(f"❌ {phase} Failed Permanently: {e}")
                    sys.exit(1)
        sys.exit(1)

    def extract_top_ips(self, logs):
        ip_counter = Counter()
        for entry in logs:
            try:
                payload = entry.payload if isinstance(entry.payload, dict) else {}
                http_req = entry.http_request or {}
                ip = payload.get('remoteIp') or http_req.get('remoteIp')
                if ip: ip_counter[ip] += 1
            except Exception:
                continue 
        return [ip for ip, _ in ip_counter.most_common(self.inputs['top_n'])]

    def group_logs_by_backend(self, logs):
        groups = defaultdict(list)
        for entry in logs:
            labels = entry.resource.labels if entry.resource else {}
            backend = labels.get('backend_service_name', 'Unknown/Edge')
            groups[backend].append(entry)
        return groups

    def analyze_backend_logs(self, logs, target_ips):
        data = {
            ip: {
                'total': 0, 'accepted': 0, 'denied': 0, 
                'rules': Counter(), 'uris': Counter(), 'policies': set()
            } for ip in target_ips
        }
        target_ip_set = set(target_ips)

        for entry in logs:
            try:
                payload = entry.payload if isinstance(entry.payload, dict) else {}
                http_req = entry.http_request or {}
                ip = payload.get('remoteIp') or http_req.get('remoteIp')
                if ip not in target_ip_set: continue
                
                data[ip]['total'] += 1
                status = http_req.get('status')
                uri = http_req.get('requestUrl')
                if uri: data[ip]['uris'][uri.split('?')[0]] += 1
                
                if status and 200 <= status < 300:
                    data[ip]['accepted'] += 1
                else:
                    data[ip]['denied'] += 1
                    policy_data = payload.get('enforcedSecurityPolicy', {})
                    rule = policy_data.get('priority', 'Default')
                    data[ip]['rules'][self.normalize_rule_id(rule)] += 1
                    
                    p_name = policy_data.get('name') or policy_data.get('policyName')
                    if p_name: data[ip]['policies'].add(p_name)
            except Exception:
                continue
        return {ip: stats for ip, stats in data.items() if stats['total'] > 0}

    def enrich_with_whois(self, data):
        print("   -> Running WHOIS...")
        for ip in data:
            try:
                obj = IPWhois(ip)
                res = obj.lookup_rdap(depth=1)
                data[ip]['country'] = res.get('asn_country_code', 'Unknown')
                data[ip]['isp'] = res.get('network', {}).get('name', 'Unknown')
            except:
                data[ip]['country'] = "Unknown"
                data[ip]['isp'] = "Unknown"
        return data

    def generate_log_link(self, start, end, backend_filter=None):
        query = (
            f'resource.type="http_load_balancer" '
            f'resource.labels.url_map_name="{self.inputs["lb_name"]}" '
        )
        if backend_filter and backend_filter != "Unknown/Edge":
            query += f' resource.labels.backend_service_name="{backend_filter}"'
        encoded = urllib.parse.quote(query)
        t_fmt = "%Y-%m-%dT%H:%M:%SZ"
        return f"https://console.cloud.google.com/logs/query;query={encoded};timeRange={start.strftime(t_fmt)}/{end.strftime(t_fmt)}?project={self.inputs['project_id']}"

    def save_to_csv(self, backend, data, log_link):
        try:
            with open(CSV_FILENAME, 'a', newline='') as f:
                writer = csv.writer(f, delimiter='|')
                for ip, info in data.items():
                    rules_str = " ; ".join([f"{k}({v})" for k,v in info['rules'].items()])
                    uris_str = " ; ".join([u for u,c in info['uris'].most_common(self.inputs['top_url_n'])])
                    writer.writerow([
                        datetime.now().strftime("%Y-%m-%d %H:%M"),
                        backend, ip, info['country'], info['isp'],
                        info['total'], info['accepted'], info['denied'],
                        rules_str, uris_str, log_link
                    ])
        except Exception as e:
            print(f"⚠️ CSV Error: {e}")

    def send_single_backend_webhook(self, backend, data, log_link, total_hits_in_backend):
        print(f"📨 Sending Report for {backend}...")
        sections = []
        header_text = (
            f"<b>🚨 Analysis:</b><br>"
            f"<b>Project:</b> {self.inputs['project_id']}<br>"
            f"<b>LB:</b> {self.inputs['lb_name']}<br>"
            f"<b>Backend Service:</b> <font color=\"#ff9900\">{backend}</font><br>"
            f"<b>Traffic Analyzed (Total Logs Count):</b> {total_hits_in_backend}<br>"
            f"<b>Alert Trigger Time:</b> {self.inputs['raw_time_str']}"
        )
        sections.append({"widgets": [{"textParagraph": {"text": header_text}}]})

        for i, (ip, info) in enumerate(data.items(), 1):
            rows_html = ""
            active_policy = next(iter(info['policies'])) if info['policies'] else "Unknown"
            
            for rule_id, count in info['rules'].most_common(5):
                lookup_key = self.normalize_lookup_key(self.inputs['project_id'], active_policy, rule_id)
                description = self.rule_inventory.get(lookup_key, "N/A")
                if len(description) > 30: description = description[:27] + "..."
                # HTML Row (Bold Rule ID | Desc | Count)
                rows_html += f"• <b>{rule_id}</b> | {description} | <b>{count}</b><br>"

            top_urls_list = info['uris'].most_common(self.inputs['top_url_n'])
            url_lines = [f"&nbsp;&nbsp;{x+1}. {u} ({c})" for x, (u,c) in enumerate(top_urls_list)]
            urls_formatted = "<br>".join(url_lines) if url_lines else "N/A"
            policy_txt = ", ".join(info['policies']) if info['policies'] else "Unknown"

            card_content = (
                f"<b><font color=\"#4285F4\">#{i} IP: {ip}</font></b> ({info['country']} - {info['isp']})<br>"
                f"--------------------------------------------------<br>"
                f"<b>📊 Traffic Stats:</b><br>"
                f"&nbsp;&nbsp;• Total Requests: <b>{info['total']}</b><br>"
                f"&nbsp;&nbsp;• <font color=\"#1e8e3e\">Accepted: {info['accepted']}</font><br>"
                f"&nbsp;&nbsp;• <font color=\"#d93025\">Denied: {info['denied']}</font><br><br>"
                f"<b>🛡️ Policy:</b> {policy_txt}<br><br>"
                f"<b>🚫 Blocked By (Rule | Desc | Count):</b><br>"
                f"{rows_html}<br>"
                f"<b>🌐 Top {self.inputs['top_url_n']} Targets:</b><br>"
                f"{urls_formatted}"
            )
            sections.append({"widgets": [{"textParagraph": {"text": card_content}}]})

        sections.append({
            "widgets": [{
                "buttons": [{
                    "textButton": {
                        "text": f"🔎 LOGS: {backend}",
                        "onClick": {"openLink": {"url": log_link}}
                    }
                }]
            }]
        })
        
        # Use SANITIZED URL
        thread_key = f"incident-{uuid.uuid4()}"
        url_with_thread = f"{self.webhook_url}&threadKey={thread_key}"
        
        try:
            r = requests.post(url_with_thread, json={"cards": [{"sections": sections}]})
            if r.status_code == 200:
                print(f"✅ Sent {backend} report.")
            else:
                print(f"⚠️ Webhook Failed: {r.status_code} {r.text}")
        except Exception as e:
            print(f"⚠️ Webhook Error: {e}")

if __name__ == "__main__":
    IncidentAnalyzer().run_analysis()
