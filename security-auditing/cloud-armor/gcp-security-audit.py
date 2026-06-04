#!/usr/bin/env python3
import json
import subprocess
import csv
import sys

PROJECTS = [
    "navision-2021", 
    "webcrm-246408", 
    "pickme-dataprod", 
    "pickme-production-210708"
]

def run_gcloud_cmd(command):
    """Executes a gcloud command, forces quiet mode, and prints live progress."""
    # Append --quiet to prevent interactive prompts from hanging the script
    if "--quiet" not in command:
        command.append("--quiet")
        
    print(f"  -> Running: {' '.join(command)}")
    
    try:
        # Added a 30-second timeout so it never freezes forever
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=30)
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        print(f"  ⚠️ Timeout: Command took too long. Skipping.")
        return []
    except subprocess.CalledProcessError as e:
        # If an API isn't enabled or permissions lack, it will print why instead of freezing
        print(f"  ⚠️ Skipped/Error: {e.stderr.strip().split('.')[:1][0]}")
        return []
    except json.JSONDecodeError:
        return []

def extract_name(url):
    if not url:
        return "N/A"
    return url.split('/')[-1]

def build_report():
    report_data = []

    print("🚀 Starting Cloud Armor & Backend Infrastructure Audit...\n")

    for project in PROJECTS:
        print(f"\n📦 [Project: {project}]")
        
        # Core networking elements
        f_rules = run_gcloud_cmd(["gcloud", "compute", "forwarding-rules", "list", f"--project={project}", "--format=json"])
        target_https = run_gcloud_cmd(["gcloud", "compute", "target-https-proxies", "list", f"--project={project}", "--format=json"])
        target_http = run_gcloud_cmd(["gcloud", "compute", "target-http-proxies", "list", f"--project={project}", "--format=json"])
        url_maps = run_gcloud_cmd(["gcloud", "compute", "url-maps", "list", f"--project={project}", "--format=json"])
        backend_services = run_gcloud_cmd(["gcloud", "compute", "backend-services", "list", f"--project={project}", "--format=json"])
        backend_buckets = run_gcloud_cmd(["gcloud", "compute", "backend-buckets", "list", f"--project={project}", "--format=json"])
        vms = run_gcloud_cmd(["gcloud", "compute", "instances", "list", f"--project={project}", "--format=json"])
        cloud_runs = run_gcloud_cmd(["gcloud", "run", "services", "list", f"--project={project}", "--format=json"])

        # Map Backend URL -> Cloud Armor Security Policy
        backend_policy_map = {}
        for bs in backend_services:
            policy = extract_name(bs.get('securityPolicy', ''))
            backend_policy_map[bs['selfLink']] = policy if policy else "None (Exposed/Blind Spot)"

        for bucket in backend_buckets:
            policy = extract_name(bucket.get('securityPolicy', ''))
            backend_policy_map[bucket['selfLink']] = policy if policy else "None (Static Bucket Unprotected)"

        # Map Target Proxies -> URL Maps
        proxy_to_map = {}
        for proxy in (target_https + target_http):
            proxy_to_map[proxy['selfLink']] = proxy.get('urlMap')

        # Map Forwarding Rules (IP Endpoints) -> URL Maps
        ip_to_urlmap = {}
        for rule in f_rules:
            ip = rule.get('IPAddress', 'N/A')
            target_url = rule.get('target', '')
            url_map_url = proxy_to_map.get(target_url)
            if url_map_url:
                ip_to_urlmap[url_map_url] = ip

        # Process Load Balanced Domains via URL Maps
        for um in url_maps:
            um_url = um['selfLink']
            ip_endpoint = ip_to_urlmap.get(um_url, "Multi-bound / Internal Rule")
            
            default_svc = um.get('defaultService', '')
            if default_svc:
                policy = backend_policy_map.get(default_svc, "N/A")
                report_data.append({
                    "Project": project,
                    "Endpoint/IP": ip_endpoint,
                    "Domain/Host": "* (Default Route)",
                    "Entry Type": "Load Balancer",
                    "Backend Name": extract_name(default_svc),
                    "Cloud Armor Policy": policy
                })

            for host_rule in um.get('hostRules', []):
                domains = host_rule.get('hosts', [])
                matcher_name = host_rule.get('pathMatcher', '')
                
                for matcher in um.get('pathMatchers', []):
                    if matcher['name'] == matcher_name:
                        matcher_default = matcher.get('defaultService', '')
                        services_found = set()
                        if matcher_default: services_found.add(matcher_default)
                        for path_rule in matcher.get('pathRules', []):
                            if path_rule.get('service'):
                                services_found.add(path_rule['service'])
                        
                        for domain in domains:
                            for svc in services_found:
                                policy = backend_policy_map.get(svc, "N/A")
                                report_data.append({
                                    "Project": project,
                                    "Endpoint/IP": ip_endpoint,
                                    "Domain/Host": domain,
                                    "Entry Type": "Load Balancer Route",
                                    "Backend Name": extract_name(svc),
                                    "Cloud Armor Policy": policy
                                })

        # Process Direct Exposed VMs
        for vm in vms:
            for interface in vm.get('networkInterfaces', []):
                for ac in interface.get('accessConfigs', []):
                    pub_ip = ac.get('natIP')
                    if pub_ip:
                        report_data.append({
                            "Project": project,
                            "Endpoint/IP": pub_ip,
                            "Domain/Host": "N/A (Direct Instance)",
                            "Entry Type": "Direct VM IP",
                            "Backend Name": f"VM: {vm['name']}",
                            "Cloud Armor Policy": "Not Supported"
                        })

        # Process Serverless Cloud Run Direct Endpoints
        for cr in cloud_runs:
            url = cr.get('status', {}).get('url', 'N/A')
            report_data.append({
                "Project": project,
                "Endpoint/IP": url,
                "Domain/Host": url.replace("https://", ""),
                "Entry Type": "Serverless URL",
                "Backend Name": f"Cloud Run: {cr['metadata']['name']}",
                "Cloud Armor Policy": "Verify IAM/Ingress Policy"
            })

    # Write to CSV
    csv_file = "gcp_master_security_report.csv"
    fields = ["Project", "Endpoint/IP", "Domain/Host", "Entry Type", "Backend Name", "Cloud Armor Policy"]
    
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(report_data)

    print(f"\n✅ Done! Summary file generated: {csv_file}")

if __name__ == "__main__":
    build_report()
