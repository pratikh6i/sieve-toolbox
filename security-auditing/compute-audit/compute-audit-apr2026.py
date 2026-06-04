#!/usr/bin/env python3
"""
GCP Compute Instance Master Audit Scanner
===================================================================
Production-ready, strictly read-only audit script.
Format matched exactly to Pickme Requirements.
Guarantees clean CSV alignment and graceful error handling.
"""

import csv
import logging
import sys
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Tuple

# Configure logging
logging.basicConfig(
    filename='errors.log',
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Suppress noisy logs from underlying Google libraries
logging.getLogger('google').setLevel(logging.ERROR)
logging.getLogger('urllib3').setLevel(logging.ERROR)

try:
    from google.cloud import compute_v1
    from google.cloud import resourcemanager_v3
    from google.cloud import osconfig_v1
    from google.api_core import exceptions as google_exceptions
    from google.api_core.exceptions import ResourceExhausted, TooManyRequests, ServiceUnavailable, Forbidden, PermissionDenied
except ImportError:
    print("Required libraries not installed. Run:")
    print("pip install google-cloud-compute google-cloud-resource-manager google-cloud-os-config")
    sys.exit(1)

# Comprehensive OAuth Scope Mapping
SCOPE_MAPPING = {
    "https://www.googleapis.com/auth/cloud-platform": "cloud-platform (Full API Access)",
    "https://www.googleapis.com/auth/compute": "Compute Engine (Read/Write)",
    "https://www.googleapis.com/auth/compute.readonly": "Compute Engine (Read Only)",
    "https://www.googleapis.com/auth/devstorage.full_control": "Cloud Storage (Full Control)",
    "https://www.googleapis.com/auth/devstorage.read_write": "Cloud Storage (Read/Write)",
    "https://www.googleapis.com/auth/devstorage.read_only": "Cloud Storage (Read Only)",
    "https://www.googleapis.com/auth/bigquery": "BigQuery (Full)",
    "https://www.googleapis.com/auth/logging.write": "Logging (Write)",
    "https://www.googleapis.com/auth/logging.admin": "Logging (Admin)",
    "https://www.googleapis.com/auth/monitoring": "Monitoring (Full)",
    "https://www.googleapis.com/auth/monitoring.write": "Monitoring (Write)",
    "https://www.googleapis.com/auth/pubsub": "Pub/Sub (Full)",
    "https://www.googleapis.com/auth/sqlservice.admin": "Cloud SQL (Admin)",
    "https://www.googleapis.com/auth/datastore": "Datastore (Full)",
    "https://www.googleapis.com/auth/userinfo.email": "User Email (Read)",
    "https://www.googleapis.com/auth/iam": "IAM (Full)",
}

# Configuration
MAX_WORKERS = 5
THROTTLE_SLEEP = 0.4

def parse_url_name(url: str) -> str:
    return url.split("/")[-1] if url else ""

def get_projects_from_org(org_id: str) -> List[str]:
    projects = []
    try:
        client = resourcemanager_v3.ProjectsClient()
        request = resourcemanager_v3.SearchProjectsRequest(query=f"parent:organizations/{org_id}")
        for project in client.search_projects(request=request):
            if project.state == resourcemanager_v3.Project.State.ACTIVE:
                projects.append(project.project_id)
    except Exception as e:
        logger.error(f"Error fetching projects from org {org_id}: {e}")
    return projects

def get_project_iam_policy(project_id: str) -> Dict[str, List[str]]:
    sa_roles = {}
    try:
        client = resourcemanager_v3.ProjectsClient()
        policy = client.get_iam_policy(request=resourcemanager_v3.GetIamPolicyRequest(resource=f"projects/{project_id}"))
        for binding in policy.bindings:
            role = binding.role
            for member in binding.members:
                if member.startswith("serviceAccount:"):
                    sa_email = member.split(":", 1)[1]
                    sa_roles.setdefault(sa_email, []).append(role)
    except Exception as e:
        logger.error(f"IAM policy fetch failed for {project_id}: {e}")
    return sa_roles

def get_static_ips(project_id: str) -> Dict[str, str]:
    static_ips = {}
    try:
        client = compute_v1.AddressesClient()
        request = compute_v1.AggregatedListAddressesRequest(project=project_id)
        for _, response in client.aggregated_list(request=request):
            if response.addresses:
                for addr in response.addresses:
                    if addr.address:
                        static_ips[addr.address] = addr.name or "Unnamed"
    except Exception as e:
        logger.error(f"Static IPs fetch failed for {project_id}: {e}")
    return static_ips

def get_os_inventory(project_id: str, zone: str, instance_name: str) -> Tuple[str, str]:
    try:
        client = osconfig_v1.OsConfigZonalServiceClient()
        inventory_name = f"projects/{project_id}/locations/{zone}/instances/{instance_name}/inventory"
        request = osconfig_v1.GetInventoryRequest(name=inventory_name)
        client.get_inventory(request=request)
        return "TRUE", "TRUE"
    except google_exceptions.NotFound:
        return "FALSE", "N/A"
    except (PermissionDenied, Forbidden) as e:
        if "not enabled" in str(e):
            return "FALSE", "API Disabled"
        return "FALSE", "Permission Denied"
    except Exception:
        return "FALSE", "Unknown Error"

def format_scopes(scopes: List[str]) -> str:
    if not scopes:
        return "None"
    formatted = []
    for scope in scopes:
        clean_scope = scope.replace("https://www.googleapis.com/auth/", "")
        formatted.append(SCOPE_MAPPING.get(scope, clean_scope.capitalize()))
    return "; ".join(formatted)

def get_metadata_value(metadata, key: str) -> str:
    if not metadata or not metadata.items:
        return ""
    for item in metadata.items:
        if item.key == key:
            return item.value or ""
    return ""

def process_project(project_id: str) -> List[Dict[str, Any]]:
    results = []
    
    # One-time per project calls
    sa_role_map = get_project_iam_policy(project_id)
    static_ips = get_static_ips(project_id)

    try:
        client = compute_v1.InstancesClient()
        request = compute_v1.AggregatedListInstancesRequest(project=project_id)

        for zone_path, response in client.aggregated_list(request=request):
            if not response.instances:
                continue

            for instance in response.instances:
                try:
                    time.sleep(THROTTLE_SLEEP)

                    zone = parse_url_name(instance.zone)
                    
                    # === Networking ===
                    public_ip = "N/A"
                    public_ip_type = "None"

                    if instance.network_interfaces:
                        for nic in instance.network_interfaces:
                            if nic.access_configs:
                                for ac in nic.access_configs:
                                    if ac.nat_i_p:
                                        public_ip = ac.nat_i_p
                                        public_ip_type = "Static" if public_ip in static_ips else "Ephemeral or Static"

                    if instance.status in ["STOPPED", "TERMINATED"] and public_ip == "N/A":
                        if instance.network_interfaces and instance.network_interfaces[0].access_configs:
                            public_ip = "Assigned on Start"
                            public_ip_type = "Ephemeral"

                    # === OS Config Agent ===
                    os_config_bool, os_config_status = get_os_inventory(project_id, zone, instance.name)

                    # === Service Account ===
                    sa_email = "None"
                    sa_roles = ""
                    sa_scopes = "None"

                    if instance.service_accounts:
                        sa = instance.service_accounts[0]
                        sa_email = sa.email
                        sa_scopes = format_scopes(sa.scopes) if sa.scopes else "None"
                        sa_roles = ";".join(sa_role_map.get(sa_email, []))

                    # === Shielded + Confidential VM ===
                    sic = instance.shielded_instance_config

                    # Note: Keys are now flattened (no \n) to ensure perfect CSV rendering
                    row = {
                        "Project ID": project_id,
                        "Instance Name": instance.name,
                        "Zone": zone,
                        "Instance Status": instance.status,
                        "Public IP Type": public_ip_type,
                        "Public IP Address": public_ip,
                        "Public IP Required Yes/No": "",
                        "If Yes Justification for Public IP.": "",
                        "Service Account": sa_email,
                        "Service Account Roles": sa_roles,
                        "API Scopes": sa_scopes,
                        "Deletion Protection": "Enabled" if instance.deletion_protection else "Disabled",
                        "Project-Wide SSH Keys Blocked": "Blocked" if get_metadata_value(instance.metadata, "block-project-ssh-keys").lower() == "true" else "Allowed / Not Set",
                        "OS Config": os_config_bool,
                        "Confidential Compute": "TRUE" if instance.confidential_instance_config and instance.confidential_instance_config.enable_confidential_compute else "FALSE",
                        "Secure Boot": "TRUE" if sic and sic.enable_secure_boot else "FALSE",
                        "vTPM": "TRUE" if sic and sic.enable_vtpm else "FALSE",
                        "Integrity Monitoring": "TRUE" if sic and sic.enable_integrity_monitoring else "FALSE",
                        "Serial Port": "Enabled" if get_metadata_value(instance.metadata, "serial-port-enable").lower() in ["true", "1"] else "Disabled",
                        "OS Config Status": os_config_status,
                        "07 Aug": "",
                        "Comments / Justifications from Pickme": ""
                    }

                    results.append(row)
                    print(".", end="", flush=True)

                except Exception as e:
                    logger.error(f"Instance {instance.name} error: {e}")

    except Exception as e:
        print(f"\n[!] GCP API Error fetching instances in {project_id}: {str(e)[:150]}")
        logger.error(f"Aggregated list failed for {project_id}: {e}")

    return results

def main():
    print("\n" + "="*70)
    print(" GCP Compute Instance MASTER Audit Scanner")
    print("="*70)

    choice = input("\n1. Scan Organization\n2. Scan Project List\nChoice (1/2): ").strip()

    projects = []
    if choice == "1":
        org_id = input("Enter Organization ID: ").strip()
        print("Fetching projects...")
        projects = get_projects_from_org(org_id)
    else:
        projects = [p.strip() for p in input("Enter Project IDs (comma-separated): ").split(",") if p.strip()]

    if not projects:
        print("No projects to scan.")
        return

    print(f"\nScanning {len(projects)} projects with max {MAX_WORKERS} workers...\n")

    all_data = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_project, p): p for p in projects}
        for future in as_completed(futures):
            project = futures[future]
            try:
                data = future.result()
                if data:
                    all_data.extend(data)
                    print(f"\n[+] {project}: {len(data)} instances processed")
                else:
                    print(f"\n[-] {project}: skipped/no instances")
            except Exception as e:
                print(f"\n[!] {project}: critical error")

    if all_data:
        filename = f"GCP_Audit_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        # Flattened headers (no newlines) match dictionary keys
        headers = [
            "Project ID", "Instance Name", "Zone", "Instance Status", "Public IP Type", 
            "Public IP Address", "Public IP Required Yes/No", "If Yes Justification for Public IP.", 
            "Service Account", "Service Account Roles", "API Scopes", "Deletion Protection", 
            "Project-Wide SSH Keys Blocked", "OS Config", "Confidential Compute", "Secure Boot", 
            "vTPM", "Integrity Monitoring", "Serial Port", "OS Config Status", 
            "07 Aug", "Comments / Justifications from Pickme"
        ]

        # Use default python CSV quoting to safely handle commas/semicolons inside fields
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(all_data)

        print(f"\nSUCCESS -> Report: {filename} ({len(all_data)} instances)")
    else:
        print("\nNo instances found.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nAudit cancelled by user. Exiting gracefully.")
        sys.exit(0) 
