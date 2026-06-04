#!/usr/bin/env python3
"""
GCP Compute Instance Master Audit Scanner (Kundli + Deep Security)
===================================================================
Single ultimate read-only audit script combining:
- Full instance details (machine type, disks, multi-NIC, timestamps, tags, labels, scripts, etc.)
- Deep security audit (OS Config agent with retry + detailed status, SA roles from IAM, Shielded VM separate flags,
  Confidential Compute, block-project-ssh-keys, serial port, precise IP types, etc.)
- Robust quota-friendly design (low concurrency, throttling, retries, minimal API calls)

Generates one comprehensive CSV with 35+ columns for complete visibility.

Author: Pratik Shetti + Grok refinement
Version: 5.0.0 Master
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

# Suppress noisy logs
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
    "https://www.googleapis.com/auth/cloud-platform": "All APIs (Full Access)",
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
THROTTLE_SLEEP = 0.4  # Between instances - very quota friendly

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
    """Fetch SA → Roles mapping once per project"""
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

def get_disk_details(project_id: str, zone: str, disk_name: str) -> Dict[str, Any]:
    try:
        client = compute_v1.DisksClient()
        disk = client.get(request=compute_v1.GetDiskRequest(project=project_id, zone=zone, disk=disk_name))
        return {
            "size_gb": disk.size_gb,
            "type": parse_url_name(disk.type_),
            "licenses": [parse_url_name(l) for l in disk.licenses] if disk.licenses else []
        }
    except Exception:
        return {}

def get_os_inventory(project_id: str, zone: str, instance_name: str) -> Tuple[str, str, str]:
    """
    Robust OS Config check with retry + detailed status + OS info if available
    Returns: (os_info, os_config_bool TRUE/FALSE, detailed_status)
    """
    client = osconfig_v1.OsConfigZonalServiceClient()
    inventory_name = f"projects/{project_id}/locations/{zone}/instances/{instance_name}/inventory"
    request = osconfig_v1.GetInventoryRequest(name=inventory_name)

    max_retries = 5
    base_delay = 2

    for attempt in range(max_retries):
        try:
            inventory = client.get_inventory(request=request)
            # Success → Agent installed and reporting
            os_info = ""
            if inventory.os_info:
                parts = []
                if inventory.os_info.long_name:
                    parts.append(inventory.os_info.long_name)
                elif inventory.os_info.short_name:
                    parts.append(inventory.os_info.short_name)
                if inventory.os_info.version:
                    parts.append(inventory.os_info.version)
                if inventory.os_info.architecture:
                    parts.append(f"({inventory.os_info.architecture})")
                os_info = " ".join(parts)
            return os_info, "TRUE", "Installed & Reporting"

        except google_exceptions.NotFound:
            return "", "FALSE", "Not Installed"

        except (PermissionDenied, Forbidden) as e:
            if "not enabled" in str(e):
                return "", "FALSE", "API Disabled"
            return "", "FALSE", "Permission Denied"

        except (ResourceExhausted, TooManyRequests, ServiceUnavailable):
            if attempt < max_retries - 1:
                sleep_time = (base_delay * (2 ** attempt)) + random.uniform(0, 1)
                time.sleep(sleep_time)
                continue
            return "", "FALSE", "Quota Exceeded"

        except Exception as e:
            return "", "FALSE", f"Error: {str(e)[:30]}"

    return "", "FALSE", "Unknown Error"

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

    # Early skip if Compute API disabled/no access
    try:
        compute_v1.ZonesClient().list(request=compute_v1.ListZonesRequest(project=project_id, max_results=1))
    except Exception:
        logger.error(f"Compute API inaccessible for {project_id}")
        return results

    # One-time per project calls
    sa_role_map = get_project_iam_policy(project_id)
    static_ips = get_static_ips(project_id)

    # Instance enumeration
    client = compute_v1.InstancesClient()
    request = compute_v1.AggregatedListInstancesRequest(project=project_id)

    for zone_path, response in client.aggregated_list(request=request):
        if not response.instances:
            continue

        for instance in response.instances:
            try:
                time.sleep(THROTTLE_SLEEP)  # Be gentle on quotas

                zone = parse_url_name(instance.zone)
                row = {
                    "Project ID": project_id,
                    "Instance Name": instance.name,
                    "Zone": zone,
                    "Status": instance.status,
                    "Machine Type": parse_url_name(instance.machine_type),
                    "Creation Time": instance.creation_timestamp,
                    "Last Start Time": instance.last_start_timestamp or "N/A",
                    "Deletion Protection": "Enabled" if instance.deletion_protection else "Disabled",
                }

                # === Networking ===
                primary_internal_ip = ""
                public_ip = "N/A"
                public_ip_type = "None"
                network = ""
                subnet = ""
                nic_summary = []

                if instance.network_interfaces:
                    for i, nic in enumerate(instance.network_interfaces):
                        int_ip = nic.network_i_p or ""
                        ext_ip = ""
                        ext_type = "None"

                        if nic.access_configs:
                            for ac in nic.access_configs:
                                if ac.nat_i_p:
                                    ext_ip = ac.nat_i_p
                                    ext_type = f"Static ({static_ips.get(ext_ip, 'Unknown')})" if ext_ip in static_ips else "Ephemeral"

                        nic_str = f"{parse_url_name(nic.network)}/{parse_url_name(nic.subnetwork)} ({int_ip})"
                        nic_summary.append(nic_str)

                        if i == 0:
                            primary_internal_ip = int_ip
                            public_ip = ext_ip or "N/A"
                            public_ip_type = ext_type
                            network = parse_url_name(nic.network)
                            subnet = parse_url_name(nic.subnetwork)

                row["Internal IP"] = primary_internal_ip
                row["Public IP Address"] = public_ip
                row["Public IP Type"] = public_ip_type
                row["Network"] = network
                row["Subnet"] = subnet
                row["Network Interfaces"] = "; ".join(nic_summary) if nic_summary else "None"

                # === Disks ===
                boot_size = ""
                boot_os_licenses = ""
                external_disks = []

                if instance.disks:
                    for disk in instance.disks:
                        disk_name = parse_url_name(disk.source)
                        details = get_disk_details(project_id, zone, disk_name)
                        size = details.get("size_gb", "?")
                        licenses = details.get("licenses", [])

                        if disk.boot:
                            boot_size = str(size)
                            boot_os_licenses = ", ".join(licenses)
                        else:
                            external_disks.append(f"{disk_name} ({size}GB)")

                row["Boot Disk Size (GB)"] = boot_size
                row["Boot Disk OS (Licenses)"] = boot_os_licenses
                row["External Disks"] = ", ".join(external_disks) if external_disks else "None"

                # === OS Config Agent (Deep check) ===
                os_running, os_config_bool, os_config_status = get_os_inventory(project_id, zone, instance.name)
                row["OS Running (Agent)"] = os_running
                row["OS Config Agent"] = os_config_bool
                row["OS Config Status"] = os_config_status

                # === Service Account ===
                sa_email = "None"
                sa_roles = ""
                sa_scopes = "None"

                if instance.service_accounts:
                    sa = instance.service_accounts[0]
                    sa_email = sa.email
                    sa_scopes = format_scopes(sa.scopes) if sa.scopes else "None"
                    sa_roles = "; ".join(sa_role_map.get(sa_email, []))

                row["Service Account"] = sa_email
                row["Service Account Roles"] = sa_roles
                row["API Scopes"] = sa_scopes

                # === Tags & Labels ===
                row["Tags"] = ", ".join(instance.tags.items) if instance.tags and instance.tags.items else "None"
                row["Labels"] = "; ".join([f"{k}={v}" for k, v in instance.labels.items()]) if instance.labels else "None"

                # === Metadata / Scripts ===
                row["Startup Script"] = "Yes" if get_metadata_value(instance.metadata, "startup-script") else "No"
                row["Shutdown Script"] = "Yes" if get_metadata_value(instance.metadata, "shutdown-script") else "No"
                row["Project-Wide SSH Keys Blocked"] = "Blocked" if get_metadata_value(instance.metadata, "block-project-ssh-keys").lower() == "true" else "Allowed / Not Set"
                row["Serial Port"] = "Enabled" if get_metadata_value(instance.metadata, "serial-port-enable").lower() in ["true", "1"] else "Disabled"

                # === Shielded + Confidential VM ===
                sic = instance.shielded_instance_config
                row["Secure Boot"] = "TRUE" if sic and sic.enable_secure_boot else "FALSE"
                row["vTPM"] = "TRUE" if sic and sic.enable_vtpm else "FALSE"
                row["Integrity Monitoring"] = "TRUE" if sic and sic.enable_integrity_monitoring else "FALSE"
                row["Confidential Compute"] = "Enabled" if instance.confidential_instance_config and instance.confidential_instance_config.enable_confidential_compute else "Disabled"

                # === Misc ===
                row["IP Forwarding"] = "Enabled" if instance.can_ip_forward else "Disabled"

                results.append(row)
                print(".", end="", flush=True)

            except Exception as e:
                logger.error(f"Instance {instance.name} in {project_id}/{zone}: {e}")

    return results

def main():
    print("\n" + "="*70)
    print(" GCP Compute Instance MASTER Audit Scanner")
    print(" Comprehensive Read-Only Security + Inventory Report")
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
                    print(f"\n[+] {project}: {len(data)} instances")
                else:
                    print(f"\n[-] {project}: skipped/no instances")
            except Exception as e:
                print(f"\n[!] {project}: error")

    if all_data:
        filename = f"GCP_Master_Audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        headers = [
            "Project ID", "Instance Name", "Zone", "Status", "Machine Type", "Creation Time", "Last Start Time",
            "Internal IP", "Public IP Address", "Public IP Type", "Network", "Subnet", "Network Interfaces",
            "Boot Disk Size (GB)", "Boot Disk OS (Licenses)", "External Disks",
            "OS Running (Agent)", "OS Config Agent", "OS Config Status",
            "Service Account", "Service Account Roles", "API Scopes",
            "Tags", "Labels",
            "Startup Script", "Shutdown Script",
            "Project-Wide SSH Keys Blocked", "Serial Port",
            "Secure Boot", "vTPM", "Integrity Monitoring", "Confidential Compute",
            "Deletion Protection", "IP Forwarding"
        ]

        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(all_data)

        print(f"\nSUCCESS → Report: {filename} ({len(all_data)} instances)")
    else:
        print("\nNo instances found.")

if __name__ == "__main__":
    main()
