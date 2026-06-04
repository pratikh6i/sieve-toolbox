import subprocess
import json
import csv
import sys
import datetime
import concurrent.futures
import threading
import os

# ---------------- CONFIGURATION ---------------- #

# Add your project IDs here, or set via env: export GCP_PROJECTS='["proj1", "proj2"]'
PROJECT_IDS = json.loads(os.getenv('GCP_PROJECTS', json.dumps([
    "YOUR_PROJECT_ID",
    # ... paste your full list here ...
])))

OUTPUT_FILE = "gcp_vm_parallel_report.csv"
MAX_WORKERS = 10  # Scans 10 projects at the same time (Safe for Quotas)

# ----------------------------------------------- #

# Lock to prevent threads from writing to CSV at the same time
csv_lock = threading.Lock()

def clean_script(metadata_items, key_name):
    """Finds a script in metadata and removes newlines for CSV safety."""
    if not metadata_items:
        return "None"
    
    for item in metadata_items:
        if item.get("key") == key_name:
            val = item.get("value", "")
            return val.replace("\n", " ").replace("\r", " ")
    return "None"

def format_timestamp(ts):
    """Parse and format ISO timestamp to readable string."""
    if ts == "N/A" or ts == "Never":
        return ts
    try:
        # Handle common ISO formats
        if ts.endswith('Z'):
            parsed = datetime.datetime.fromisoformat(ts.replace('Z', '+00:00'))
        else:
            parsed = datetime.datetime.fromisoformat(ts)
        return parsed.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError):
        return ts  # Fallback to raw if parsing fails

def process_project(project):
    """
    Worker function to scan a single project.
    Returns a LIST of rows (one per VM) or a single error row.
    """
    rows = []
    
    # -- SAFETY & STUCK FIX --
    # 1. 'instances list' is strictly Read-Only.
    # 2. '--quiet' disables interactive prompts (prevents "stuck" behavior).
    # 3. '--no-user-output-enabled' suppresses 'API not enabled' spam in your terminal.
    cmd = [
        "gcloud", "compute", "instances", "list",
        "--project", project,
        "--format", "json",
        "--quiet" 
    ]
    
    try:
        # Run gcloud command
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Check if gcloud command failed (e.g., API disabled, No Permission)
        if result.returncode != 0:
            err_msg = result.stderr.strip().replace("\n", " ")
            # Categorize common errors for cleaner report
            note = "Unknown Error"
            if "API" in err_msg and "not enabled" in err_msg:
                note = "API Disabled"
            elif "Permission denied" in err_msg:
                note = "Permission Denied"
            
            # Return a single error row for this project (standardized)
            return [[project, f"{note}_PROJECT", "N/A", "ERROR", "N/A", "N/A", "N/A", 
                     "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", 
                     "N/A", "N/A", "N/A", "N/A", "N/A", f"{note} - {err_msg[:100]}..."]]

        # Parse JSON output
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
             return [[project, "JSON_PARSE_PROJECT", "N/A", "ERROR", "N/A", "N/A", "N/A", 
                      "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", 
                      "N/A", "N/A", "N/A", "N/A", "N/A", "Raw Output could not be parsed"]]

        if not data:
            # Empty list = No VMs found
            return [] 

        # Process each VM found in the JSON
        for vm in data:
            try:
                name = vm.get("name", "Unknown")
                zone = vm.get("zone", "").split("/")[-1]
                status = vm.get("status", "Unknown")
                machine_type = vm.get("machineType", "").split("/")[-1]
                creation_ts = format_timestamp(vm.get("creationTimestamp", "N/A"))
                last_start = format_timestamp(vm.get("lastStartTimestamp", "Never"))
                del_prot = vm.get("deletionProtection", False)

                # Networking (handle multi-NIC)
                int_ips = []
                ext_ips = []
                networks = []
                subnets = []
                nics = vm.get("networkInterfaces", [])
                for nic in nics:
                    int_ip = nic.get("networkIP", "N/A")
                    if int_ip != "N/A":
                        int_ips.append(int_ip)
                    
                    network = nic.get("network", "").split("/")[-1]
                    if network != "":
                        networks.append(network)
                    
                    subnet = nic.get("subnetwork", "").split("/")[-1]
                    if subnet != "":
                        subnets.append(subnet)
                    
                    # External IPs (one per accessConfig, detect Ephemeral vs Static)
                    acc_configs = nic.get("accessConfigs", [])
                    for acc in acc_configs:
                        nat_ip = acc.get("natIP")
                        addr_link = acc.get("address")
                        if nat_ip:
                            if addr_link and addr_link.startswith("https://"):
                                # Static IP (has selfLink to address resource)
                                addr_name = addr_link.split("/")[-1]
                                ext_ips.append(f"{nat_ip} (Static: {addr_name})")
                            else:
                                # Ephemeral IP (no address link)
                                ext_ips.append(f"{nat_ip} (Ephemeral)")
                        else:
                            ext_ips.append("No NAT IP Configured")

                int_ip = "; ".join(int_ips) if int_ips else "N/A"
                ext_ip = "; ".join(ext_ips) if ext_ips else "N/A"
                network = "; ".join(networks) if networks else "N/A"
                subnet = "; ".join(subnets) if subnets else "N/A"

                # ---------------- FIXED STORAGE & OS LOGIC ----------------
                disk_gb = "N/A"
                os_details = "Unknown"
                disks = vm.get("disks", [])
                
                for disk in disks:
                    if disk.get("boot"):
                        disk_gb = disk.get("diskSizeGb", "N/A")
                        
                        # FIX: We changed the priority here. 
                        # We check sourceImage FIRST, because Licenses are often outdated billing tags.
                        
                        # 1. Try to get the specific Image Name (e.g. ubuntu-2404-noble...)
                        if "sourceImage" in disk:
                             os_details = disk["sourceImage"].split("/")[-1]
                        
                        # 2. Try initializeParams (Common in some deployment methods)
                        elif "initializeParams" in disk and "sourceImage" in disk["initializeParams"]:
                            os_details = disk["initializeParams"]["sourceImage"].split("/")[-1]
                            
                        # 3. Fallback to Licenses only if Image info is missing
                        else:
                            licenses = disk.get("licenses", [])
                            if licenses:
                                os_details = "; ".join([l.split("/")[-1] for l in licenses])
                        
                        break
                # ----------------------------------------------------------

                # Metadata (handle multi-SA)
                sa_list = vm.get("serviceAccounts", [])
                sa_emails = [sa.get("email", "None") for sa in sa_list if sa.get("email")]
                sa_email = "; ".join(sa_emails) if sa_emails else "None"
                
                tags = ";".join(vm.get("tags", {}).get("items", []))
                labels = "; ".join([f"{k}:{v}" for k, v in vm.get("labels", {}).items()])
                
                # Scripts
                meta_items = vm.get("metadata", {}).get("items", [])
                startup = clean_script(meta_items, "startup-script")
                shutdown = clean_script(meta_items, "shutdown-script")

                # Notes: Add security audit flag for TERMINATED VMs with Ephemeral external IPs
                notes = "Success"
                if status == "TERMINATED":
                    has_ephemeral = any(" (Ephemeral)" in ip for ip in ext_ips)
                    if has_ephemeral:
                        notes += "; [AUDIT] TERMINATED VM with Ephemeral External IP - Review for Cleanup"

                rows.append([
                    project, name, zone, status, machine_type,
                    creation_ts, last_start, del_prot,
                    int_ip, ext_ip, network, subnet,
                    disk_gb, os_details,
                    sa_email, tags, labels, 
                    startup, shutdown, notes
                ])
            except Exception as e:
                # Individual VM parsing error (standardized)
                rows.append([project, "PARSING_ERROR_VM", "N/A", "ERROR", "N/A", "N/A", "N/A", 
                             "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", 
                             "N/A", "N/A", "N/A", "N/A", "N/A", str(e)])
        
        return rows

    except Exception as e:
        return [[project, "SYSTEM_ERROR_PROJECT", "N/A", "ERROR", "N/A", "N/A", "N/A", 
                 "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", 
                 "N/A", "N/A", "N/A", "N/A", "N/A", str(e)]]

def main():
    # Pre-flight: Check gcloud auth (read-only check)
    try:
        auth_result = subprocess.run(["gcloud", "auth", "list", "--quiet"], 
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if auth_result.returncode != 0:
            print("❌ Error: gcloud auth not configured. Run 'gcloud auth login' first.")
            sys.exit(1)
        print("✅ gcloud auth OK.")
    except FileNotFoundError:
        print("❌ Error: gcloud not found. Install via https://cloud.google.com/sdk/docs/install")
        sys.exit(1)

    print(f"🚀 Starting Parallel Audit for {len(PROJECT_IDS)} projects...")
    print(f"⚡ Max Workers: {MAX_WORKERS}")

    headers = [
        'Project ID', 'Instance Name', 'Zone', 'Status', 'Machine Type',
        'Creation Time', 'Last Start', 'Deletion Protection',
        'Internal IP', 'External IP', 'Network', 'Subnet',
        'Boot Disk Size (GB)', 'OS Details',
        'Service Account', 'Tags', 'Labels', 
        'Startup Script', 'Shutdown Script', 'Notes'
    ]

    # Write Header
    with open(OUTPUT_FILE, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(headers)

    # Use ThreadPoolExecutor to run process_project in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit all tasks
        future_to_project = {executor.submit(process_project, pid): pid for pid in PROJECT_IDS}
        
        for future in concurrent.futures.as_completed(future_to_project):
            project = future_to_project[future]
            try:
                data_rows = future.result()
                
                if not data_rows:
                    print(f"✅ {project}: 0 VMs found.")
                else:
                    # Check if it was an error row (look for ERROR in Status)
                    if data_rows[0][3] == "ERROR":
                         print(f"❌ {project}: {data_rows[0][-1][:60]}...")
                    else:
                         print(f"✅ {project}: {len(data_rows)} VMs found.")

                    # Write to CSV (Thread Safe)
                    with csv_lock:
                        with open(OUTPUT_FILE, mode='a', newline='', encoding='utf-8') as file:
                            writer = csv.writer(file)
                            writer.writerows(data_rows)

            except Exception as exc:
                print(f"⚠️ {project} generated an exception: {exc}")

    print(f"\n🎉 Done! Inventory saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main() 
