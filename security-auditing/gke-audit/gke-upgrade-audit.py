#!/usr/bin/env python3
import json
import subprocess
import csv
import sys
import os
from datetime import datetime, timedelta

# SOP Reference Mapping Matrix
SOP_INVENTORY = {
    "YOUR_PROJECT_ID_1": "Dataiku Production & Testing",
    "YOUR_PROJECT_ID_2": "SME Development",
    "YOUR_PROJECT_ID_3": "SME Testing",
    "YOUR_PROJECT_ID_4": "GitHub Enterprise",
    "YOUR_PROJECT_ID_5": "SME Production",
    "YOUR_PROJECT_ID_6": "Cloud Composer (Dev)",
    "YOUR_PROJECT_ID_7": "Cloud Composer (Prod)"
}

DEFAULT_PROJECTS = list(SOP_INVENTORY.keys())

def check_gcloud_installed():
    """Confirms gcloud CLI is ready and authenticated."""
    try:
        subprocess.run(["gcloud", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("\n❌ CRITICAL ERROR: 'gcloud' CLI is missing or not in your PATH.", file=sys.stderr)
        sys.exit(1)

def parse_utc_to_ist(utc_str, include_time=True):
    """Converts GCloud ISO UTC timestamps to human-readable Indian Standard Time (IST)."""
    if not utc_str or utc_str == "N/A":
        return "N/A"
    try:
        clean_str = utc_str.rstrip('Z')
        if '.' in clean_str:
            base_time, _ = clean_str.split('.', 1)
        else:
            base_time = clean_str
        
        dt_utc = datetime.strptime(base_time, "%Y-%m-%dT%H:%M:%S")
        dt_ist = dt_utc + timedelta(hours=5, minutes=30)
        
        return dt_ist.strftime("%Y-%m-%d %H:%M:%S IST") if include_time else dt_ist.strftime("%Y-%m-%d")
    except Exception:
        return str(utc_str)[:10]

def run_readonly_gcloud(cmd):
    """Executes purely read-only gcloud structural commands safely."""
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return json.loads(result.stdout)
    except Exception:
        return None

def extract_cluster_name_from_link(target_link):
    """
    EDGE CASE PROTECTION: Parses absolute cluster name from Google target resource links.
    Prevents substring collision issues (e.g., 'gke-prod' matching 'gke-prod-backup').
    """
    if not target_link or "/clusters/" not in target_link:
        return None
    try:
        # Splits right after '/clusters/' and takes the exact remaining segment name string
        parts = target_link.split("/clusters/")
        if len(parts) > 1:
            # Drop any dangling HTTP URL query parameters if present
            return parts[1].split('?')[0].strip()
    except Exception:
        pass
    return None

def main():
    check_gcloud_installed()

    print("=" * 75)
    print(" 🛡️  ROBUST GKE UPGRADE AUDIT ENGINE — MULTI-CLUSTER EDGE-CASE PROOF  🛡️ ")
    print("=" * 75)
    print("🤖 Status: 100% Read-Only Production Safe | Exact Slicing Active\n")

    # Step 1: Display Default SOP Map Reference
    print("📋 [Loaded SOP Scope Tracking Matrix]:")
    for proj, purpose in SOP_INVENTORY.items():
        print(f"  • {proj} -> ({purpose})")
    print("-" * 75)

    # Step 2: Interactive project insertion modification
    extra_input = input("\n💡 Want to add any extra GCP Project IDs to this scan? \n👉 (Comma-separated list, or press ENTER to stick to baseline): ").strip()
    
    project_ids = list(DEFAULT_PROJECTS)
    if extra_input:
        extras = [p.strip() for p in extra_input.split(",") if p.strip()]
        for e in extras:
            if e not in project_ids:
                project_ids.append(e)

    print(f"\n🔄 Compiling live topology layout for {len(project_ids)} target projects...")
    
    # Step 3: Discover the live topology sequentially to eliminate client lock drops
    final_scan_manifest = {}
    for project in project_ids:
        print(f"  🔍 Inspecting infrastructure in: [{project}]...", end="\r")
        clusters = run_readonly_gcloud(["gcloud", "container", "clusters", "list", f"--project={project}", "--format=json"])
        final_scan_manifest[project] = clusters if clusters else []
    
    # Render Target Summary Map layout
    print("\n" + "=" * 75)
    print("🎯 LIVE TOPOLOGY PREVIEW")
    print("=" * 75)
    total_clusters = 0
    for project in project_ids:
        clusters = final_scan_manifest.get(project, [])
        purpose_str = f" [{SOP_INVENTORY[project]}]" if project in SOP_INVENTORY else " [Custom External Project]"
        print(f"📦 Project ID: {project}{purpose_str}")
        if not clusters:
            print("   └── ℹ️  No active GKE clusters detected or lacks API visibility.")
        for c in clusters:
            total_clusters += 1
            print(f"   └── ☸️  Cluster: {c.get('name')} | Loc: {c.get('location')} | Control Plane Ver: {c.get('currentMasterVersion')}")
    print("=" * 75)

    if total_clusters == 0:
        print("\n🤷 No target clusters available for review. Exiting process safely.")
        sys.exit(0)

    # Step 4: Operator Gate Guard
    print(f"\n📢 READY TO EXECUTE SYSTEM DATA-EXTRACTION FOR {total_clusters} CLUSTERS?")
    confirm = input("👉 Type 'Y' to pull deep upgrade logs, or any other key to halt: ").strip().lower()

    if confirm != 'y':
        print("\n🛑 Execution stopped by engineer. Safe termination.")
        sys.exit(0)

    # Step 5: Sequential Log Processing Phase
    print("\n🚀 Analyzing cloud logs. Sorting timelines chronologically...")
    csv_data = []
    current_check_date = datetime.now().strftime("%Y-%m-%d")

    for project in project_ids:
        clusters = final_scan_manifest.get(project, [])
        if not clusters:
            continue
            
        print(f" 📥 Fetching precise upgrade history entries for project: [{project}]")
        operations = run_readonly_gcloud([
            "gcloud", "container", "operations", "list", 
            f"--project={project}", 
            '--filter=operationType=UPGRADE_MASTER OR operationType=UPGRADE_NODES', 
            "--format=json"
        ])
        if not operations:
            operations = []

        for cluster in clusters:
            cluster_name = cluster.get("name", "UNKNOWN_NAME")
            master_version = cluster.get("currentMasterVersion", "UNKNOWN")
            gke_native_status = cluster.get("status", "UNKNOWN")
            
            # Map Primary Purpose strictly tracking the SOP rules
            if cluster_name == "gke-prod" and project == "YOUR_PROJECT_ID_1":
                primary_purpose = "Dataiku Production"
            elif cluster_name == "gke-test" and project == "YOUR_PROJECT_ID_1":
                primary_purpose = "Dataiku Testing"
            elif cluster_name == "gke-sme-dev":
                primary_purpose = "SME Development"
            elif cluster_name == "gke-sme-test":
                primary_purpose = "SME Testing"
            elif cluster_name == "gke-github-enterprise":
                primary_purpose = "GitHub Enterprise"
            elif cluster_name == "gke-sme-prod":
                primary_purpose = "SME Production"
            elif "YOUR_PROJECT_ID_6" in project:
                primary_purpose = "Cloud Composer (Dev)"
            elif "YOUR_PROJECT_ID_7" in project:
                primary_purpose = "Cloud Composer (Prod)"
            else:
                primary_purpose = "Ad-hoc / Unmapped Cluster"

            # Parse Node Pools and execute absolute matching evaluation
            node_pools = cluster.get("nodePools", [])
            np_status_strings = []
            versions_match = "Match"
            
            for np in node_pools:
                np_name = np.get("name", "unnamed")
                np_ver = np.get("version", "unknown")
                auto_up = "AutoUp:On" if np.get("management", {}).get("autoUpgrade", False) else "AutoUp:Off"
                np_status_strings.append(f"{np_name}(v{np_ver}, {auto_up})")
                
                if np_ver != master_version:
                    versions_match = "MISMATCH DETECTED"
            
            node_pool_summary = " // ".join(np_status_strings) if np_status_strings else "No active Node Pools"

            # SOP Compliance Status translation mapper logic
            if gke_native_status == "RUNNING":
                status_mapped = "Healthy"
            elif gke_native_status in ["RECONCILING", "UPDATING"]:
                status_mapped = "Upgrade Pending"
            elif gke_native_status in ["ERROR", "DEGRADED"]:
                status_mapped = "Upgrade Failed"
            else:
                status_mapped = f"Unhealthy ({gke_native_status})"

            # EDGE CASE FIX: Exact parsing match comparison to assign operations to the correct cluster
            cluster_ops = []
            for op in operations:
                target_link = op.get("targetLink")
                parsed_name = extract_cluster_name_from_link(target_link)
                if parsed_name and parsed_name == cluster_name:
                    cluster_ops.append(op)
            
            # Sort operations chronologically by start timestamp, newest first
            cluster_ops.sort(key=lambda x: x.get("startTime", ""), reverse=True)
            
            # Identify the single most recent SUCCESSFUL upgrade execution (Status: DONE)
            last_successful_upgrade = "No successful upgrades in log window"
            for op in cluster_ops:
                if op.get("status") == "DONE":
                    last_successful_upgrade = parse_utc_to_ist(op.get("startTime", ""))
                    break
            
            # String build the concise tracking timeline history pattern sequence trail
            history_summary_list = []
            for op in cluster_ops[:5]:
                op_type = op.get("operationType", "UPGRADE")
                op_status = op.get("status", "UNKNOWN")
                ist_date = parse_utc_to_ist(op.get("startTime", ""), include_time=False)
                history_summary_list.append(f"[{ist_date}] {op_type}➔{op_status}")
            
            history_timeline = " ➔ ".join(history_summary_list) if history_summary_list else "No recorded upgrade logs found in window"

            # Assemble clean linear matrix entry mapping row dataset payload
            row = [
                current_check_date,
                project,
                cluster_name,
                primary_purpose,
                status_mapped,
                master_version,
                node_pool_summary,
                versions_match,
                last_successful_upgrade,
                history_timeline
            ]
            csv_data.append(row)

    # Step 6: Write to uniquely-stamped output spreadsheet file
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"gke_upgrade_report_{timestamp_str}.csv"
    
    headers = [
        "Check_Date", "Project_ID", "Cluster_Name", "Primary_Purpose", 
        "Cluster_Status", "Control_Plane_Version", "Node_Pool_Details", 
        "Version_Match_Status", "Last_Successful_Upgrade_IST", "Recent_Upgrade_History"
    ]

    try:
        with open(output_filename, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter="|", quoting=csv.QUOTE_MINIMAL)
            writer.writerow(headers)
            writer.writerows(csv_data)
        
        print("\n" + "=" * 75)
        print("🎉 SUCCESS: COMPREHENSIVE COMPLIANCE MATRIX READY!")
        print("=" * 75)
        print(f"💾 Report Saved File: {os.path.abspath(output_filename)}")
        print(f"📊 Extracted Rows  : Total of {len(csv_data)} cluster tracking lines built.")
        print(f"📊 Format Type     : Pipe-Delimited Matrix Schema ('|')")
        print("✨ Safe, accurate, and completely sorted. Ready for copy-pasting!")
        print("=" * 75 + "\n")
        
    except Exception as e:
        print(f"\n❌ Unexpected error saving the report file asset: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
