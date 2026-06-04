import subprocess
import json
import csv
import argparse
import sys
from typing import List, Dict, Any

def run_gcloud_command(command: List[str]) -> List[Dict[str, Any]]:
    """
    Runs a gcloud command and returns the parsed JSON output.
    Handles errors gracefully.
    """
    try:
        print(f"-> Running: {' '.join(command)}", file=sys.stderr)
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8'
        )
        if not process.stdout.strip():
            return []
        return json.loads(process.stdout)
    except FileNotFoundError:
        print("\n[ERROR] 'gcloud' command not found. Please ensure the Google Cloud SDK is installed and in your system's PATH.", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"\n[ERROR] gcloud command failed with exit code {e.returncode}:", file=sys.stderr)
        print(e.stderr, file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print("\n[ERROR] Failed to parse JSON from gcloud output. The command may have failed or returned an unexpected format.", file=sys.stderr)
        sys.exit(1)

def format_list_for_csv(items: list) -> str:
    """Formats a list into a clean, comma-separated string, sorted alphabetically."""
    return ', '.join(sorted(list(items))) if items else "N/A"

def format_ports_for_csv(allowed_rules: List[Dict[str, Any]]) -> str:
    """Formats the 'allowed' port rules into a readable string."""
    if not allowed_rules:
        return "N/A"
    parts = []
    for rule in allowed_rules:
        protocol = rule.get('IPProtocol', 'all')
        ports = rule.get('ports', [])
        if ports:
            parts.append(f"{protocol}:{','.join(ports)}")
        else:
            parts.append(protocol)
    return ' | '.join(sorted(parts)) if parts else "all"

def get_vm_public_ip(instance: Dict[str, Any]) -> str:
    """Extracts the public IP from a VM instance object, returning 'N/A' if not found."""
    try:
        return instance['networkInterfaces'][0]['accessConfigs'][0]['natIP']
    except (KeyError, IndexError):
        return "N/A"

def main(project_id: str):
    """
    Main function to fetch GCP firewall and instance data, correlate them,
    and write a clean CSV report.
    """
    print(f"[*] Starting firewall assessment for project: {project_id}")

    # ===== 1. FETCH DATA FROM GCLOUD =====
    firewall_cmd = ["gcloud", "compute", "firewall-rules", "list", f"--project={project_id}", "--format=json"]
    instances_cmd = ["gcloud", "compute", "instances", "list", f"--project={project_id}", "--format=json"]

    firewall_rules = run_gcloud_command(firewall_cmd)
    instances = run_gcloud_command(instances_cmd)

    if not firewall_rules:
        print(f"[INFO] No firewall rules found in project {project_id}. Exiting.", file=sys.stderr)
        return

    print(f"[*] Found {len(firewall_rules)} firewall rules and {len(instances)} VM instances.", file=sys.stderr)
    print("[*] Correlating rules to instances...", file=sys.stderr)

    # Pre-process instances into a map for faster lookups
    instance_map = {inst['name']: inst for inst in instances}

    # ===== 2. PROCESS AND CORRELATE DATA =====
    final_report = []
    for rule in firewall_rules:
        attached_vms_names: List[str] = []
        rule_network = rule.get('network')
        target_tags = set(rule.get('targetTags', []))
        target_service_accounts = set(rule.get('targetServiceAccounts', []))

        # Determine which instances this rule applies to
        for inst_name, inst_details in instance_map.items():
            if inst_details.get('networkInterfaces', [{}])[0].get('network') != rule_network:
                continue

            instance_tags = set(inst_details.get('tags', {}).get('items', []))
            instance_sa = inst_details.get('serviceAccounts', [{}])[0].get('email', '')

            if (not target_tags and not target_service_accounts) or \
               (target_tags and not instance_tags.isdisjoint(target_tags)) or \
               (target_service_accounts and instance_sa in target_service_accounts):
                attached_vms_names.append(inst_name)

        # ===== 3. CREATE THE NEW 'VM:IP' FORMAT =====
        vm_ip_pairs = []
        for name in sorted(attached_vms_names):
            public_ip = get_vm_public_ip(instance_map[name])
            vm_ip_pairs.append(f"{name}:{public_ip}")

        # ===== 4. PREPARE THE ROW FOR THE CSV =====
        report_row = {
            'Project_ID': project_id,
            'Firewall_Rule_Name': rule.get('name', ''),
            'Is_Disabled': rule.get('disabled', False),
            'Network_VPC': rule.get('network', '').split('/')[-1],
            'Direction': rule.get('direction', ''),
            'Priority': rule.get('priority', ''),
            'Source_Ranges': format_list_for_csv(rule.get('sourceRanges', [])),
            'Allowed_Protocols_Ports': format_ports_for_csv(rule.get('allowed', [])),
            'Target_Tags': format_list_for_csv(target_tags),
            'Target_Service_Accounts': format_list_for_csv(target_service_accounts),
            'Attached_VMs (Name:PublicIP)': f"[{', '.join(vm_ip_pairs)}]" if vm_ip_pairs else "[N/A]"
        }
        final_report.append(report_row)

    # ===== 5. WRITE THE FINAL CSV REPORT =====
    output_filename = f"{project_id}_firewall_assessment_v3.csv"
    if not final_report:
        print("[INFO] No data to write to report.", file=sys.stderr)
        return

    try:
        with open(output_filename, 'w', newline='', encoding='utf-8') as csvfile:
            headers = [
                'Project_ID', 'Firewall_Rule_Name', 'Is_Disabled', 'Network_VPC',
                'Direction', 'Priority', 'Source_Ranges', 'Allowed_Protocols_Ports',
                'Target_Tags', 'Target_Service_Accounts', 'Attached_VMs (Name:PublicIP)'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            writer.writerows(final_report)
        print(f"\n[SUCCESS] Report generated: {output_filename}")
    except IOError as e:
        print(f"\n[ERROR] Could not write to file {output_filename}: {e}", file=sys.stderr)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a clean CSV report of GCP firewall rules and their associated VMs (Name:PublicIP).",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--project",
        dest="project_id",
        required=True,
        help="The GCP Project ID to analyze."
    )
    args = parser.parse_args()
    main(args.project_id)
 
