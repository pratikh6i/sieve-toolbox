import subprocess
import json
import csv
import sys
import concurrent.futures

# --- CONFIGURATION ---
OUTPUT_CSV = "gcp_api_keys_report.csv"
MAX_THREADS = 10  # Adjust based on your CPU and network


def get_projects_from_user():
    """Prompts the user to input a comma-separated list of project IDs."""
    user_input = input("Enter the Project IDs separated by commas: ")

    # Split by comma, strip extra whitespace, and filter out any empty strings
    projects = [p.strip() for p in user_input.split(',') if p.strip()]

    if not projects:
        print("CRITICAL ERROR: No valid project IDs provided. Exiting.")
        sys.exit(1)

    print(f"\nLoaded {len(projects)} project(s). Starting parallel processing...\n")
    return projects


def process_project(project_id):
    """Processes a single project, strictly fetching API keys (read-only)."""
    rows = []
    cmd = [
        "gcloud", "services", "api-keys", "list",
        "--project", project_id,
        "--format", "json",
        "--quiet"
    ]

    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # 1. Handle Errors Gracefully
    if result.returncode != 0:
        error_msg = result.stderr.strip()

        # Simplify common errors for easier debugging in the CSV
        if "API_KEYS_API_NOT_ENABLED" in error_msg or "not enabled" in error_msg:
            status = "Error: API Keys API is not enabled"
        elif "PERMISSION_DENIED" in error_msg:
            status = "Error: Permission Denied (Needs 'apikeys.keys.list')"
        else:
            # Capture any other unexpected errors exactly as they are
            status = f"Error: {error_msg.splitlines()[0] if error_msg else 'Unknown Error'}"

        rows.append({
            "Project ID": project_id,
            "Key Display Name": "N/A",
            "Key ID (UID)": "N/A",
            "Creation Date": "N/A",
            "API Restrictions": "N/A",
            "Application Restrictions": "N/A",
            "Status / Debug Info": status
        })
        print(f"[-] Project {project_id}: Failed ({status})")
        return rows

    # 2. Parse Data
    try:
        keys = json.loads(result.stdout)

        # Handle cases where project has no keys
        if not keys:
            rows.append({
                "Project ID": project_id,
                "Key Display Name": "None",
                "Key ID (UID)": "None",
                "Creation Date": "N/A",
                "API Restrictions": "N/A",
                "Application Restrictions": "N/A",
                "Status / Debug Info": "Success: No keys present"
            })
            print(f"[+] Project {project_id}: No keys present")
            return rows

        # Extract details for each key
        for key in keys:
            display_name = key.get("displayName", "N/A")
            key_id = key.get("uid", key.get("name", "N/A").split('/')[-1])
            create_time = key.get("createTime", "N/A")
            restrictions = key.get("restrictions", {})

            # Parse API Restrictions (Target Services)
            api_targets = restrictions.get("apiTargets", [])
            if api_targets:
                api_restr_list = [target.get("service", "Unknown") for target in api_targets]
                api_restrictions_str = ", ".join(api_restr_list)
            else:
                api_restrictions_str = "Unrestricted"

            # Parse Application Restrictions (IPs, HTTP Referrers, Android/iOS)
            app_restrictions_str = "None"
            if "browserKeyRestrictions" in restrictions:
                allowed = restrictions["browserKeyRestrictions"].get("allowedReferrers", [])
                app_restrictions_str = "HTTP Referrers: " + ", ".join(allowed)
            elif "serverKeyRestrictions" in restrictions:
                allowed = restrictions["serverKeyRestrictions"].get("allowedIps", [])
                app_restrictions_str = "IP Addresses: " + ", ".join(allowed)
            elif "androidKeyRestrictions" in restrictions:
                allowed = restrictions["androidKeyRestrictions"].get("allowedApplications", [])
                apps = [f"{app.get('packageName', '')}" for app in allowed]
                app_restrictions_str = "Android Apps: " + ", ".join(apps)
            elif "iosKeyRestrictions" in restrictions:
                allowed = restrictions["iosKeyRestrictions"].get("allowedBundleIds", [])
                app_restrictions_str = "iOS Apps: " + ", ".join(allowed)

            rows.append({
                "Project ID": project_id,
                "Key Display Name": display_name,
                "Key ID (UID)": key_id,
                "Creation Date": create_time,
                "API Restrictions": api_restrictions_str,
                "Application Restrictions": app_restrictions_str,
                "Status / Debug Info": "Success"
            })

        print(f"[+] Project {project_id}: Processed {len(keys)} key(s)")

    except json.JSONDecodeError:
        rows.append({
            "Project ID": project_id,
            "Key Display Name": "N/A",
            "Key ID (UID)": "N/A",
            "Creation Date": "N/A",
            "API Restrictions": "N/A",
            "Application Restrictions": "N/A",
            "Status / Debug Info": "Error: Failed to parse Google Cloud JSON output"
        })
        print(f"[-] Project {project_id}: JSON parse error")

    return rows


def main():
    # Ask user for input instead of fetching all projects
    projects = get_projects_from_user()
    all_data = []

    # Run in parallel threads for speed
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        # executor.map maintains the output list in the same order as input list
        results = executor.map(process_project, projects)

        # Flatten the list of lists returned by threads
        for result in results:
            all_data.extend(result)

    # 3. Write to CSV
    if all_data:
        headers = ["Project ID", "Key Display Name", "Key ID (UID)", "Creation Date",
                   "API Restrictions", "Application Restrictions", "Status / Debug Info"]
        with open(OUTPUT_CSV, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=headers)
            writer.writeheader()
            writer.writerows(all_data)
        print(f"\nDone! Report successfully generated: {OUTPUT_CSV}")
    else:
        print("\nNo data generated.")


if __name__ == "__main__":
    main()
