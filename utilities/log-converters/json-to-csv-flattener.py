# gemini chag used - https://gemini.google.com/app/9f5187841fc4b49d


import json
import csv
import sys
import os
import subprocess

def flatten_json(data, parent_key='', sep='.'):
    """
    Recursively flattens a nested dictionary into a single level.
    Example: {'a': {'b': 1}} becomes {'a.b': 1}
    """
    items = {}
    for key, value in data.items():
        new_key = f"{parent_key}{sep}{key}" if parent_key else key
        if isinstance(value, dict):
            items.update(flatten_json(value, new_key, sep=sep))
        elif isinstance(value, list):
            # Convert lists to a JSON string to keep them in one cell
            items[new_key] = json.dumps(value)
        else:
            items[new_key] = value
    return items

def get_value_from_path(data, path):
    """
    Safely gets a value from a nested dict using a dot-separated path.
    Example path: 'jsonPayload.threatDetails.severity'
    """
    keys = path.split('.')
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key)
        else:
            return None # Path is invalid
    return data

def convert_json_to_csv(input_file, output_file, mode):
    """
    Converts a JSON file to a CSV file with user-selectable columns.
    """
    # Define the columns for the "Overview" mode
    overview_columns = {
        "Timestamp": "timestamp",
        "Severity": "jsonPayload.threatDetails.severity",
        "Threat Name": "jsonPayload.threatDetails.threat",
        "Category": "jsonPayload.threatDetails.category",
        "Action": "jsonPayload.action",
        "Source IP": "jsonPayload.connection.clientIp",
        "Source Port": "jsonPayload.connection.clientPort",
        "Destination IP": "jsonPayload.connection.serverIp",
        "Destination Port": "jsonPayload.connection.serverPort",
        "Protocol": "jsonPayload.connection.protocol",
        "Direction": "jsonPayload.threatDetails.direction",
        "VM Name": "jsonPayload.interceptInstance.vm",
        "VPC": "jsonPayload.interceptVpc.vpc"
    }

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            # Handle empty file from gcloud if no logs are found
            content = f.read()
            if not content.strip():
                log_data = []
            else:
                log_data = json.loads(content)
    except FileNotFoundError:
        print(f"❌ Error: The temporary log file '{input_file}' was not found.")
        return
    except json.JSONDecodeError:
        print(f"❌ Error: '{input_file}' contains invalid JSON. This may happen if the gcloud command failed.")
        return

    # Ensure data is a list for consistent processing
    if isinstance(log_data, dict):
        log_data = [log_data]
    
    if not log_data:
        print("⚠️ No logs found for the specified criteria. An empty CSV file will be created.")
        open(output_file, 'w').close()
        print(f"✅ Successfully created empty CSV '{output_file}'")
        return

    with open(output_file, 'w', newline='', encoding='utf-8') as csv_file:
        if mode == '1': # Overview Mode
            print("📊 Generating 'Overview' CSV...")
            # Use pipe as the delimiter
            writer = csv.writer(csv_file, delimiter='|')
            writer.writerow(overview_columns.keys())
            for entry in log_data:
                row = [get_value_from_path(entry, path) for path in overview_columns.values()]
                writer.writerow(row)

        elif mode == '2': # Full Detail Mode
            print("⚙️ Generating 'Full Detail' CSV...")
            flattened_data = [flatten_json(entry) for entry in log_data]
            all_headers = set().union(*(d.keys() for d in flattened_data))
            sorted_headers = sorted(list(all_headers))
            # Use pipe as the delimiter
            writer = csv.DictWriter(csv_file, fieldnames=sorted_headers, delimiter='|')
            writer.writeheader()
            writer.writerows(flattened_data)

    print(f"✅ Successfully converted logs to '{output_file}'")


def fetch_gcloud_logs(project_id, freshness, temp_json_file):
    """
    Runs the gcloud command to fetch logs and saves them to a file.
    """
    print("\n☁️  Fetching logs from Google Cloud...")
    log_name = f'logName="projects/{project_id}/logs/networksecurity.googleapis.com%2Ffirewall_threat"'
    
    command = [
        "gcloud", "logging", "read", log_name,
        "--project", project_id,
        "--freshness", freshness,
        "--format", "json"
    ]
    
    try:
        with open(temp_json_file, 'w') as f:
            # Execute the command and redirect output to the temp file
            subprocess.run(command, check=True, text=True, stdout=f)
        print("✔️  Logs fetched successfully.")
        return True
    except FileNotFoundError:
        print("❌ Error: 'gcloud' command not found. Is the Google Cloud SDK installed and in your PATH?")
        return False
    except subprocess.CalledProcessError as e:
        print(f"❌ Error during gcloud command execution. Please check your permissions and project ID.")
        # print(f"   Details: {e}") # Uncomment for more detailed error info
        return False


# --- Main execution logic ---
if __name__ == "__main__":
    print("--- Automated GCP Log Fetcher and Converter ---")
    
    # Get user input for the gcloud command
    project_id = input("Enter your GCP Project ID (e.g., vitupay-ins-prod): ")
    freshness = input("Enter the log freshness (e.g., 7d, 24h, 60m): ")
    output_csv_file = input("Enter the desired name for your output CSV file (e.g., threats.csv): ")

    temp_json_filename = "temp_gcp_logs.json"

    # Fetch logs first
    if fetch_gcloud_logs(project_id, freshness, temp_json_filename):
        # If logs are fetched successfully, proceed with conversion
        choice = ''
        while choice not in ['1', '2']:
            print("\nSelect the type of CSV you want to create:")
            print("  1: Overview (Recommended for analysis - clean, essential columns)")
            print("  2: Full Detail (All log fields - very wide file)")
            choice = input("Enter your choice (1 or 2): ")

        convert_json_to_csv(temp_json_filename, output_csv_file, choice)

    # Cleanup: Remove the temporary JSON file
    if os.path.exists(temp_json_filename):
        os.remove(temp_json_filename)


