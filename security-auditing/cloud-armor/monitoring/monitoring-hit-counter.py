import sys
import csv
import logging
from datetime import datetime, timedelta, timezone
from google.cloud import compute_v1
from google.cloud import monitoring_v3
from google.api_core import exceptions

# --- Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)

# --- Main Functions ---

def get_preview_rules(project_id: str, policy_name: str) -> list:
    """Fetches a Cloud Armor policy and returns a list of its preview rules."""
    logging.info(f"Attempting to fetch rules for policy '{policy_name}' in project '{project_id}'.")
    try:
        logging.info("Initializing Google Cloud Compute API client.")
        client = compute_v1.SecurityPoliciesClient()
        logging.info("Compute API client initialized successfully.")
        logging.info(f"Requesting details for security policy '{policy_name}'.")
        policy = client.get(project=project_id, security_policy=policy_name)
        logging.info(f"Successfully fetched security policy '{policy_name}'.")
        preview_rules = [rule for rule in policy.rules if rule.preview]
        logging.info(f"Found a total of {len(preview_rules)} preview rules in policy '{policy_name}'.")
        return preview_rules
    except exceptions.NotFound:
        logging.error(f"Error: Security policy '{policy_name}' not found in project '{project_id}'.")
        return []
    except Exception as e:
        logging.error(f"An unexpected error occurred while fetching rules: {e}")
        return []

def get_request_count_from_monitoring(project_id: str, policy_name: str, rule_priority: int) -> int:
    """
    Queries the Cloud Monitoring API for the aggregated count of requests
    matched by a preview rule. This is highly efficient.
    """
    logging.info(f"Querying Monitoring API for aggregated count for rule '{rule_priority}'.")
    try:
        logging.info("Initializing Google Cloud Monitoring API client.")
        client = monitoring_v3.MetricServiceClient()
        project_name = f"projects/{project_id}"
        logging.info("Monitoring API client initialized successfully.")

        logging.info("Calculating time window: last 30 days.")
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=30)
        
        interval = monitoring_v3.TimeInterval(
            {
                "end_time": {"seconds": int(end_time.timestamp())},
                "start_time": {"seconds": int(start_time.timestamp())},
            }
        )
        logging.info(f"Query time range (UTC): {start_time.isoformat()} to {end_time.isoformat()}.")

        metric_filter = (
            f'metric.type="networksecurity.googleapis.com/security_policy_rule/evaluated_count" '
            f'metric.labels.security_policy_name = "{policy_name}" '
            f'metric.labels.priority = "{rule_priority}" '
            f'metric.labels.outcome = "PREVIEW"'
        )
        logging.info(f"Constructed Monitoring API filter:\n---\n{metric_filter}\n---")

        request = {
            "name": project_name,
            "filter": metric_filter,
            "interval": interval,
            "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            "aggregation": {
                "alignment_period": {"seconds": (30 * 24 * 60 * 60) + 60},
                "per_series_aligner": monitoring_v3.Aggregation.Aligner.ALIGN_SUM,
            },
        }

        logging.info("Executing the monitoring query...")
        time_series = client.list_time_series(request)
        total_count = 0
        for series in time_series:
            for point in series.points:
                total_count += point.value.int64_value
        
        logging.info(f"Query complete. Found an aggregated count of {total_count} for rule '{rule_priority}'.")
        return total_count

    # --- THE FIX ---
    # Catch the 'NotFound' error specifically. This means the metric exists but has no data, so the count is 0.
    except exceptions.NotFound:
        logging.info(f"API returned 404 Not Found for rule '{rule_priority}'. This means the count is 0.")
        return 0
    except exceptions.PermissionDenied:
        logging.error(f"Permission denied. Ensure you have 'monitoring.timeSeries.list' permission.")
        return -1
    except Exception as e:
        logging.error(f"An unexpected error occurred during monitoring query for rule '{rule_priority}': {e}")
        return -2

def write_to_csv(data: list, policy_name: str):
    """Writes the collected data to a CSV file."""
    filename = f"cloud_armor_{policy_name}_preview_counts.csv"
    logging.info(f"Preparing to write results to CSV file: '{filename}'.")
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            header = ["Project ID", "Policy Name", "Rule Priority", "Rule Description", "Preview Request Count (Last 30 Days)"]
            writer.writerow(header)
            writer.writerows(data)
        logging.info(f"Successfully created CSV file: {filename}")
        print(f"\n✅ Success! Data has been written to {filename}")
    except IOError as e:
        logging.error(f"Failed to write to CSV file '{filename}': {e}")
        print(f"\n❌ Error: Could not write data to {filename}.")

def main():
    """Main function to drive the script."""
    logging.info("--- Cloud Armor Preview Rule Counter Script Started ---")
    
    project_id = input("▶ Enter your Google Cloud Project ID: ").strip()
    policy_name = input(f"▶ Enter the Cloud Armor Policy Name for project '{project_id}': ").strip()
        
    logging.info(f"User provided Project ID: '{project_id}' and Policy Name: '{policy_name}'.")

    preview_rules = get_preview_rules(project_id, policy_name)

    if not preview_rules:
        print(f"\nCould not find any rules in preview mode for policy '{policy_name}'.")
        return
    
    print("\n--------------------------------------------------")
    print(f"🔍 Found the following {len(preview_rules)} rules in PREVIEW mode:")
    for rule in preview_rules:
        print(f"  - Priority: {rule.priority:<10} | Description: '{rule.description or 'No description'}'")
    print("--------------------------------------------------")

    proceed = input("\n❔ Do you want to continue and query the counts for these rules? (Y/N): ").strip().lower()
    if proceed != 'y':
        print("Ok, stopping script as requested.")
        return

    logging.info("User confirmed. Proceeding to query metrics for each preview rule.")
    results_data = []
    for rule in preview_rules:
        print(f"\nProcessing rule with priority: {rule.priority}...")
        count = get_request_count_from_monitoring(project_id, policy_name, rule.priority)
        
        count_display = str(count) if count >= 0 else "ERROR (Check logs for details)"
        
        results_data.append([
            project_id,
            policy_name,
            rule.priority,
            rule.description or "No description provided",
            count_display
        ])
        logging.info(f"Stored result for rule {rule.priority}: Count = {count_display}")

    if results_data:
        write_to_csv(results_data, policy_name)

    logging.info("--- Script Finished ---")

if __name__ == "__main__":
    main() 
