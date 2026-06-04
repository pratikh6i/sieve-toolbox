import csv
import time
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from google.cloud import compute_v1
from google.cloud import monitoring_v3
from google.api_core import exceptions
from tqdm import tqdm
from dateutil.parser import parse
from dateutil import tz

# Configuration
OUTPUT_CSV = "cloud_armor_preview_metrics.csv"
SEPARATOR = "|"
LOOKBACK_MINUTES = 60  # Query 60 minutes of data
RETRY_COUNT = 3
RETRY_DELAY = 5  # Seconds
MAX_THREADS = 10  # Adjust based on API rate limits

def validate_datetime(date_str):
    try:
        dt = datetime.datetime.strptime(date_str, "%d-%m-%Y %H:%M")
        ist = tz.gettz("Asia/Kolkata")
        dt = dt.replace(tzinfo=ist)
        return dt
    except ValueError:
        raise ValueError("Invalid date-time format. Use DD-MM-YYYY HH:MM (e.g., 29-07-2025 14:30)")

def get_cloud_armor_policies(project_id):
    try:
        client = compute_v1.SecurityPoliciesClient()
        policies = client.list(project=project_id)
        return [(policy.name, policy) for policy in policies]
    except exceptions.GoogleAPIError as e:
        print(f"Error listing policies for project {project_id}: {e}")
        return []

def get_preview_rules(project_id, policy_name):
    try:
        client = compute_v1.SecurityPoliciesClient()
        rules = client.list_rules(project=project_id, security_policy=policy_name)
        return [(rule.priority, rule) for rule in rules if rule.preview]
    except exceptions.GoogleAPIError as e:
        print(f"Error listing rules for policy {policy_name} in project {project_id}: {e}")
        return []

def get_preview_request_count(project_id, policy_name, rule_priority, start_time, end_time):
    for attempt in range(RETRY_COUNT):
        try:
            client = monitoring_v3.MetricServiceClient()
            project_name = f"projects/{project_id}"
            metric_type = "networksecurity.googleapis.com/security_policy_rule/evaluated_count"
            filter_str = (
                f'metric.type="{metric_type}" '
                f'resource.type="network_security_policy" '
                f'metric.labels.outcome="PREVIEW_DENIED" '
                f'metric.labels.security_policy_name="{policy_name}" '
                f'metric.labels.priority="{rule_priority}"'
            )
            interval = monitoring_v3.TimeInterval(
                end_time={"seconds": int(end_time.timestamp())},
                start_time={"seconds": int(start_time.timestamp())}
            )
            results = client.list_time_series(
                request={
                    "name": project_name,
                    "filter": filter_str,
                    "interval": interval,
                    "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL
                }
            )
            count = 0
            for result in results:
                for point in result.points:
                    count += point.value.int64_value
            return count
        except exceptions.GoogleAPIError as e:
            if attempt < RETRY_COUNT - 1:
                print(f"Retrying ({attempt + 1}/{RETRY_COUNT}) for rule {rule_priority} in policy {policy_name}: {e}")
                time.sleep(RETRY_DELAY)
            else:
                print(f"Failed after {RETRY_COUNT} attempts for rule {rule_priority} in policy {policy_name}: {e}")
                return None
    return None

def process_rule(project_id, policy_name, rule_priority, rule, start_time, end_time):
    count = get_preview_request_count(project_id, policy_name, rule_priority, start_time, end_time)
    if count is not None:
        description = rule.description or "No description"
        return [project_id, policy_name, str(rule_priority), description, str(count)]
    return None

def write_csv(data):
    try:
        with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter=SEPARATOR, quoting=csv.QUOTE_MINIMAL)
            writer.writerow(["Project ID", "Policy Name", "Rule Priority", "Rule Description", "Preview Request Count"])
            for row in data:
                writer.writerow(row)
        print(f"\nCSV written to {OUTPUT_CSV}")
    except IOError as e:
        print(f"Error writing CSV: {e}")

def main():
    # Prompt for user input
    project_id = input("Enter Project ID: ").strip()
    if not project_id:
        print("Error: Project ID cannot be empty")
        return

    date_str = input("Enter date and time (DD-MM-YYYY HH:MM IST): ").strip()
    try:
        dt_ist = validate_datetime(date_str)
    except ValueError as e:
        print(f"Error: {e}")
        return

    # Convert IST to UTC for Cloud Monitoring
    utc = tz.gettz("UTC")
    dt_utc = dt_ist.astimezone(utc)
    end_time = dt_utc
    start_time = dt_utc - datetime.timedelta(minutes=LOOKBACK_MINUTES)

    print(f"Processing project: {project_id}")
    print(f"Querying data from {start_time.strftime('%Y-%m-%d %H:%M:%S %Z')} to {end_time.strftime('%Y-%m-%d %H:%M:%S %Z')}")

    # Get policies
    policies = get_cloud_armor_policies(project_id)
    if not policies:
        print(f"No policies found in project {project_id}")
        return

    results = []
    tasks = []

    # Collect all rules for parallel processing
    for policy_name, _ in policies:
        print(f"  Fetching rules for policy: {policy_name}")
        rules = get_preview_rules(project_id, policy_name)
        if not rules:
            print(f"    No preview rules found for policy {policy_name}")
            continue
        for rule_priority, rule in rules:
            tasks.append((project_id, policy_name, rule_priority, rule, start_time, end_time))

    # Process rules in parallel with progress bar
    print("  Querying preview rule metrics...")
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_task = {executor.submit(process_rule, *task): task for task in tasks}
        for future in tqdm(as_completed(future_to_task), total=len(tasks), desc="Processing rules"):
            result = future.result()
            if result:
                results.append(result)

    if not results:
        print("No valid data to write to CSV")
        return

    write_csv(results)

if __name__ == "__main__":
    main()