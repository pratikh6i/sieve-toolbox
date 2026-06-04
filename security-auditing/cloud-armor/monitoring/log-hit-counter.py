import sys
from datetime import datetime, timedelta
import pytz  # A robust library for handling timezones
from tqdm import tqdm
from google.cloud import logging  # Requires: pip install google-cloud-logging

# --- Configuration ---
# You can set your local timezone here. 'Asia/Kolkata' is for IST.
LOCAL_TIMEZONE = 'Asia/Kolkata'

def parse_datetime_input(input_str: str, tz_info) -> datetime:
    """Parses 'DD-MM-YYYY HH:MM' format and makes it timezone-aware."""
    try:
        dt_naive = datetime.strptime(input_str, "%d-%m-%Y %H:%M")
        return tz_info.localize(dt_naive)
    except ValueError:
        print(f"❌ Error: Invalid date format. Please use 'DD-MM-YYYY HH:MM'.")
        sys.exit(1)

def generate_daily_ranges(start_dt: datetime, end_dt: datetime) -> list:
    """Splits a date range into a list of smaller (start, end) tuples, mostly 24h long."""
    if start_dt >= end_dt:
        print("❌ Error: Start date must be before the end date.")
        sys.exit(1)

    # If the range is less than a day, don't split it.
    if (end_dt - start_dt) < timedelta(days=1):
        return [(start_dt, end_dt)]

    ranges = []
    current_start = start_dt
    while current_start < end_dt:
        day_end = (current_start + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        effective_end = min(day_end, end_dt)
        ranges.append((current_start, effective_end))
        current_start = effective_end
    
    return ranges

def get_count_for_range(project_id: str, policy_name: str, priority: str, date_range: tuple) -> int:
    """Uses the Google Cloud Logging API to count logs for a specific date range."""
    start_dt, end_dt = date_range
    
    # Convert local time to UTC and format for the filter
    start_utc_str = start_dt.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    end_utc_str = end_dt.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    # Construct the filter
    filter_string = (
        f'jsonPayload.previewSecurityPolicy.name="{policy_name}" '
        f'AND jsonPayload.previewSecurityPolicy.priority="{priority}" '
        f'AND timestamp >= "{start_utc_str}" AND timestamp < "{end_utc_str}"'
    )

    try:
        client = logging.Client(project=project_id)
        count = 0
        # Iterate over the entries to count them, streaming without storing full data
        for _ in client.list_entries(filter_=filter_string, page_size=1000):
            count += 1
        return count
    except Exception as e:
        print(f"\nError for priority {priority} range {start_utc_str} to {end_utc_str}: {e}", file=sys.stderr)
        return -1

def main():
    """Main function to drive the script."""
    print("--- Serial Cloud Armor Log Counter ---")
    
    # 1. Get user input
    project_id = input("▶ Enter Google Cloud Project ID: ").strip()
    policy_name = input("▶ Enter Cloud Armor Policy Name: ").strip()
    priority_input = input("▶ Enter the Preview Rule Priorities (comma-separated): ").strip()
    priorities = [p.strip() for p in priority_input.split(',') if p.strip()]
    
    if not priorities:
        print("❌ Error: No priorities entered.")
        sys.exit(1)
    
    try:
        local_tz = pytz.timezone(LOCAL_TIMEZONE)
    except pytz.UnknownTimeZoneError:
        print(f"❌ Error: Unknown timezone '{LOCAL_TIMEZONE}'. Please check the configuration.")
        sys.exit(1)

    start_str = input(f"▶ Enter Start Time ({local_tz.zone} in DD-MM-YYYY HH:MM format): ").strip()
    start_dt = parse_datetime_input(start_str, local_tz)
    
    end_str = input(f"▶ Enter End Time ({local_tz.zone} in DD-MM-YYYY HH:MM format): ").strip()
    end_dt = parse_datetime_input(end_str, local_tz)

    # 2. Split the date range into daily jobs
    daily_jobs = generate_daily_ranges(start_dt, end_dt)
    print(f"\n🗓️ Splitting the time range into {len(daily_jobs)} smaller jobs per priority.")

    priority_counts = {}
    priority_failed = {}
    
    # 3. Process priorities serially
    for prio in priorities:
        print(f"\nProcessing priority: {prio}")
        total_count = 0
        tasks_failed = False
        
        # Process days serially with tqdm
        for job_range in tqdm(daily_jobs, desc=f"Processing days for {prio}", unit="day"):
            daily_count = get_count_for_range(project_id, policy_name, prio, job_range)
            if daily_count >= 0:
                total_count += daily_count
            else:
                tasks_failed = True
        
        priority_counts[prio] = total_count
        priority_failed[prio] = tasks_failed
    
    # 4. Print the final summary
    print("\n--- Counting Complete ---")
    print(f"Policy Name:      {policy_name}")
    print(f"Time Range (UTC): {start_dt.astimezone(pytz.utc).strftime('%Y-%m-%d %H:%M')} to {end_dt.astimezone(pytz.utc).strftime('%Y-%m-%d %H:%M')}")
    print("-----------------------------------")
    for prio in priorities:
        count = priority_counts[prio]
        if priority_failed[prio]:
            print(f"⚠️  Priority {prio} (PARTIAL): {count}")
        else:
            print(f"✅ Priority {prio}: {count}")
    print("-----------------------------------")
    
    # 5. CSV Output
    print("\n--- CSV Output (Copy to Google Sheets) ---")
    print("Priority,Count")
    try:
        sorted_priorities = sorted(priorities, key=int)
    except ValueError:
        sorted_priorities = sorted(priorities)
    for prio in sorted_priorities:
        print(f"{prio},{priority_counts[prio]}")

if __name__ == "__main__":
    main() 
