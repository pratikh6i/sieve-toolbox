#!/usr/bin/env python3
"""
Google SecOps (Chronicle) Universal High-Speed Case Exporter
Multi-Stream | Automatic 429 Retry | Readable Timestamps & Formatted Column Headers
"""

import argparse
import concurrent.futures
import csv
import json
import random
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[*] Installing required 'requests' package...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

# Default environment configuration — replace with your own values or pass via CLI flags
DEFAULT_PROJECT_ID = "YOUR_PROJECT_ID"
DEFAULT_INSTANCE_ID = "YOUR_INSTANCE_ID"
DEFAULT_REGION = "us"

# Rate-limit optimized defaults
DEFAULT_NUM_SLICES = 6       # 6 parallel streams prevents 429 rate-limiting
MAX_WORKER_THREADS = 30      # Connection pool thread limit
PAGE_MICRO_PAUSE = 0.05      # 50ms delay between pages to keep velocity smooth


def get_gcloud_token():
    """Retrieves access token using gcloud CLI."""
    try:
        token = subprocess.check_output(
            ["gcloud", "auth", "print-access-token"], text=True
        ).strip()
        if not token:
            raise ValueError("Empty access token returned.")
        return token
    except Exception as e:
        print(f"\n[!] AUTH ERROR: Failed to get gcloud access token: {e}", flush=True)
        sys.exit(1)


def create_pooled_session():
    """Creates a high-performance HTTP session with connection pooling."""
    session = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=MAX_WORKER_THREADS + 10,
        pool_maxsize=MAX_WORKER_THREADS + 10
    )
    session.mount("https://", adapter)
    return session


def format_epoch_ms(ms_val):
    """
    Converts epoch milliseconds/seconds to human-readable datetime format.
    Example output: '12 July 2026, 18:32 IST'
    """
    if not ms_val:
        return ""
    try:
        val = float(ms_val)
        # Handle milliseconds vs seconds
        if val > 100000000000:
            val = val / 1000.0
        
        # Convert to IST timezone (UTC + 5:30)
        ist_tz = timezone(timedelta(hours=5, minutes=30))
        dt = datetime.fromtimestamp(val, tz=timezone.utc).astimezone(ist_tz)
        return dt.strftime("%d %B %Y, %H:%M IST")
    except Exception:
        return str(ms_val)


def format_header_name(key):
    """
    Converts camelCase, snake_case, or dot.notation into Clean Title Case with spaces.
    Examples:
      'createTime'             -> 'Create Time'
      'alertCount'             -> 'Alert Count'
      'lastModifyingUserId'    -> 'Last Modifying User Id'
      'customFields.subField'  -> 'Custom Fields Sub Field'
    """
    if not key:
        return ""
    # Split camelCase words
    s = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', key)
    # Replace dots, underscores, and hyphens with spaces
    s = re.sub(r'[\._\-]+', ' ', s)
    # Capitalize first character of every word
    words = [w.capitalize() for w in s.split()]
    return " ".join(words)


def parse_datetime(dt_str, is_end=False):
    """Parses standard ISO date/time strings into UTC datetimes."""
    dt_str = dt_str.strip()
    if len(dt_str) == 10:  # YYYY-MM-DD
        dt_str += "T23:59:59Z" if is_end else "T00:00:00Z"
    if dt_str.endswith("Z"):
        dt_str = dt_str[:-1] + "+00:00"
    
    dt = datetime.fromisoformat(dt_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def parse_time_input(time_str):
    """Parses relative time strings ('15d', '30d', '90d', '24h') or exact dates into UTC datetimes."""
    time_str = time_str.strip()
    now_utc = datetime.now(timezone.utc)

    match = re.match(r"^(\d+)\s*([dDhHmMsS])$", time_str)
    if match:
        amount = int(match.group(1))
        unit = match.group(2).lower()
        
        if unit == 'd':
            start_dt = now_utc - timedelta(days=amount)
        elif unit == 'h':
            start_dt = now_utc - timedelta(hours=amount)
        elif unit == 'm':
            start_dt = now_utc - timedelta(minutes=amount)
        elif unit == 's':
            start_dt = now_utc - timedelta(seconds=amount)
        
        return start_dt, now_utc, True

    start_dt = parse_datetime(time_str, is_end=False)
    return start_dt, None, False


def generate_time_slices(start_dt, end_dt, slices=6):
    """Splits a large time range into N equal parallel time-slice chunks."""
    total_seconds = (end_dt - start_dt).total_seconds()
    if total_seconds <= 0:
        return [(start_dt, end_dt)]
        
    chunk_seconds = total_seconds / slices
    chunks = []
    for i in range(slices):
        c_start = start_dt + timedelta(seconds=i * chunk_seconds)
        c_end = start_dt + timedelta(seconds=(i + 1) * chunk_seconds)
        if i == slices - 1:
            c_end = end_dt
        chunks.append((c_start, c_end))
    return chunks


def flatten_json(nested_data, parent_key='', sep='.'):
    """Recursively flattens any nested dictionary or list structure."""
    items = {}
    if isinstance(nested_data, dict):
        for key, value in nested_data.items():
            new_key = f"{parent_key}{sep}{key}" if parent_key else key
            items.update(flatten_json(value, new_key, sep=sep))
    elif isinstance(nested_data, list):
        if not nested_data:
            items[parent_key] = ""
        elif all(isinstance(x, (str, int, float, bool)) for x in nested_data):
            items[parent_key] = ", ".join(map(str, nested_data))
        else:
            items[parent_key] = json.dumps(nested_data, ensure_ascii=False)
    else:
        items[parent_key] = nested_data
    return items


def fetch_custom_fields(session, token, host, case_name):
    """Fetches custom field sub-resource values using connection pooling."""
    custom_url = f"{host}/v1beta/{case_name}/customFieldValues"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = session.get(custom_url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("customFieldValues", data)
    except Exception:
        pass
    return {}


def process_case(session, token, host, case, fetch_custom=False):
    """Standardizes case fields: Clean ID, Clean Priority, Readable Timestamps, Alert Count."""
    raw_case_name = case.get("name", "")

    # Save raw creation timestamp for accurate numerical sorting
    raw_create_time = case.get("createTime", 0)
    try:
        case["_sort_time"] = int(raw_create_time)
    except Exception:
        case["_sort_time"] = 0

    # 1. Clean numeric Case ID
    if raw_case_name and "/" in raw_case_name:
        case["name"] = raw_case_name.split("/")[-1]

    # 2. Convert Timestamps to Human-Readable Format
    if "createTime" in case:
        case["createTime"] = format_epoch_ms(case["createTime"])
    if "updateTime" in case:
        case["updateTime"] = format_epoch_ms(case["updateTime"])

    # 3. Clean Priority enum value
    if "priority" in case and isinstance(case["priority"], str):
        case["priority"] = case["priority"].replace("PRIORITY_", "")

    # 4. Formatted products list
    if "products" in case and isinstance(case["products"], list):
        formatted_products = []
        for item in case["products"]:
            if isinstance(item, dict):
                alert_name = item.get("alert", "")
                disp_name = item.get("displayName", "")
                if alert_name and disp_name:
                    formatted_products.append(f"[{disp_name}] {alert_name}")
                elif alert_name:
                    formatted_products.append(alert_name)
                elif disp_name:
                    formatted_products.append(disp_name)
            elif isinstance(item, str):
                formatted_products.append(item)
        case["products"] = "; ".join(formatted_products)

    # 5. Guarantee alertCount
    if "alertCount" not in case:
        case["alertCount"] = len(case.get("alerts", [])) or len(case.get("caseAlerts", []))

    flat_case = flatten_json(case)

    if fetch_custom and raw_case_name:
        custom_fields = fetch_custom_fields(session, token, host, raw_case_name)
        if custom_fields:
            flat_custom = flatten_json(custom_fields, parent_key="customFields")
            flat_case.update(flat_custom)

    return flat_case


def fetch_slice_cases(session, token, host, base_url, slice_id, start_dt, end_dt, custom_filter, fetch_custom):
    """Worker function: Fetches all pages for a slice with automatic 429 retry backoff."""
    start_ms = int(start_dt.timestamp() * 1000)
    end_ms = int(end_dt.timestamp() * 1000)

    filter_expr = f'CreateTime >= {start_ms} AND CreateTime <= {end_ms}'
    if custom_filter:
        filter_expr += f' AND ({custom_filter})'

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    slice_cases = []
    page_token = ""
    page_count = 0
    retries_429 = 0

    while True:
        params = {
            "pageSize": 100,
            "expand": "tags,products,tasks",
            "filter": filter_expr
        }
        if page_token:
            params["pageToken"] = page_token

        try:
            resp = session.get(base_url, headers=headers, params=params, timeout=30)
            
            # AUTOMATIC 429 RETRY BACKOFF
            if resp.status_code == 429 or "RESOURCE_EXHAUSTED" in resp.text:
                retries_429 += 1
                backoff_time = min(60, (2 ** retries_429) + random.uniform(0.5, 1.5))
                print(f"\n[*] [Stream {slice_id:02d}] Rate limit hit (429). Retrying page in {backoff_time:.1f}s (Attempt {retries_429})...", flush=True)
                time.sleep(backoff_time)
                continue

            if resp.status_code != 200:
                print(f"\n[!] Stream {slice_id} HTTP Error {resp.status_code}: {resp.text}", flush=True)
                break

            retries_429 = 0
            page_count += 1

            data = resp.json()
            raw_cases = data.get("cases", [])
            if not raw_cases:
                break

            if fetch_custom:
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKER_THREADS) as executor:
                    futures = [executor.submit(process_case, session, token, host, c, True) for c in raw_cases]
                    for f in concurrent.futures.as_completed(futures):
                        slice_cases.append(f.result())
            else:
                for c in raw_cases:
                    slice_cases.append(process_case(session, token, host, c, False))

            print(f"[*] [Stream {slice_id:02d}] Page {page_count:02d} fetched ({len(slice_cases)} cases total)...", flush=True)

            page_token = data.get("nextPageToken")
            if not page_token:
                break

            time.sleep(PAGE_MICRO_PAUSE)

        except Exception as e:
            print(f"\n[!] Stream {slice_id} Exception: {e}", flush=True)
            time.sleep(2)

    return slice_cases


def generate_unique_filename():
    """Generates a unique timestamped output filename."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"secops_cases_export_{ts}.csv"


def main():
    parser = argparse.ArgumentParser(description="Universal High-Speed Google SecOps Cases Exporter")
    parser.add_argument("-p", "--project", default=DEFAULT_PROJECT_ID, help="GCP Project ID")
    parser.add_argument("-i", "--instance", default=DEFAULT_INSTANCE_ID, help="SecOps Customer / Instance ID")
    parser.add_argument("-r", "--region", default=DEFAULT_REGION, help="SecOps Region (e.g. us, eu, asia-south1)")
    parser.add_argument("-t", "--timeframe", help="Timeframe (e.g., '15d', '30d', '90d', '24h')")
    parser.add_argument("--start", help="Start Date (YYYY-MM-DD or ISO string)")
    parser.add_argument("--end", help="End Date (YYYY-MM-DD or ISO string)")
    parser.add_argument("-f", "--filter", default="", help="Optional additional API filter string")
    parser.add_argument("-o", "--output", help="Output CSV filename")
    parser.add_argument("-d", "--delimiter", default="|", help="CSV Delimiter (default: '|')")
    parser.add_argument("-s", "--slices", type=int, default=DEFAULT_NUM_SLICES, help="Number of parallel time streams (default: 6)")
    parser.add_argument("-c", "--fetch-custom", action="store_true", help="Fetch deep customFieldValues sub-resource for each case")

    args = parser.parse_args()

    print("=" * 75, flush=True)
    print("      Google SecOps Universal High-Speed Case Exporter", flush=True)
    print("=" * 75, flush=True)

    project_id = args.project
    instance_id = args.instance
    region = args.region

    if not args.timeframe and not args.start:
        tf_input = input("\n[?] Enter timeframe (e.g. '15d', '30d', '90d') OR start date (YYYY-MM-DD): ").strip()
        if not tf_input:
            tf_input = "90d"
            print(f"[*] Defaulting timeframe to: {tf_input}", flush=True)
        
        start_dt, end_dt, is_relative = parse_time_input(tf_input)
        if not is_relative:
            end_prompt = input("[?] Enter end date (YYYY-MM-DD) [Press Enter for NOW]: ").strip()
            if not end_prompt:
                end_dt = datetime.now(timezone.utc)
            else:
                end_dt = parse_datetime(end_prompt, is_end=True)
    elif args.start:
        start_dt = parse_datetime(args.start, is_end=False)
        end_dt = parse_datetime(args.end, is_end=True) if args.end else datetime.now(timezone.utc)
    else:
        start_dt, end_dt, _ = parse_time_input(args.timeframe)

    fetch_custom = args.fetch_custom
    if not args.timeframe and not args.fetch_custom:
        cf_prompt = input("\n[?] Fetch deep dynamic customFieldValues sub-resource for each case? (y/N) [Default N = 10x Faster]: ").strip().lower()
        fetch_custom = cf_prompt.startswith('y')

    output_filename = args.output if args.output else generate_unique_filename()

    token = get_gcloud_token()
    host = f"https://{region}-chronicle.googleapis.com"
    base_url = f"{host}/v1beta/projects/{project_id}/locations/{region}/instances/{instance_id}/cases"

    num_slices = args.slices
    time_chunks = generate_time_slices(start_dt, end_dt, slices=num_slices)

    print("\n" + "-" * 75, flush=True)
    print(" EXPORT CONFIGURATION SUMMARY", flush=True)
    print("-" * 75, flush=True)
    print(f"[*] Project ID     : {project_id}", flush=True)
    print(f"[*] Instance ID    : {instance_id}", flush=True)
    print(f"[*] Region Host    : {host}", flush=True)
    print(f"[*] Time Range     : {start_dt.strftime('%Y-%m-%dT%H:%M:%SZ')} --> {end_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}", flush=True)
    print(f"[*] Time Streams   : {num_slices} Parallel Workers", flush=True)
    print(f"[*] Auto 429 Retry : Enabled (Zero Data Loss)", flush=True)
    print(f"[*] Output File    : {output_filename}", flush=True)
    print(f"[*] Delimiter      : '{args.delimiter}'", flush=True)
    print("-" * 75 + "\n", flush=True)

    session = create_pooled_session()
    all_flattened_cases = []
    all_field_names = set()
    seen_case_ids = set()

    start_benchmark = time.time()
    print("[*] Launching parallel time-stream workers...", flush=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_slices) as slice_executor:
        futures = [
            slice_executor.submit(
                fetch_slice_cases,
                session, token, host, base_url,
                idx + 1, chunk[0], chunk[1],
                args.filter, fetch_custom
            )
            for idx, chunk in enumerate(time_chunks)
        ]

        for future in concurrent.futures.as_completed(futures):
            try:
                slice_data = future.result()
                for c in slice_data:
                    case_id = c.get("name", c.get("id", ""))
                    if case_id and case_id not in seen_case_ids:
                        seen_case_ids.add(case_id)
                        all_field_names.update(c.keys())
                        all_flattened_cases.append(c)
            except Exception as slice_err:
                print(f"[!] Worker stream error: {slice_err}", flush=True)

    if not all_flattened_cases:
        print("\n[!] Export complete. Zero matching cases found.", flush=True)
        return

    # Sort cases chronologically using numerical sort key
    all_flattened_cases.sort(key=lambda x: x.get("_sort_time", 0), reverse=True)

    # Discard temporary internal sort key from CSV export headers
    all_field_names.discard("_sort_time")

    # Order priority keys first
    priority_headers = ["name", "id", "title", "createTime", "alertCount", "priority", "status", "stage"]
    sorted_raw_headers = sorted(
        list(all_field_names),
        key=lambda x: (0, priority_headers.index(x)) if x in priority_headers else (1, x)
    )

    # Map raw key headers to Clean Title Case headers
    header_mapping = {raw_key: format_header_name(raw_key) for raw_key in sorted_raw_headers}
    final_csv_headers = [header_mapping[raw_key] for raw_key in sorted_raw_headers]

    print(f"\n[*] Writing {len(all_flattened_cases)} cases with {len(final_csv_headers)} distinct columns to '{output_filename}'...", flush=True)
    try:
        with open(output_filename, mode='w', newline='', encoding='utf-8') as csv_file:
            writer = csv.DictWriter(
                csv_file,
                fieldnames=final_csv_headers,
                delimiter=args.delimiter,
                quoting=csv.QUOTE_MINIMAL
            )
            writer.writeheader()
            
            for row in all_flattened_cases:
                # Transform dictionary keys to clean header names
                row_formatted = {header_mapping[k]: v for k, v in row.items() if k != "_sort_time"}
                writer.writerow(row_formatted)

        total_duration = time.time() - start_benchmark
        rate = len(all_flattened_cases) / total_duration if total_duration > 0 else 0
        
        print(f"\n[+] SUCCESS! Exported all {len(all_flattened_cases)} cases in {total_duration:.2f} seconds! (~{rate:.1f} cases/sec)")
        print(f"[+] Output File          : {output_filename}")
        print(f"[+] Total Cases Exported : {len(all_flattened_cases)}")
        print(f"[+] Total Columns Mapped : {len(final_csv_headers)}")
        print(f"[+] Delimiter Used       : '{args.delimiter}'\n")

    except Exception as e:
        print(f"\n[!] FILE WRITE ERROR: {e}\n", flush=True)


if __name__ == "__main__":
    main()
