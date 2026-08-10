#!/usr/bin/env python3
import sys
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import google.auth
from google.auth.transport.requests import Request

# =============================================================
# CONFIGURATION - Update these before running
# =============================================================
PROJECT_ID   = "YOUR_PROJECT_ID"    # GCP Project ID
LOCATION     = "us"                 # SecOps region (e.g., 'us', 'eu', 'asia-south1')
INSTANCE_ID  = "YOUR_INSTANCE_ID"  # SecOps Instance UUID (Settings > Instance)

MAX_WORKERS    = 4     # Safe thread count to prevent quota spikes
REQUEST_DELAY  = 0.15  # Micro-delay (seconds) between requests
MAX_RETRIES    = 5     # Retries for HTTP 429
# =============================================================

print_lock = threading.Lock()

def safe_print(msg: str):
    with print_lock:
        print(msg)

def get_access_token() -> str:
    credentials, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    credentials.refresh(Request())
    return credentials.token

def make_request_with_backoff(url: str, headers: dict) -> requests.Response:
    """Executes GET request with exponential backoff for HTTP 429."""
    delay = 1.0
    for attempt in range(MAX_RETRIES):
        time.sleep(REQUEST_DELAY)  # Micro-throttle
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 429:
            sleep_time = delay + random.uniform(0.1, 0.5)
            time.sleep(sleep_time)
            delay *= 2
            continue
        return response
    return response

def check_case_status(case_id: int, base_url: str, headers: dict) -> dict:
    url = f"{base_url}/{case_id}"
    try:
        response = make_request_with_backoff(url, headers)
        if response.status_code == 200:
            data = response.json()
            stage = data.get("stage", "UNKNOWN")
            is_closed = (
                stage.upper() == "CLOSED" 
                or "closeDetails" in data 
                or data.get("status", "").upper() == "CLOSED"
            )
            status_str = "CLOSED" if is_closed else f"OPEN ({stage})"
            close_reason = data.get("closeDetails", {}).get("closeReason", "N/A") if is_closed else "-"
            
            return {
                "case_id": case_id,
                "is_closed": is_closed,
                "status": status_str,
                "reason": close_reason,
                "error": None
            }
        elif response.status_code == 404:
            return {
                "case_id": case_id,
                "is_closed": None,
                "status": "NOT_FOUND",
                "reason": "-",
                "error": "Case ID does not exist"
            }
        else:
            return {
                "case_id": case_id,
                "is_closed": None,
                "status": "ERROR",
                "reason": "-",
                "error": f"HTTP {response.status_code}: {response.text}"
            }
    except Exception as e:
        return {
            "case_id": case_id,
            "is_closed": None,
            "status": "ERROR",
            "reason": "-",
            "error": str(e)
        }

def main():
    if "YOUR_INSTANCE_ID" in INSTANCE_ID:
        print("Error: Please update PROJECT_ID and INSTANCE_ID in the script before running.")
        sys.exit(1)

    raw_input = input("Enter Case IDs to check status (comma-separated): ").strip()
    if not raw_input:
        print("No input provided. Exiting.")
        sys.exit(0)

    try:
        case_ids = list(dict.fromkeys([int(x.strip()) for x in raw_input.split(",") if x.strip()]))
    except ValueError:
        print("Error: All Case IDs must be numeric integers.")
        sys.exit(1)

    total_cases = len(case_ids)
    print(f"\nLoaded {total_cases} unique Case IDs. Authenticating...")

    try:
        token = get_access_token()
    except Exception as e:
        print(f"Authentication error: {e}")
        sys.exit(1)

    base_url = (
        f"https://{LOCATION}-chronicle.googleapis.com/v1beta/"
        f"projects/{PROJECT_ID}/locations/{LOCATION}/instances/{INSTANCE_ID}/cases"
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    print(f"Checking status of {total_cases} cases with rate throttling & retry backoff...\n")

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(check_case_status, cid, base_url, headers): cid 
            for cid in case_ids
        }
        for future in as_completed(futures):
            res = future.result()
            results.append(res)
            
            if res["status"] == "CLOSED":
                safe_print(f"  [ALREADY CLOSED] Case ID: {res['case_id']} (Reason: {res['reason']})")
            elif "OPEN" in res["status"]:
                safe_print(f"  [OPEN]           Case ID: {res['case_id']}")
            else:
                safe_print(f"  [{res['status']}]          Case ID: {res['case_id']} - {res['error']}")

    results.sort(key=lambda x: x["case_id"])
    open_cases   = [str(r["case_id"]) for r in results if r["is_closed"] is False]
    closed_cases = [str(r["case_id"]) for r in results if r["is_closed"] is True]
    failed_cases = [str(r["case_id"]) for r in results if r["is_closed"] is None]

    print("\n" + "=" * 60)
    print("                    CASE STATUS REPORT")
    print("=" * 60)
    print(f"Total Checked    : {total_cases}")
    print(f"Already Closed   : {len(closed_cases)}")
    print(f"Currently Open   : {len(open_cases)}")
    print(f"Errors/Not Found : {len(failed_cases)}")
    print("=" * 60)

    if closed_cases:
        print(f"\nAlready Closed Case IDs ({len(closed_cases)}):\n" + ", ".join(closed_cases))

    if open_cases:
        print(f"\nCurrently Open Case IDs ({len(open_cases)}):\n" + ", ".join(open_cases))

    if failed_cases:
        print(f"\nCases with Errors / Not Found ({len(failed_cases)}):\n" + ", ".join(failed_cases))

if __name__ == "__main__":
    main()
