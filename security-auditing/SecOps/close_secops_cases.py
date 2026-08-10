#!/usr/bin/env python3
import sys
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

# Close reason values (match SecOps UI dropdown exactly)
CLOSE_REASON = "MAINTENANCE"        # Options: MAINTENANCE, FALSE_POSITIVE, etc.
ROOT_CAUSE   = "Other"              # Matches UI 'Other'
CLOSE_COMMENT = "Clean up activity."

MAX_WORKERS = 8    # Concurrent thread count
BATCH_SIZE  = 25   # Cases sent per parallel chunk
# =============================================================

print_lock = threading.Lock()

def safe_print(msg: str):
    """Thread-safe printing to terminal."""
    with print_lock:
        print(msg)

def get_access_token() -> str:
    """Fetches OAuth2 access token using Application Default Credentials (ADC)."""
    credentials, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    credentials.refresh(Request())
    return credentials.token

def close_single_case(case_id: int, endpoint: str, headers: dict) -> tuple[int, bool, str]:
    """Closes a single case; used as fallback if a batch fails."""
    payload = {
        "casesIds": [case_id],
        "closeReason": CLOSE_REASON,
        "rootCause": ROOT_CAUSE,
        "closeComment": CLOSE_COMMENT
    }
    try:
        response = requests.post(endpoint, json=payload, headers=headers, timeout=15)
        if response.status_code == 200:
            return (case_id, True, "Successfully closed")
        else:
            return (case_id, False, f"HTTP {response.status_code}: {response.text}")
    except Exception as e:
        return (case_id, False, str(e))

def process_batch(batch_ids: list[int], endpoint: str, headers: dict):
    """Sends a batch close request. Falls back to individual processing if batch fails."""
    payload = {
        "casesIds": batch_ids,
        "closeReason": CLOSE_REASON,
        "rootCause": ROOT_CAUSE,
        "closeComment": CLOSE_COMMENT
    }
    try:
        response = requests.post(endpoint, json=payload, headers=headers, timeout=30)
        if response.status_code == 200:
            for cid in batch_ids:
                safe_print(f"  [SUCCESS] Case ID: {cid} -> Closed")
        else:
            safe_print(f"  [WARN] Batch failed ({response.status_code}). Falling back to single-case processing...")
            for cid in batch_ids:
                cid_res, success, msg = close_single_case(cid, endpoint, headers)
                if success:
                    safe_print(f"  [SUCCESS] Case ID: {cid_res} -> Closed")
                else:
                    safe_print(f"  [FAILURE] Case ID: {cid_res} -> Error: {msg}")
    except Exception as e:
        safe_print(f"  [ERROR] Network error on batch ({e}). Retrying individually...")
        for cid in batch_ids:
            cid_res, success, msg = close_single_case(cid, endpoint, headers)
            if success:
                safe_print(f"  [SUCCESS] Case ID: {cid_res} -> Closed")
            else:
                safe_print(f"  [FAILURE] Case ID: {cid_res} -> Error: {msg}")

def main():
    if "YOUR_INSTANCE_ID" in INSTANCE_ID:
        print("Error: Please set PROJECT_ID and INSTANCE_ID at the top of the script.")
        sys.exit(1)

    raw_input = input("Enter Case IDs to close (comma-separated): ").strip()
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
        print("Run 'gcloud auth application-default login' and try again.")
        sys.exit(1)

    endpoint = (
        f"https://{LOCATION}-chronicle.googleapis.com/v1beta/"
        f"projects/{PROJECT_ID}/locations/{LOCATION}/instances/{INSTANCE_ID}/cases:executeBulkClose"
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    chunks = [case_ids[i:i + BATCH_SIZE] for i in range(0, total_cases, BATCH_SIZE)]
    print(f"Processing {total_cases} cases across {len(chunks)} parallel batches using {MAX_WORKERS} threads...\n")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(process_batch, chunk, endpoint, headers)
            for chunk in chunks
        ]
        for future in as_completed(futures):
            future.result()

    print(f"\nFinished processing all {total_cases} cases.")

if __name__ == "__main__":
    main()
