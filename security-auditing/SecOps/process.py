#!/usr/bin/env python3
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import pandas as pd

# Concurrency Configuration
MAX_WORKERS = 25  # 25 parallel threads for high-speed scanning
MAX_RETRIES = 3


def get_gcloud_access_token():
  """Retrieves OAuth access token from active gcloud session."""
  try:
    token = (
        subprocess.check_output(
            ["gcloud", "auth", "print-access-token"], stderr=subprocess.DEVNULL
        )
        .decode("utf-8")
        .strip()
    )
    return token
  except Exception as e:
    print(f"[ERROR] Failed to get gcloud access token: {e}")
    sys.exit(1)


def extract_clean_scc_paths(product_str):
  """Parses Products string (handling single or semicolon-separated findings),
  cleans all control characters/spaces, and returns normalized lowercase SCC paths.
  """
  if not isinstance(product_str, str) or "GSCC_ORGANIZATIONS/" not in product_str:
    return []

  clean_paths = []
  chunks = product_str.split(";")

  for chunk in chunks:
    chunk = chunk.strip()
    if "GSCC_ORGANIZATIONS/" not in chunk:
      continue

    try:
      suffix = chunk.split("GSCC_ORGANIZATIONS/")[1]
      org_id = suffix.split("/SOURCES/")[0].strip()
      rest   = suffix.split("/SOURCES/")[1].strip()

      if "/FINDINGS/" in rest:
        source_id, finding_part = rest.split("/FINDINGS/")
        source_id  = source_id.strip()
        finding_id = re.sub(r"_(NO_CASE|\d+)$", "", finding_part.strip())
      else:
        m = re.match(r"(\d{15,20})(.*)", rest)
        if m:
          source_id    = m.group(1).strip()
          finding_part = m.group(2).lstrip("/").strip()
          finding_id   = re.sub(r"_(NO_CASE|\d+)$", "", finding_part)
        else:
          source_id  = "UNKNOWN"
          finding_id = rest.strip()

      finding_id = finding_id.split()[0].strip()

      # GCP SCC REST API v1 expects lowercase finding resource paths
      path_lower = f"organizations/{org_id.lower()}/sources/{source_id.lower()}/findings/{finding_id.lower()}"
      clean_paths.append(path_lower)
    except Exception:
      pass

  return clean_paths


def query_scc_finding_worker(finding_path, token):
  """Queries GCP SCC REST API in parallel with auto-retry on 429 rate limits."""
  url = f"https://securitycenter.googleapis.com/v1/{finding_path}"
  headers = {
      "Authorization": f"Bearer {token}",
      "Content-Type": "application/json",
  }

  for attempt in range(1, MAX_RETRIES + 1):
    req = urllib.request.Request(url, headers=headers)
    try:
      with urllib.request.urlopen(req, timeout=10) as response:
        data      = json.loads(response.read().decode("utf-8"))
        scc_state = data.get("state", "UNKNOWN")  # ACTIVE or INACTIVE
        mute_state = data.get("mute", "UNMUTED")
        return (
            finding_path,
            {
                "Exists": True,
                "SCC_State": scc_state,
                "Mute_State": mute_state,
                "Error": None,
            },
        )
    except urllib.error.HTTPError as e:
      if e.code == 404:
        return (
            finding_path,
            {
                "Exists": False,
                "SCC_State": "NOT_FOUND",
                "Mute_State": "UNKNOWN",
                "Error": "Finding path not found in SCC",
            },
        )
      elif e.code == 429:  # Rate limit -> exponential backoff
        time.sleep(1 * attempt)
        continue
      elif e.code == 403:
        return (
            finding_path,
            {
                "Exists": False,
                "SCC_State": "PERMISSION_DENIED",
                "Mute_State": "UNKNOWN",
                "Error": "IAM permission error",
            },
        )
      else:
        return (
            finding_path,
            {
                "Exists": False,
                "SCC_State": f"HTTP_{e.code}",
                "Mute_State": "UNKNOWN",
                "Error": str(e),
            },
        )
    except Exception as e:
      if attempt == MAX_RETRIES:
        return (
            finding_path,
            {
                "Exists": False,
                "SCC_State": "ERROR",
                "Mute_State": "UNKNOWN",
                "Error": str(e),
            },
        )
      time.sleep(0.5)

  return (
      finding_path,
      {
          "Exists": False,
          "SCC_State": "TIMEOUT",
          "Mute_State": "UNKNOWN",
          "Error": "Request timed out",
      },
  )


def main():
  print("=" * 70)
  print(" GCP SecOps vs. SCC Reconciliation Scanner (High Performance) ")
  print("=" * 70)

  csv_file = input("\nEnter SecOps export CSV filename: ").strip()

  if not os.path.exists(csv_file):
    print(f"[ERROR] File '{csv_file}' not found.")
    sys.exit(1)

  start_time = time.time()

  # Step 1: Read CSV with Pipe '|' Delimiter
  print(f"\n[1/4] Reading '{csv_file}' using pipe '|' delimiter...")
  df = pd.read_csv(csv_file, sep="|")
  df.columns = df.columns.str.strip()

  case_mappings    = []
  all_unique_paths = set()

  for idx, row in df.iterrows():
    case_id      = row["Name"]
    display_name = row["Display Name"]
    priority     = row["Priority"]
    status       = row["Status"]
    prod_str     = str(row.get("Products", ""))

    clean_paths = extract_clean_scc_paths(prod_str)
    all_unique_paths.update(clean_paths)

    case_mappings.append({
        "Case_ID": case_id,
        "Display_Name": display_name,
        "Priority": priority,
        "SecOps_Status": status,
        "SCC_Finding_Paths": clean_paths,
        "Path_Count": len(clean_paths),
    })

  mapping_df        = pd.DataFrame(case_mappings)
  unique_paths_list = sorted(list(all_unique_paths))

  print(f" -> Successfully loaded {len(mapping_df)} SecOps cases.")
  print(f" -> Extracted {len(unique_paths_list)} unique, clean SCC finding paths.")

  # Step 2: Get Auth Token
  print("\n[2/4] Authenticating with GCP...")
  token = get_gcloud_access_token()

  # Step 3: Multi-Threaded Parallel Execution
  print(f"\n[3/4] Launching {MAX_WORKERS} parallel threads to query GCP SCC API...")
  finding_results = {}
  completed = 0

  with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    future_to_path = {
        executor.submit(query_scc_finding_worker, path, token): path
        for path in unique_paths_list
    }

    for future in as_completed(future_to_path):
      path, result = future.result()
      finding_results[path] = result
      completed += 1

      percent = (completed / len(unique_paths_list)) * 100
      sys.stdout.write(
          f"\r -> Scanning Progress: [{completed}/{len(unique_paths_list)}]"
          f" ({percent:.1f}%)"
      )
      sys.stdout.flush()

  print("\n -> Parallel scan complete!")

  # Save Unique Findings Lookup
  finding_summary = []
  for path in unique_paths_list:
    res = finding_results[path]
    finding_summary.append({
        "SCC_Finding_Path": path,
        "Finding_Exists_In_SCC": res["Exists"],
        "SCC_Current_State": res["SCC_State"],
        "SCC_Mute_State": res["Mute_State"],
        "Error_Details": res["Error"],
    })
  pd.DataFrame(finding_summary).to_csv(
      "scc_unique_findings_lookup.csv", index=False
  )

  # Step 4: Map Back to Cases & Determine Case Closure Recommendations
  print("\n[4/4] Mapping results to cases & generating final report...")
  case_final_report = []

  for idx, row in mapping_df.iterrows():
    case_id = row["Case_ID"]
    paths   = row["SCC_Finding_Paths"]

    if not paths:
      recommendation      = "KEEP_OPEN_IN_SECOPS"
      reason              = "No valid SCC finding paths could be parsed"
      scc_states_summary  = "MISSING_PATH"
      all_exists          = False
    else:
      lookups = [
          finding_results.get(
              p,
              {"Exists": False, "SCC_State": "UNKNOWN", "Mute_State": "UNKNOWN"},
          )
          for p in paths
      ]
      states             = [l["SCC_State"] for l in lookups]
      all_exists         = all(l["Exists"] for l in lookups)
      scc_states_summary = ",".join(set(states))

      has_active    = "ACTIVE" in states
      has_not_found = "NOT_FOUND" in states or not all_exists
      all_inactive  = all(l["Exists"] and l["SCC_State"] == "INACTIVE" for l in lookups)

      # Decision Rules:
      # CLOSE case ONLY if ALL associated findings exist in SCC AND ALL are INACTIVE.
      if all_inactive:
        recommendation = "CLOSE_SECOPS_CASE"
        reason = f"All {len(paths)} associated finding(s) are INACTIVE in GCP SCC (remediated/resolved)"
      elif has_active:
        recommendation = "KEEP_OPEN_IN_SECOPS"
        reason = "Case has ACTIVE finding(s) in GCP SCC"
      elif has_not_found:
        recommendation = "KEEP_OPEN_IN_SECOPS"
        reason = "Case has finding(s) not found in GCP SCC"
      else:
        recommendation = "KEEP_OPEN_IN_SECOPS"
        reason = f"Finding state(s) in SCC: {scc_states_summary}"

    case_final_report.append({
        "Case_ID": case_id,
        "SecOps_Status": row["SecOps_Status"],
        "Priority": row["Priority"],
        "Display_Name": row["Display_Name"],
        "Finding_Count": len(paths),
        "SCC_Finding_Paths": ";".join(paths),
        "All_Findings_Exist_In_SCC": all_exists,
        "SCC_States_Summary": scc_states_summary,
        "Case_Action_Recommendation": recommendation,
        "Reason": reason,
    })

  final_df = pd.DataFrame(case_final_report)
  final_df.to_csv("secops_case_reconciliation_report.csv", index=False)

  elapsed = time.time() - start_time

  print("\n" + "=" * 70)
  print(f" RECONCILIATION SUMMARY (Completed in {elapsed:.2f} seconds) ")
  print("=" * 70)
  print(final_df["Case_Action_Recommendation"].value_counts().to_string())
  print("\nFiles Generated:")
  print(" 1. scc_unique_findings_lookup.csv (Finding-level status lookup)")
  print(" 2. secops_case_reconciliation_report.csv (Final case decisions)")
  print("=" * 70)


if __name__ == "__main__":
  main()
