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
MAX_WORKERS = 25  # Number of parallel threads for SCC API calls
MAX_RETRIES = 3   # Retry attempts for network glitches or rate limits


def get_gcloud_access_token():
  """Retrieves OAuth access token from active gcloud authorization session."""
  try:
    token = (
        subprocess.check_output(
            ['gcloud', 'auth', 'print-access-token'], stderr=subprocess.DEVNULL
        )
        .decode('utf-8')
        .strip()
    )
    return token
  except Exception as e:
    print(f'[ERROR] Failed to get gcloud access token: {e}')
    print(
        "Please run 'gcloud auth login' or 'gcloud auth application-default"
        " login' first."
    )
    sys.exit(1)


def extract_scc_path(product_str):
  """Parses Products field to construct standard SCC finding resource path:
  organizations/<ORG_ID>/sources/<SOURCE_ID>/findings/<FINDING_ID>
  """
  if not isinstance(product_str, str) or 'GSCC_ORGANIZATIONS/' not in product_str:
    return None

  try:
    suffix = product_str.split('GSCC_ORGANIZATIONS/')[1]
    org_id = suffix.split('/SOURCES/')[0]
    rest = suffix.split('/SOURCES/')[1]

    if '/FINDINGS/' in rest:
      source_id, finding_part = rest.split('/FINDINGS/')
      finding_id = re.sub(r'_(NO_CASE|\d+)$', '', finding_part)
    else:
      m = re.match(r'(\d{15,20})(.*)', rest)
      if m:
        source_id = m.group(1)
        finding_id = re.sub(r'_(NO_CASE|\d+)$', '', m.group(2).lstrip('/'))
      else:
        source_id = 'UNKNOWN'
        finding_id = rest

    return f'organizations/{org_id}/sources/{source_id}/findings/{finding_id}'
  except Exception:
    return None


def query_scc_finding_worker(finding_path, token):
  """Worker function executed in parallel threads to query GCP SCC REST API with auto-retry."""
  url = f'https://securitycenter.googleapis.com/v1/{finding_path}'
  headers = {
      'Authorization': f'Bearer {token}',
      'Content-Type': 'application/json',
  }

  for attempt in range(1, MAX_RETRIES + 1):
    req = urllib.request.Request(url, headers=headers)
    try:
      with urllib.request.urlopen(req, timeout=10) as response:
        data = json.loads(response.read().decode('utf-8'))
        scc_state = data.get('state', 'UNKNOWN')  # ACTIVE or INACTIVE
        mute_state = data.get('mute', 'UNMUTED')
        return (
            finding_path,
            {
                'Exists': True,
                'SCC_State': scc_state,
                'Mute_State': mute_state,
                'Error': None,
            },
        )
    except urllib.error.HTTPError as e:
      if e.code == 404:
        return (
            finding_path,
            {
                'Exists': False,
                'SCC_State': 'NOT_FOUND',
                'Mute_State': 'UNKNOWN',
                'Error': 'Finding path not found in SCC',
            },
        )
      elif e.code == 429:  # Rate limited -> Exponential backoff retry
        time.sleep(1 * attempt)
        continue
      elif e.code == 403:
        return (
            finding_path,
            {
                'Exists': False,
                'SCC_State': 'PERMISSION_DENIED',
                'Mute_State': 'UNKNOWN',
                'Error': 'IAM permission error',
            },
        )
      else:
        return (
            finding_path,
            {
                'Exists': False,
                'SCC_State': f'HTTP_{e.code}',
                'Mute_State': 'UNKNOWN',
                'Error': str(e),
            },
        )
    except Exception as e:
      if attempt == MAX_RETRIES:
        return (
            finding_path,
            {
                'Exists': False,
                'SCC_State': 'ERROR',
                'Mute_State': 'UNKNOWN',
                'Error': str(e),
            },
        )
      time.sleep(0.5)

  return (
      finding_path,
      {
          'Exists': False,
          'SCC_State': 'TIMEOUT',
          'Mute_State': 'UNKNOWN',
          'Error': 'Request timed out after retries',
      },
  )


def main():
  print('=' * 70)
  print(' High-Speed Parallel GCP SecOps vs. SCC Case Reconciliation System ')
  print('=' * 70)

  input_csv = input(
      '\nEnter the path/filename of exported SecOps cases CSV: '
  ).strip()

  if not os.path.exists(input_csv):
    print(f"[ERROR] File '{input_csv}' not found. Please check the filename.")
    sys.exit(1)

  start_time = time.time()

  # Step 1: Load and Parse CSV
  print(f"\n[1/4] Loading and parsing '{input_csv}'...")
  df = pd.read_csv(input_csv, sep='|')
  df.columns = df.columns.str.strip()

  case_mappings = []
  for idx, row in df.iterrows():
    case_id      = row['Name']
    display_name = row['Display Name']
    priority     = row['Priority']
    status       = row['Status']
    prod_str     = str(row.get('Products', ''))

    scc_path = extract_scc_path(prod_str)

    case_mappings.append({
        'Case_ID': case_id,
        'Display_Name': display_name,
        'Priority': priority,
        'SecOps_Status': status,
        'SCC_Finding_Path': scc_path,
    })

  mapping_df = pd.DataFrame(case_mappings)
  unique_finding_paths = (
      mapping_df['SCC_Finding_Path'].dropna().unique().tolist()
  )

  print(f' -> Loaded {len(mapping_df)} SecOps cases.')
  print(f' -> Extracted {len(unique_finding_paths)} unique SCC finding paths.')

  # Step 2: Authenticate
  print('\n[2/4] Authenticating with GCP...')
  token = get_gcloud_access_token()

  # Step 3: Multi-Threaded Parallel Execution
  print(
      f'\n[3/4] Launching {MAX_WORKERS} parallel threads to scan GCP'
      ' SCC API...'
  )
  finding_results = {}
  completed_count = 0

  with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    future_to_path = {
        executor.submit(query_scc_finding_worker, path, token): path
        for path in unique_finding_paths
    }

    for future in as_completed(future_to_path):
      path, result = future.result()
      finding_results[path] = result
      completed_count += 1

      percent = (completed_count / len(unique_finding_paths)) * 100
      sys.stdout.write(
          f"\r -> Scanning Progress: [{completed_count}/{len(unique_finding_paths)}] ({percent:.1f}%)"
      )
      sys.stdout.flush()

  print('\n -> Parallel scan complete!')

  # Export unique finding summary
  finding_summary = []
  for path, res in finding_results.items():
    finding_summary.append({
        'SCC_Finding_Path': path,
        'Finding_Exists_In_SCC': res['Exists'],
        'SCC_Current_State': res['SCC_State'],
        'SCC_Mute_State': res['Mute_State'],
        'Error_Details': res['Error'],
    })
  pd.DataFrame(finding_summary).to_csv(
      'scc_unique_findings_lookup.csv', index=False
  )

  # Step 4: Map Back to Cases & Apply Rules
  print('\n[4/4] Mapping results back to cases & generating final report...')
  case_final_report = []

  for idx, row in mapping_df.iterrows():
    case_id = row['Case_ID']
    path    = row['SCC_Finding_Path']

    if pd.isna(path):
      scc_state       = 'INVALID_OR_MISSING_PATH'
      exists          = False
      mute            = 'UNKNOWN'
      recommendation  = 'KEEP_OPEN_IN_SECOPS'
      closure_reason  = 'Finding path could not be parsed from case'
    else:
      lookup = finding_results.get(
          path,
          {
              'Exists': False,
              'SCC_State': 'UNKNOWN',
              'Mute_State': 'UNKNOWN',
              'Error': 'Not queried',
          },
      )
      scc_state = lookup['SCC_State']
      exists    = lookup['Exists']
      mute      = lookup['Mute_State']

      # Rule: Close ONLY if finding exists AND state is INACTIVE.
      if exists and scc_state == 'INACTIVE':
        recommendation = 'CLOSE_SECOPS_CASE'
        closure_reason = 'Finding is INACTIVE in GCP SCC (remediated/resolved)'
      elif exists and scc_state == 'ACTIVE':
        recommendation = 'KEEP_OPEN_IN_SECOPS'
        closure_reason = 'Finding is currently ACTIVE in GCP SCC'
      else:
        recommendation = 'KEEP_OPEN_IN_SECOPS'
        closure_reason = f"Finding state in SCC is '{scc_state}' (Not present or active)"

    case_final_report.append({
        'Case_ID': case_id,
        'SecOps_Status': row['SecOps_Status'],
        'Priority': row['Priority'],
        'Display_Name': row['Display_Name'],
        'SCC_Finding_Path': path,
        'Finding_Exists_In_SCC': exists,
        'SCC_Current_State': scc_state,
        'SCC_Mute_State': mute,
        'Case_Action_Recommendation': recommendation,
        'Reason': closure_reason,
    })

  final_df = pd.DataFrame(case_final_report)
  final_df.to_csv('secops_case_reconciliation_report.csv', index=False)

  elapsed = time.time() - start_time

  print('\n' + '=' * 70)
  print(f' RECONCILIATION SUMMARY (Completed in {elapsed:.2f} seconds) ')
  print('=' * 70)
  print(final_df['Case_Action_Recommendation'].value_counts().to_string())
  print('\nReports Generated:')
  print(' 1. scc_unique_findings_lookup.csv')
  print(' 2. secops_case_reconciliation_report.csv')
  print('=' * 70)


if __name__ == '__main__':
  main()
