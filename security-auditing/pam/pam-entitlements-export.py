import subprocess
import json
import csv
import concurrent.futures
import threading
import sys
import urllib.request
import urllib.error

# --- ANSI Color Codes for Terminal Styling ---
CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
MAGENTA = '\033[95m'
BOLD = '\033[1m'
RESET = '\033[0m'

# Thread locks to prevent terminal output garbling and safely write to CSV
print_lock = threading.Lock()
csv_lock = threading.Lock()

def safe_print(message):
    """Prints to terminal thread-safely."""
    with print_lock:
        print(message, flush=True)

def run_readonly_command(cmd):
    """Executes a basic gcloud command safely."""
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def get_auth_token():
    """Fetches a single Bearer token so we don't have to keep calling gcloud."""
    safe_print(f"{CYAN}[*] Generating GCP Access Token for ultra-fast API calls...{RESET}")
    result = run_readonly_command('gcloud auth print-access-token')
    if result.returncode != 0:
        safe_print(f"{RED}[-] Failed to get access token. Are you logged in?{RESET}")
        sys.exit(1)
    return result.stdout.strip()

def fetch_active_projects(org_id):
    """Fetches all active project IDs, filtering sys- projects."""
    safe_print(f"{CYAN}[*] Fetching accessible projects for Org {BOLD}{org_id}{RESET}{CYAN}...{RESET}")
    
    cmd = 'gcloud projects list --format="value(projectId)" --filter="lifecycleState:ACTIVE" --quiet'
    result = run_readonly_command(cmd)
    
    if result.returncode != 0:
        safe_print(f"{RED}[-] CRITICAL ERROR: Failed to fetch projects.{RESET}")
        sys.exit(1)
        
    raw_projects = result.stdout.split('\n')
    clean_projects = [p.strip() for p in raw_projects if p.strip() and not p.strip().startswith('sys-')]
    
    if not clean_projects:
        safe_print(f"{RED}[-] Error: Command succeeded but returned 0 projects. Check permissions.{RESET}")
        sys.exit(1)
        
    return clean_projects

def process_project_entitlements_rest(project_id, token, csv_writer):
    """Uses raw REST API requests to fetch data 100x faster without choking the CPU."""
    url = f"https://privilegedaccessmanager.googleapis.com/v1/projects/{project_id}/locations/-/entitlements"
    
    req = urllib.request.Request(url)
    req.add_header('Authorization', f'Bearer {token}')
    req.add_header('Accept', 'application/json')
    
    try:
        # 15 second timeout is plenty for a raw HTTP request
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode('utf-8'))
            entitlements = data.get('entitlements', [])
            
    except urllib.error.HTTPError as e:
        # 403 means API is disabled or we don't have permission. Silently skip.
        if e.code == 403 or e.code == 404:
            return 
        safe_print(f"{YELLOW}[!] Project {project_id}: Skipping. HTTP Error {e.code}{RESET}")
        return
    except Exception as e:
        safe_print(f"{YELLOW}[!] Project {project_id}: Skipping. Request failed: {str(e)}{RESET}")
        return

    if not entitlements:
        return # Skip silently to keep terminal output clean

    # Parse the data cleanly
    for ent in entitlements:
        name = ent.get('name', '').split('/')[-1]
        state = ent.get('state', 'UNKNOWN')
        max_duration = ent.get('maxRequestDuration', '')

        # Process Roles & Conditions
        roles = []
        role_bindings = ent.get('privilegedAccess', {}).get('gcpIamAccess', {}).get('roleBindings', [])
        for rb in role_bindings:
            role = rb.get('role', '').replace('roles/', '')
            condition = rb.get('conditionExpression', '')
            role_text = role if not condition else f"{role} (Condition: {condition})"
            roles.append(role_text)
        roles_str = ', '.join(roles)

        # Process Requesters
        requesters = []
        for eu in ent.get('eligibleUsers', []):
            for p in eu.get('principals', []):
                requesters.append(p.replace('user:', '').replace('group:', '').replace('serviceAccount:', ''))
        req_str = ', '.join(requesters)

        # Process Approvers
        approvers = []
        steps = ent.get('approvalWorkflow', {}).get('manualApprovals', {}).get('steps', [])
        for step in steps:
            for app in step.get('approvers', []):
                for p in app.get('principals', []):
                    approvers.append(p.replace('user:', '').replace('group:', '').replace('serviceAccount:', ''))
        app_str = ', '.join(approvers)

        # Process Notifications
        notifications = ent.get('additionalNotificationTargets', {})
        admin_emails = ', '.join(notifications.get('adminEmailRecipients', []))
        req_emails = ', '.join(notifications.get('requesterEmailRecipients', []))
        app_emails = ', '.join(notifications.get('approvalEmailRecipients', []))

        # Write to CSV securely through the thread lock
        with csv_lock:
            csv_writer.writerow([
                project_id, name, state, max_duration, roles_str, req_str, app_str, 
                admin_emails, req_emails, app_emails
            ])

    safe_print(f"{GREEN}[✓]{RESET} Scanned {CYAN}{project_id:<30}{RESET} : {GREEN}{BOLD}{len(entitlements)}{RESET} Entitlements exported!")

def print_banner():
    banner = f"""
{MAGENTA}{BOLD}================================================================={RESET}
{CYAN}  ██▓███   ▄▄▄       ███▄ ▄███▓   ▓█████▒██   ██▒██▓███   ▒█████   ██▀███  ▄▄▄█████▓
 ▓██░  ██▒▒████▄    ▓██▒▀█▀ ██▒   ▓█   ▀▒▒ █ █ ▒░▓██░  ██▒▒██▒  ██▒▓██ ▒ ██▒▓  ██▒ ▓▒
 ▓██░ ██▓▒▒██  ▀█▄  ▓██    ▓██░   ▒███  ░░  █   ░▓██░ ██▓▒▒██░  ██▒▓██ ░▄█ ▒▒ ▓██░ ▒░
 ▒██▄█▓▒ ▒░██▄▄▄▄██ ▒██    ▒██    ▒▓█  ▄ ░ █ █ ▒ ▒██▄█▓▒ ▒▒██   ██░▒██▀▀█▄  ░ ▓██▓ ░ 
 ▒██▒ ░  ░ ▓█   ▓██▒▒██▒   ░██▒   ░▒████▒▒██▒ ▒██▒██▒ ░  ░░ ████▓▒░░██▓ ▒██▒  ▒██▒ ░ 
 ▒▓▒░ ░  ░ ▒▒   ▓▒█░░ ▒░   ░  ░   ░░ ▒░ ░▒▒ ░ ░▓ ▒▓▒░ ░  ░░ ▒░▒░▒░ ░ ▒▓ ░▒▓░  ▒ ░░   
 ░▒ ░       ▒   ▒▒ ░░  ░      ░    ░ ░  ░░░   ░▒ ░▒ ░       ░ ▒ ▒░   ░▒ ░ ▒░    ░    
 ░░         ░   ▒   ░      ░         ░    ░    ░ ░░       ░ ░ ░ ▒    ░░   ░   ░      
                ░  ░       ░         ░  ░ ░    ░              ░ ░     ░              {RESET}
{MAGENTA}{BOLD}================================================================={RESET}
{YELLOW}         ULTRA-FAST REST API MULTI-THREADED EXPORT (v6.0)        {RESET}
{MAGENTA}{BOLD}================================================================={RESET}
    """
    print(banner)

def main():
    print_banner()
    
    while True:
        print(f"\n{CYAN}How would you like to run the scan?{RESET}")
        print(f"  {YELLOW}[1]{RESET} Scan specific Project(s)")
        print(f"  {YELLOW}[2]{RESET} Scan entire Organization")
        choice = input(f"\n{BOLD}Enter 1 or 2: {RESET}").strip()
        
        if choice == '1':
            mode = 'project'
            break
        elif choice == '2':
            mode = 'org'
            break
        else:
            print(f"{RED}⚠ Invalid input. Please strictly enter '1' or '2'.{RESET}")

    projects_to_scan = []

    if mode == 'org':
        org_id = input(f"\n{CYAN}Enter the Organization ID (e.g., 369031569694): {RESET}").strip()
        projects_to_scan = fetch_active_projects(org_id)
        print(f"{GREEN}[*] Found {BOLD}{len(projects_to_scan)}{RESET}{GREEN} real projects. Let's go!{RESET}")

    elif mode == 'project':
        proj_input = input(f"\n{CYAN}Enter Project IDs separated by commas: {RESET}").strip()
        projects_to_scan = [p.strip() for p in proj_input.split(',') if p.strip()]

    # Fetch the token exactly ONE time
    token = get_auth_token()

    output_file = "GCP_PAM_Entitlements.csv"
    headers = [
        "Project ID", "Entitlement Name", "Status", "Max Duration", 
        "Roles & Conditions", "Requester(s)", "Approver(s)", 
        "Admin Notifications", "Requester Notifications", "Approver Notifications"
    ]

    print(f"\n{MAGENTA}[*] Starting REST API multi-threaded scan (50 HTTP threads)...{RESET}")
    print(f"{MAGENTA}[*] Initializing output file: {BOLD}{output_file}{RESET}\n")

    with open(output_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(headers)

        # We can safely push this to 50 because HTTP requests use virtually zero CPU
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(process_project_entitlements_rest, pid, token, writer) for pid in projects_to_scan]
            concurrent.futures.wait(futures)

    print(f"\n{MAGENTA}{BOLD}================================================================={RESET}")
    print(f"{GREEN}{BOLD} [★] DONE! Master report cleanly generated: {output_file}{RESET}")
    print(f"{MAGENTA}{BOLD}================================================================={RESET}\n")

if __name__ == "__main__":
    main() 
