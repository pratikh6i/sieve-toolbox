import requests
from bs4 import BeautifulSoup
import time
import csv
import random

# --- CONFIGURATION ---
INPUT_FILE = 'ips.txt'      # File with one IP address per line
OUTPUT_FILE = 'blacklist_results.csv' # Output file for the results
# --- END CONFIGURATION ---

def get_blacklist_count(ip_address):
    """
    Scrapes MX Toolbox for the blacklist count of a given IP address.

    Args:
        ip_address (str): The IP address to check.

    Returns:
        tuple: A tuple containing (status_string, list_count).
               e.g., ("OK", 0) or ("LISTED", 5)
               Returns (None, None) on failure.
    """
    url = f"https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{ip_address}"
    
    # Using a realistic user-agent can help avoid being blocked.
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        print(f"Checking IP: {ip_address}...")
        response = requests.get(url, headers=headers, timeout=20)
        response.raise_for_status()  # Raises an exception for bad status codes (4xx or 5xx)

        soup = BeautifulSoup(response.text, 'html.parser')

        # Find the summary result element. This is the most crucial part.
        # We look for a <td> tag with the class 'tool-result-body' which contains the summary.
        result_summary_element = soup.find('td', class_='tool-result-body')

        if not result_summary_element:
            print(f"  -> Could not find the result summary element for {ip_address}. The page structure might have changed.")
            return "Error: Page structure changed?", -1

        # The summary text is usually in a <div> inside this <td>
        summary_text = result_summary_element.get_text(strip=True)

        if "OK" in summary_text or "not listed" in summary_text:
            return "Clean", 0
        
        # Look for the pattern "Listed on X of Y blacklists"
        if "Listed on" in summary_text:
            try:
                # Extract the number of lists it's on
                parts = summary_text.split()
                # Find the number that comes after "on"
                count_index = parts.index("on") + 1
                count = int(parts[count_index])
                return f"Listed in {count} blacklists", count
            except (ValueError, IndexError) as e:
                print(f"  -> Could not parse the count from summary text: '{summary_text}'. Error: {e}")
                return "Error: Could not parse count", -1

        # Fallback if the text is unexpected
        return f"Unknown Status: {summary_text}", -1

    except requests.exceptions.HTTPError as e:
        print(f"  -> HTTP Error for {ip_address}: {e}")
        return f"Error: HTTP {e.response.status_code}", -1
    except requests.exceptions.RequestException as e:
        print(f"  -> A network error occurred for {ip_address}: {e}")
        return "Error: Network issue", -1
    except Exception as e:
        print(f"  -> An unexpected error occurred for {ip_address}: {e}")
        return "Error: Unexpected", -1


def main():
    """
    Main function to read IPs, process them, and write to a CSV.
    """
    try:
        with open(INPUT_FILE, 'r') as f:
            # Read IPs and strip any whitespace
            ips_to_check = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Input file '{INPUT_FILE}' not found.")
        print("Please create it and add one IP address per line.")
        return

    if not ips_to_check:
        print(f"Error: No IP addresses found in '{INPUT_FILE}'.")
        return

    print(f"Found {len(ips_to_check)} IPs to check. Starting process...")

    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        # Write the header row
        writer.writerow(['IP Address', 'Status', 'Blacklist Count'])

        for ip in ips_to_check:
            status, count = get_blacklist_count(ip)
            
            # Write the result for the current IP
            writer.writerow([ip, status, count])

            # Be a good web citizen: wait a random amount of time between requests
            # to avoid overwhelming the server.
            sleep_time = random.uniform(1.5, 3.5)
            print(f"  -> Waiting for {sleep_time:.2f} seconds...")
            time.sleep(sleep_time)

    print("\n--------------------------------------------------")
    print(f"Processing complete! Results saved to '{OUTPUT_FILE}'.")
    print("--------------------------------------------------")


if __name__ == "__main__":
    main()
