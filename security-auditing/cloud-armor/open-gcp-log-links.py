import json
import webbrowser
import time # Optional for delays
from datetime import datetime, timedelta, timezone


# --- Configuration ---
JSON_TEMPLATE_FILE = 'links-template.json'
CHROME_BROWSER_PATH = 'chrome' # Use 'chrome', 'google-chrome', or the full path if needed
# Example for Windows if not in PATH: 'C:/Program Files/Google/Chrome/Application/chrome.exe %s'
# Example for macOS: 'open -a /Applications/Google\ Chrome.app %s'
# Example for Linux: '/usr/bin/google-chrome %s'


# Define IST timezone offset (UTC+5:30)
IST_OFFSET = timedelta(hours=5, minutes=30)


# --- Functions ---


def get_user_datetime_ist(prompt_date, prompt_time):
   """Gets date and time input from user in IST, returns UTC datetime object."""
   while True:
       try:
           date_str = input(f"{prompt_date} (YYYY-MM-DD): ")
           time_str = input(f"{prompt_time} (HH:MM, 24-hour format): ")
          
           # Parse local IST time
           local_dt_str = f"{date_str} {time_str}"
           local_dt = datetime.strptime(local_dt_str, "%Y-%m-%d %H:%M")
          
           # Convert IST to UTC (subtract offset)
           utc_dt = local_dt - IST_OFFSET
           print(f"  > Converted IST {local_dt.strftime('%Y-%m-%d %H:%M')} to UTC {utc_dt.strftime('%Y-%m-%d %H:%M:%S')}")
           return utc_dt
       except ValueError:
           print("❌ Invalid date/time format. Please use YYYY-MM-DD and HH:MM (e.g., 14:30 for 2:30 PM).")


def format_utc_for_url(dt):
   """Formats a datetime object into the required GCP URL string format."""
   # Format: YYYY-MM-DDTHH:MM:SS.000Z
   return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def open_tab(url):
   """Opens the given URL in a new Chrome tab."""
   try:
       # Get the Chrome browser controller
       # Use .get(CHROME_BROWSER_PATH) to try and specify Chrome
       # If CHROME_BROWSER_PATH isn't found, webbrowser might try default
       controller = webbrowser.get(CHROME_BROWSER_PATH)
       controller.open_new_tab(url)
       # print(f"  Opening: {url[:100]}...") # Optional: print truncated URL
   except webbrowser.Error as e:
       print(f"❌ Error opening browser: {e}")
       print("   Trying default browser instead...")
       try:
           webbrowser.open_new_tab(url) # Fallback to default
       except webbrowser.Error as e2:
           print(f"❌ Failed to open URL with default browser either: {e2}")
           print("   Please check your browser setup.")




# --- Main Script ---


print("--- Google Cloud Link Opener ---")
print("Please provide the time range for the links (in Indian Standard Time - IST).")


# Get user input for the overall time range
start_dt_utc = get_user_datetime_ist("Enter START Date", "Enter START Time")
end_dt_utc = get_user_datetime_ist("Enter END Date", "Enter END Time")


# Validate that end time is after start time
if end_dt_utc <= start_dt_utc:
   print("❌ Error: End date/time must be after start date/time.")
   exit()


# Format the times for URL insertion
formatted_start_utc = format_utc_for_url(start_dt_utc)
formatted_end_utc = format_utc_for_url(end_dt_utc)


print(f"\nTime range set (UTC for URLs):")
print(f"  Start: {formatted_start_utc}")
print(f"  End:   {formatted_end_utc}")


# Load the link templates from the JSON file
try:
   with open(JSON_TEMPLATE_FILE, 'r') as f:
       link_data = json.load(f)
except FileNotFoundError:
   print(f"❌ Error: Cannot find the template file '{JSON_TEMPLATE_FILE}'. Make sure it's in the same directory.")
   exit()
except json.JSONDecodeError:
   print(f"❌ Error: Could not decode '{JSON_TEMPLATE_FILE}'. Ensure it's valid JSON.")
   exit()
except Exception as e:
   print(f"❌ An unexpected error occurred loading the JSON: {e}")
   exit()
  
print(f"\nFound {len(link_data)} groups in '{JSON_TEMPLATE_FILE}'.")
print("Starting to open links...")


# Iterate through groups and links
for group in link_data:
   group_name = group.get('group_name', 'Unnamed Group')
   links = group.get('links', [])
  
   print(f"\n--- Processing Group: {group_name} ---")
  
   if not links:
       print("  No links found in this group.")
       continue


   for i, template_url in enumerate(links):
       modified_url = template_url # Start with the template


       # Check if placeholders exist before attempting format
       needs_formatting = "{START_TIME}" in template_url or "{END_TIME}" in template_url


       if needs_formatting:
           try:
               # Use .format() to insert the times into the placeholders
               modified_url = template_url.format(
                   START_TIME=formatted_start_utc,
                   END_TIME=formatted_end_utc
               )
               print(f"  ({i+1}/{len(links)}) Opening (time modified): {group_name} link")
           except KeyError as e:
               # This should ideally not happen if JSON is correct, but good to handle
               print(f"  ⚠️ ({i+1}/{len(links)}) Warning: Placeholder {e} not found in URL template. Opening as is.")
               print(f"     URL: {template_url[:100]}...")
               modified_url = template_url # Revert to template if format fails
       else:
            print(f"  ({i+1}/{len(links)}) Opening (no time params): {group_name} link")


       open_tab(modified_url)
      
       # Optional small delay between tabs
       # time.sleep(0.5)


   # Open a blank tab after processing all links in the group for separation
   print(f"--- Finished Group: {group_name}. Opening separator tab. ---")
   open_tab('about:blank')
   # Optional longer delay between groups
   # time.sleep(2)


print("\n✅ All groups processed and links opened!")
