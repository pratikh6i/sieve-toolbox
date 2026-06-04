# GCP Log Link Opener for Cloud Armor

## Purpose
This utility automates opening multiple Google Cloud Console log and dashboard links for Cloud Armor analysis within a designated time window. The script converts local Indian Standard Time (IST) inputs to UTC, injects these times into the URL templates defined in `links-template.json`, and opens the links in your work Chrome browser window.

## Target Variables to Change
*   **In `links-template.json`**: Replace the following placeholders with your actual GCP configuration details:
    *   `YOUR_HOST_VPC_PROJECT_ID`: The project ID of your Host VPC (e.g., `inf-nw-ngfw-hostvpc-040823`).
    *   `YOUR_OBSERVABILITY_PROJECT_ID`: The project ID containing your observability bucket (e.g., `inf-obsr-sre-040823`).
    *   `YOUR_POLICY_NAME`: The Cloud Armor security policy name (e.g., `aeldm-prod-common-cloud-armor-policy-01`).
    *   `YOUR_ARMOR_LOG_SINK_BUCKET`: The destination logging bucket name.
*   **In `open-gcp-log-links.py`**:
    *   `CHROME_BROWSER_PATH`: Browser executable alias/path. Set to `'chrome'` by default. If on macOS, you can set it to `'open -a "/Applications/Google Chrome.app" %s'` if the shorthand isn't recognized.

## Prerequisites
*   **Environment**: Python 3.x installed.
*   **Browser**: Google Chrome installed and running with your active GCP work profile window selected.
*   **Network Access**: Authenticated access to the relevant GCP consoles.

## Usage
1. Make sure your target Google Chrome profile is active on your desktop.
2. Run the script:
   ```bash
   python3 open-gcp-log-links.py
   ```
3. Enter the start/end dates and times in `YYYY-MM-DD` and `HH:MM` formats when prompted.
