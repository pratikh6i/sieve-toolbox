# Cloud Armor Security Automations

This folder contains scripts and utilities to manage, analyze, and configure Google Cloud Armor security policies.

---

## 1. Cloud Armor Adaptive Protection Enablement

### Purpose
This script automates enabling Adaptive Protection (Layer 7 DDoS Defense) across all Cloud Armor security policies in a specified GCP project. It scans for existing policies, checks if Adaptive Protection is active, and enables it if it is currently disabled.

### Target Variables to Change
None. The script prompts interactively for:
*   `Google Cloud Project ID`

### Prerequisites
*   **CLI Tools**: `gcloud` SDK installed and authenticated.
*   **IAM Roles**: `Compute Security Admin` or `Compute Admin` role on the target project.

### Usage
```bash
chmod +x enable-adaptive-protection.sh && ./enable-adaptive-protection.sh
```

---

## 2. GCP Log Link Opener for Cloud Armor

### Purpose
This utility automates opening multiple Google Cloud Console log and dashboard links for Cloud Armor analysis within a designated time window. The script converts local Indian Standard Time (IST) inputs to UTC, injects these times into the URL templates defined in `links-template.json`, and opens the links in your work Chrome browser window.

### Target Variables to Change
*   **In `links-template.json`**: Replace the following placeholders with your actual GCP configuration details:
    *   `YOUR_HOST_VPC_PROJECT_ID`: The project ID of your Host VPC (e.g., `inf-nw-ngfw-hostvpc-040823`).
    *   `YOUR_OBSERVABILITY_PROJECT_ID`: The project ID containing your observability bucket (e.g., `inf-obsr-sre-040823`).
    *   `YOUR_POLICY_NAME`: The Cloud Armor security policy name (e.g., `aeldm-prod-common-cloud-armor-policy-01`).
    *   `YOUR_ARMOR_LOG_SINK_BUCKET`: The destination logging bucket name.
*   **In `open-gcp-log-links.py`**:
    *   `CHROME_BROWSER_PATH`: Browser executable alias/path. Set to `'chrome'` by default.

### Prerequisites
*   **Environment**: Python 3.x installed.
*   **Browser**: Google Chrome installed and running with your active GCP work profile window selected.
*   **Network Access**: Authenticated access to the relevant GCP consoles.

### Usage
```bash
python3 open-gcp-log-links.py
```
