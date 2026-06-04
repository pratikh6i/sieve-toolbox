# Google Sheets Custom SecOps Tools (Apps Script)

## Purpose
This Google Apps Script acts as a custom toolkit within Google Sheets to extract variables from raw JSON outputs, perform batch IP geographic lookups (using `ipinfo.io`), and conduct deep WHOIS and threat intelligence queries (using `RIPEstat` and `AbuseIPDB`).

---

## Target Variables to Change
*   **ipinfo.io API Token**:
    In the `getIpData` function, update:
    ```javascript
    const API_TOKEN = 'YOUR_IPINFO_API_TOKEN';
    ```
*   **AbuseIPDB API Key**:
    In the `getAdvancedKundli` function, update:
    ```javascript
    const ABUSEIPDB_KEY = 'YOUR_ABUSEIPDB_API_KEY';
    ```

---

## Prerequisites
*   A Google Sheet containing raw SCC JSON exports or IP lists.
*   A free API key from **[AbuseIPDB](https://www.abuseipdb.com/)**.
*   A token from **[ipinfo.io](https://ipinfo.io/)**.

---

## Installation & Usage
1. Open your Google Sheet.
2. Click **Extensions** -> **Apps Script**.
3. Copy and paste the contents of `custom-secops-tools.js` into the Apps Script editor.
4. Replace the API token placeholders with your actual keys.
5. Click **Save** and close the Apps Script editor.
6. Refresh the Google Sheet. A new menu named **`Custom Tools`** will appear in the toolbar.
7. Select cells in the sheet and run the desired tool from the menu.
