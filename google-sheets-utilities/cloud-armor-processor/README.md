# Cloud Armor Report Processor Component

This component provides a Google Apps Script designed to process raw Cloud Armor preview rule CSV logs in Google Sheets into a beautifully formatted, group-merged, and color-coded executive analysis sheet.

## Tools Overview

### 1. [cloud-armor-processor.js](cloud-armor-processor.js)
A Google Apps Script macro that filters out active rules, empty rows, and disabled API messages, sorts rows logically by project/policy/priority, formats headers with a standard corporate layout, applies low-traffic highlights (green row backgrounds for total requests < 30), flags data integrity/rate-limit warnings (red cell highlight with notes), and merges duplicate cells in logical columns for readability.

---

## Cloud Armor Report Processor (`cloud-armor-processor.js`)

### Purpose
- Streamline raw WAF/Cloud Armor preview rules audit exports into client/board-ready reports.
- Filter out active/non-preview rules to focus purely on policy review candidates.
- Automatically highlight candidate rules that can be safely promoted (low requests count) vs rules requiring troubleshooting (rate-limit integrity warnings).

### Target Variables
- **Column Configurations**: Assumes the sheet contains the standard 13-column output format from Cloud Armor audit tool runs:
  - Column 0: Project
  - Column 1: Policy
  - Column 2: Description
  - Column 3: Priority
  - Column 4: Sensitivity
  - Column 5: Action
  - Column 6: Requests (Warning)
  - Column 7: Requests (Info)
  - Column 8: Total Requests
  - Column 9: Signature
  - Column 10: Signature Description
  - Column 11: Log Link
  - Column 12: Integrity Status

### Prerequisites
- Open the Google Sheet where raw Cloud Armor CSV outputs were imported.

### Usage
1. In your Google Sheet, select **Extensions** > **Apps Script**.
2. Replace any existing contents in the script editor with the full contents of `cloud-armor-processor.js`.
3. Save the script (Ctrl+S or Cmd+S) and refresh your Google Sheet.
4. A new custom menu **🛡️ Armor Analysis** will appear. Click **Generate Analysis Report**.
5. Select the sheet containing your raw data in the popup modal and click **Generate Analysis Report**.
6. A formatted sheet named `Analysis | DD MMM YYYY` will be added to the spreadsheet automatically.
