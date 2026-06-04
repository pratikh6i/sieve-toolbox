# Security Report Slides Synchronization (Apps Script)

## Purpose
This Google Apps Script parses project-level vulnerability data in a Google Sheet pivot table, generates structured summary tables and 3D pie charts in a new "Project Reports" sheet, and automatically exports these tables and charts to a Google Slides presentation for monthly reporting.

---

## Target Variables to Change
*   **Google Slides Presentation ID**:
    In the first line of the script, update:
    ```javascript
    var PRESENTATION_ID = "YOUR_PRESENTATION_ID";
    ```
*   **Production Project List**:
    If your production projects change, update the `targetProjects` array inside the `generateProjectReports()` function:
    ```javascript
    var targetProjects = [
      "awr-enable-prod",
      "awr-infosec-prod",
      ...
    ];
    ```

---

## Prerequisites
*   A Google Sheet containing your Cloud Armor or SCC Pivot Table data in columns D, E, and F (Project, Finding Category, Count).
*   A Google Slides Presentation to which the reports will be appended.
*   Google Drive and Google Slides edit permissions for the executing account.

---

## Installation & Usage
1. Open your Google Sheet.
2. Click **Extensions** -> **Apps Script**.
3. Copy and paste the contents of `sync-reports-to-slides.js` into the Apps Script editor.
4. Replace `YOUR_PRESENTATION_ID` with the ID of your target Google Slides presentation (copied from its URL: `https://docs.google.com/presentation/d/PRESENTATION_ID/edit`).
5. Save the project and close the editor.
6. Refresh the Google Sheet. A new menu named **`Security Ops Tools`** will appear in the toolbar.
7. Click **`1. Generate Tables & Charts`** to parse the pivot table and generate formatted summaries and charts in the sheet.
8. Click **`2. Sync Reports to Slides`** to automatically append slides for each production project with the data table and chart.
