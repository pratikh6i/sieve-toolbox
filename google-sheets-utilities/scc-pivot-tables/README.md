# SCC Pivot Tables Generator — Google Sheets Apps Script

This utility automates the generation of structured, side-by-side pivot tables inside Google Sheets using Security Command Center (SCC) raw findings data.

It helps security managers and teams quickly analyze finding distributions across **Category**, **Severity**, **Project Name**, and **Parent Display Name** without needing to manually build multiple pivot tables.

## Pivot Tables Generated

The script inserts a new tab (e.g. `Pivot Summary (DD/MM/YYYY)`) and automatically builds four side-by-side pivot tables:
1. **Category vs. Severity** (from all findings source)
2. **Project vs. Severity** (from all findings source)
3. **Parent Name vs. Severity vs. Project** (from all findings source)
4. **Project vs. Severity vs. Category** (from filtered findings source, e.g. excluding OS/Software vulnerabilities)

---

## Prerequisites

1. A Google Sheet containing two tabs:
   - **All Findings**: The raw export of all SCC findings.
   - **Filtered Findings**: A sheet where OS and software vulnerabilities have been filtered out (or other customized filtering).
2. The columns in both sheets should have standard SCC headers. The script dynamically maps columns by searching case-insensitively for variations of:
   - **Category** (e.g. `findingcategory`, `category`)
   - **Severity** (e.g. `findingseverity`, `severity`)
   - **Project Name** (e.g. `projectname`, `project`)
   - **Parent Display Name** (e.g. `findingparentdisplayname`, `parentdisplayname`)

---

## Installation & Setup

1. Open your target Google Sheet.
2. Click on **Extensions** > **Apps Script** in the top menu.
3. In the Apps Script Editor:
   - Rename `Code.gs` (or create a new script file) to `scc-pivot-tables.gs` and paste the contents of [scc-pivot-tables.js](scc-pivot-tables.js).
   - Click the **+** (Add a file) icon next to Files, select **HTML**, name it **`dialog`** (Apps Script will save it as `dialog.html`), and paste the contents of [dialog.html](dialog.html).
4. Save the project by clicking the **Save** floppy disk icon or pressing `Cmd + S` / `Ctrl + S`.
5. Close the Apps Script tab and reload your Google Sheet.

---

## How to Use

1. Once the sheet is reloaded, a custom menu titled **🛡️ SCC Tools** will appear in the toolbar.
2. Select **🛡️ SCC Tools** > **Generate Pivot Tables Summary**.
3. A modal dialog will appear requesting the data sources:
   - **Select ALL FINDINGS Sheet**: Choose the worksheet containing all raw findings.
   - **Select Sheet WITHOUT OS & Software Vul**: Choose the worksheet containing filtered findings.
4. Click **Generate**.
5. Once completed, a confirmation popup will appear and a new tab containing the side-by-side pivot tables will be displayed.
