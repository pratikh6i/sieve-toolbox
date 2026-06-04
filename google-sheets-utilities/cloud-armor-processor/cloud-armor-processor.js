/**
 * Cloud Armor Report Processor — Apps Script
 * Processes raw analyzer CSV data into a formatted, email-ready analysis sheet.
 * * HOW TO USE:
 * 1. Open your Google Sheet containing the raw data
 * 2. Go to Extensions > Apps Script
 * 3. Paste this entire code
 * 4. Save, then run "showSheetPicker" from the menu or toolbar
 * 5. Select the raw data sheet and click "Generate Report"
 */

// ─── Menu ───
function onOpen() {
  SpreadsheetApp.getUi()
    .createMenu('🛡️ Armor Analysis')
    .addItem('Generate Analysis Report', 'showSheetPicker')
    .addToUi();
}

// ─── HTML Sheet Picker Dialog ───
function showSheetPicker() {
  var html = HtmlService.createHtmlOutput(getPickerHtml_())
    .setWidth(380)
    .setHeight(220)
    .setTitle('Select Raw Data Sheet');
  SpreadsheetApp.getUi().showModalDialog(html, 'Cloud Armor Report Processor');
}

function getSheetNames() {
  return SpreadsheetApp.getActiveSpreadsheet().getSheets().map(function(s) { return s.getName(); });
}

function getPickerHtml_() {
  return `
  <style>
    body { font-family: 'Google Sans', Arial, sans-serif; padding: 16px; background: #f8f9fa; }
    h3 { margin: 0 0 12px; color: #1a73e8; font-size: 16px; }
    select { width: 100%; padding: 10px; border: 1px solid #dadce0; border-radius: 8px; font-size: 14px; margin-bottom: 16px; }
    button { background: #1a73e8; color: #fff; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; width: 100%; }
    button:hover { background: #1557b0; }
    #status { margin-top: 10px; font-size: 13px; color: #5f6368; text-align: center; }
  </style>
  <h3>🛡️ Select the sheet with raw data</h3>
  <select id="sheetSelect"></select>
  <button onclick="run()">Generate Analysis Report</button>
  <div id="status"></div>
  <script>
    google.script.run.withSuccessHandler(function(names) {
      var sel = document.getElementById('sheetSelect');
      names.forEach(function(n) {
        var opt = document.createElement('option');
        opt.value = n; opt.text = n;
        sel.appendChild(opt);
      });
    }).getSheetNames();
    
    function run() {
      document.getElementById('status').innerText = '⏳ Processing... please wait.';
      document.querySelector('button').disabled = true;
      google.script.run.withSuccessHandler(function(msg) {
        document.getElementById('status').innerText = '✅ ' + msg;
        setTimeout(function() { google.script.host.close(); }, 2000);
      }).withFailureHandler(function(e) {
        document.getElementById('status').innerText = '❌ ' + e.message;
        document.querySelector('button').disabled = false;
      }).processSheet(document.getElementById('sheetSelect').value);
    }
  </script>`;
}

// ═══════════════════════════════════════════════════
// CORE PROCESSOR
// ═══════════════════════════════════════════════════
function processSheet(sheetName) {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var src = ss.getSheetByName(sheetName);
  
  if (!src) throw new Error('Sheet "' + sheetName + '" not found.');
  
  // ── Read all data in one batch ──
  var raw = src.getDataRange().getValues();
  if (raw.length < 2) throw new Error('Sheet has no data rows.');
  
  // ── Column indices (0-based) updated for new data structure ──
  var COL = {
    project: 0, 
    policy: 1, 
    desc: 2, 
    priority: 3,
    sensitivity: 4, 
    action: 5, 
    reqWarn: 6,       // Number of Requests, Warning
    reqInfo: 7,       // Number of Requests, Info
    reqTotal: 8,      // Total Number of Requests
    signature: 9, 
    sigDesc: 10, 
    logLink: 11, 
    integrity: 12
  };

  // ── Step 1: Filter — remove Active rules, API-disabled, and empty rows ──
  var filtered = [];
  for (var i = 1; i < raw.length; i++) {
    var row = raw[i];
    var integ = String(row[COL.integrity] || '');
    var policy = String(row[COL.policy] || '');
    
    // Skip active rules
    if (integ.indexOf('Active rule') > -1) continue;
    // Skip API disabled
    if (integ.indexOf('API') > -1 && integ.indexOf('not enabled') > -1) continue;
    if (integ.indexOf('⏭') > -1) continue;
    // Skip completely empty rows
    if (!policy || policy === '-') continue;
    
    filtered.push(row);
  }
  
  if (filtered.length === 0) throw new Error('No preview rules found after filtering.');

  // ── Step 2: Sort by Project > Policy > Priority for clean grouping ──
  filtered.sort(function(a, b) {
    var c = String(a[COL.project]).localeCompare(String(b[COL.project]));
    if (c !== 0) return c;
    c = String(a[COL.policy]).localeCompare(String(b[COL.policy]));
    if (c !== 0) return c;
    return Number(a[COL.priority]) - Number(b[COL.priority]);
  });

  // ── Step 3: Build output — keep all rows (same priority + different sigs stay separate) ──
  // Output headers updated to 13 columns
  var outHeaders = [
    'Project Name', 'Cloud Armor Policy', 'Rule Description', 'Priority',
    'Sensitivity', 'Action', 'Requests (Warning)', 'Requests (Info)', 'Total Requests',
    'Signature Detected', 'Signature Description', 'Log Link', 'Data Integrity Status'
  ];
  
  var outData = [];
  for (var j = 0; j < filtered.length; j++) {
    var r = filtered[j];
    outData.push([
      r[COL.project], r[COL.policy], r[COL.desc], r[COL.priority],
      r[COL.sensitivity], r[COL.action], r[COL.reqWarn], r[COL.reqInfo], r[COL.reqTotal],
      r[COL.signature], r[COL.sigDesc], r[COL.logLink], r[COL.integrity]
    ]);
  }

  // ── Step 4: Create the Analysis sheet ──
  var today = Utilities.formatDate(new Date(), Session.getScriptTimeZone(), 'dd MMM yyyy');
  var analysisName = 'Analysis | ' + today;
  
  // Delete existing sheet with same name if any
  var existing = ss.getSheetByName(analysisName);
  if (existing) ss.deleteSheet(existing);
  
  var dest = ss.insertSheet(analysisName);

  // ── Step 5: Write all data in one batch ──
  var allRows = [outHeaders].concat(outData);
  dest.getRange(1, 1, allRows.length, outHeaders.length).setValues(allRows);

  // ── Step 6: Apply formatting (all batch operations for speed) ──
  var totalRows = allRows.length;
  var totalCols = outHeaders.length;
  var fullRange = dest.getRange(1, 1, totalRows, totalCols);
  
  // Font: Google Sans for all cells
  fullRange.setFontFamily('Google Sans');
  // Alignment: left-aligned horizontally, center vertically
  fullRange.setHorizontalAlignment('left');
  fullRange.setVerticalAlignment('middle');
  // Row height: 37px for all rows
  dest.setRowHeightsForced(1, totalRows, 37);
  
  // ── Header row: Blue (#0000ff) with white text ──
  var headerRange = dest.getRange(1, 1, 1, totalCols);
  headerRange.setBackground('#0000ff');
  headerRange.setFontColor('#ffffff');
  headerRange.setFontWeight('bold');
  headerRange.setHorizontalAlignment('center');

  // ── Step 7: Conditional highlights (batch-friendly) ──
  var lowHitBg = [];    // backgrounds for low-request rows
  var integrityBg = []; // backgrounds for integrity issues
  var integrityFc = []; // font colors for integrity issues
  var commentsToAdd = [];
  
  for (var r = 0; r < outData.length; r++) {
    var rowIdx = r + 2; // 1-indexed, skip header
    var totalRequests = Number(outData[r][8]) || 0; // Index 8 is now "Total Requests"
    var integrity = String(outData[r][12] || '');   // Index 12 is now "Integrity"
    
    // Low-hit highlight: rows with total requests < 30
    if (totalRequests < 30 && !isNaN(outData[r][8]) && String(outData[r][8]) !== '' && String(outData[r][8]) !== '-') {
      // Build array of backgrounds for this row
      var rowBgs = [];
      for (var c = 0; c < totalCols; c++) rowBgs.push('#d9ead3');
      lowHitBg.push({ row: rowIdx, bgs: rowBgs });
    }
    
    // Data Integrity: flag non-verified
    if (integrity && integrity.indexOf('Verified') === -1) {
      commentsToAdd.push({ row: rowIdx, col: totalCols, text: '⚠️ Data may be incomplete or rate-limited. Verify manually.' });
      integrityBg.push({ row: rowIdx, col: totalCols });
    }
  }
  
  // Apply low-hit highlights
  for (var h = 0; h < lowHitBg.length; h++) {
    dest.getRange(lowHitBg[h].row, 1, 1, totalCols).setBackgrounds([lowHitBg[h].bgs]);
  }
  
  // Apply integrity flags (dark red bg + white text + comment)
  for (var g = 0; g < integrityBg.length; g++) {
    var cell = dest.getRange(integrityBg[g].row, integrityBg[g].col);
    cell.setBackground('#8b0000');
    cell.setFontColor('#ffffff');
    cell.setFontWeight('bold');
  }
  
  for (var n = 0; n < commentsToAdd.length; n++) {
    dest.getRange(commentsToAdd[n].row, commentsToAdd[n].col).setNote(commentsToAdd[n].text);
  }

  // ── Step 8: Merge cells for same Project and same Policy ──
  applyMerges_(dest, outData, totalCols);

  // ── Step 9: Auto-fit column widths ──
  for (var col = 1; col <= totalCols; col++) {
    dest.autoResizeColumn(col);
  }
  
  // Cap max width for very long columns (indices updated for new structure)
  var maxWidths = { 3: 350, 10: 280, 11: 350 }; // desc (3), signature (10), sigDesc (11)
  for (var mCol in maxWidths) {
    if (dest.getColumnWidth(Number(mCol)) > maxWidths[mCol]) {
      dest.setColumnWidth(Number(mCol), maxWidths[mCol]);
    }
  }

  // ── Step 10: Freeze header, activate sheet ──
  dest.setFrozenRows(1);
  ss.setActiveSheet(dest);
  
  return 'Report "' + analysisName + '" created with ' + outData.length + ' rows.';
}

// ═══════════════════════════════════════════════════
// MERGE HELPER — merges Project Name and Policy Name cells
// ═══════════════════════════════════════════════════
function applyMerges_(sheet, data, totalCols) {
  if (data.length === 0) return;
  
  // Merge Column A (Project Name)
  mergeSameValues_(sheet, data, 0, 2);
  
  // Merge Column B (Policy Name) — only within same Project block
  var projectStart = 0;
  for (var i = 1; i <= data.length; i++) {
    if (i === data.length || String(data[i][0]) !== String(data[projectStart][0])) {
      // Within this project block, merge policy names
      mergeSameValuesInRange_(sheet, data, 1, projectStart + 2, i + 1);
      projectStart = i;
    }
  }
}

function mergeSameValues_(sheet, data, colIdx, startRow) {
  var runStart = 0;
  for (var i = 1; i <= data.length; i++) {
    if (i === data.length || String(data[i][colIdx]) !== String(data[runStart][colIdx])) {
      if (i - runStart > 1) {
        sheet.getRange(startRow + runStart, colIdx + 1, i - runStart, 1).merge();
      }
      runStart = i;
    }
  }
}

function mergeSameValuesInRange_(sheet, data, colIdx, sheetStartRow, sheetEndRow) {
  var dataStart = sheetStartRow - 2;
  var dataEnd = sheetEndRow - 2;
  if (dataEnd - dataStart < 2) return;
  
  var runStart = dataStart;
  for (var i = dataStart + 1; i <= dataEnd; i++) {
    if (i === dataEnd || String(data[i][colIdx]) !== String(data[runStart][colIdx])) {
      if (i - runStart > 1) {
        sheet.getRange(runStart + 2, colIdx + 1, i - runStart, 1).merge();
      }
      runStart = i;
    }
  }
}
