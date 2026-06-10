/**
 * SCC Pivot Tables Generator — Apps Script
 * Creates custom menus and automates generation of structured pivot tables
 * from Security Command Center (SCC) findings data.
 *
 * HOW TO USE:
 * 1. Open your Google Sheet containing the raw SCC data.
 * 2. Go to Extensions > Apps Script.
 * 3. Create a script file (e.g., scc-pivot-tables.gs) and paste the contents of scc-pivot-tables.js.
 * 4. Create an HTML file in Apps Script called 'dialog.html' and paste the contents of dialog.html.
 * 5. Save the project and refresh your spreadsheet.
 * 6. Run "🛡️ SCC Tools" > "Generate Pivot Tables Summary" from the menu.
 */

/**
 * Creates custom menu item when the Google Sheet opens.
 */
function onOpen() {
  var ui = SpreadsheetApp.getUi();
  ui.createMenu('🛡️ SCC Tools')
    .addItem('Generate Pivot Tables Summary', 'createSccPivotTables')
    .addToUi();
}

/**
 * Main execution entry point. Collects sheet list and presents the HTML UI modal.
 */
function createSccPivotTables() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheets = ss.getSheets();
  
  // Extract all sheet names to pass into the dropdown fields
  var sheetNames = sheets.map(function(sheet) {
    return sheet.getName();
  });
  
  // Store names globally or pass directly to the template evaluation context
  var template = HtmlService.createTemplateFromFile('dialog');
  template.sheetNames = sheetNames;
  
  var htmlOutput = template.evaluate()
      .setWidth(450)
      .setHeight(300)
      .setTitle('🛡️ Data Source Selection');
      
  SpreadsheetApp.getUi().showModalDialog(htmlOutput, 'Select Source Worksheets');
}

/**
 * Core processor triggered remotely by the user from the HTML Dialog view.
 */
function processSheetSelections(allSheetName, filteredSheetName) {
  var ui = SpreadsheetApp.getUi();
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  
  var allSheet = ss.getSheetByName(allSheetName);
  var filteredSheet = ss.getSheetByName(filteredSheetName);
  
  if (!allSheet || !filteredSheet) {
    ui.alert('❌ Selection Error', 'One or both of the target sheets could not be processed.', ui.ButtonSet.OK);
    return;
  }

  // Look up column positions dynamically by matching normalized variants
  var allCategoryCol = findColumnIndex(allSheet, ['findingcategory', 'category']);
  var allSeverityCol = findColumnIndex(allSheet, ['findingseverity', 'severity']);
  var allProjectCol = findColumnIndex(allSheet, ['projectname', 'project']);
  var allParentCol = findColumnIndex(allSheet, ['findingparentdisplayname', 'parentdisplayname']);
  
  var filtCategoryCol = findColumnIndex(filteredSheet, ['findingcategory', 'category']);
  var filtSeverityCol = findColumnIndex(filteredSheet, ['findingseverity', 'severity']);
  var filtProjectCol = findColumnIndex(filteredSheet, ['projectname', 'project']);

  // Missing data column validation checks
  if (!allCategoryCol || !allSeverityCol || !allProjectCol || !allParentCol) {
    ui.alert('❌ Configuration Error', 'Required columns (Category, Severity, Project, or Parent) missing from All Findings sheet.', ui.ButtonSet.OK);
    return;
  }
  if (!filtCategoryCol || !filtSeverityCol || !filtProjectCol) {
    ui.alert('❌ Configuration Error', 'Required columns missing from your Filtered sheet.', ui.ButtonSet.OK);
    return;
  }

  // Set up Source Data Ranges
  var allSourceRange = allSheet.getRange(1, 1, allSheet.getLastRow(), allSheet.getLastColumn());
  var filtSourceRange = filteredSheet.getRange(1, 1, filteredSheet.getLastRow(), filteredSheet.getLastColumn());

  // Create a brand new Summary Destination Sheet
  var destSheetName = "Pivot Summary (" + new Date().toLocaleDateString() + ")";
  var destSheet = ss.getSheetByName(destSheetName);
  if (destSheet) {
    destSheetName = "Pivot Summary " + Math.floor(Date.now() / 1000);
  }
  destSheet = ss.insertSheet(destSheetName);

  // Table 1: Category -> Severity (From All Findings) | Column A
  var pTable1 = destSheet.getRange("A1").createPivotTable(allSourceRange);
  pTable1.addRowGroup(allCategoryCol).showTotals(false);
  pTable1.addRowGroup(allSeverityCol).showTotals(false);
  pTable1.addPivotValue(allCategoryCol, SpreadsheetApp.PivotTableSummarizeFunction.COUNTA);

  // Table 2: Project -> Severity (From All Findings) | Column E
  var pTable2 = destSheet.getRange("E1").createPivotTable(allSourceRange);
  pTable2.addRowGroup(allProjectCol).showTotals(false);
  pTable2.addRowGroup(allSeverityCol).showTotals(false);
  pTable2.addPivotValue(allProjectCol, SpreadsheetApp.PivotTableSummarizeFunction.COUNTA);

  // Table 3: Parent Name -> Severity -> Project Name (From All Findings) | Column I
  var pTable3 = destSheet.getRange("I1").createPivotTable(allSourceRange);
  pTable3.addRowGroup(allParentCol).showTotals(false);
  pTable3.addRowGroup(allSeverityCol).showTotals(false);
  pTable3.addRowGroup(allProjectCol).showTotals(false);
  pTable3.addPivotValue(allCategoryCol, SpreadsheetApp.PivotTableSummarizeFunction.COUNTA);

  // Table 4: Project Name -> Severity -> Category (From Filtered Sheet) | Column N
  var pTable4 = destSheet.getRange("N1").createPivotTable(filtSourceRange);
  pTable4.addRowGroup(filtProjectCol).showTotals(false);
  pTable4.addRowGroup(filtSeverityCol).showTotals(false);
  pTable4.addRowGroup(filtCategoryCol).showTotals(false);
  pTable4.addPivotValue(filtCategoryCol, SpreadsheetApp.PivotTableSummarizeFunction.COUNTA);

  // Automatically adjust columns for ideal readability
  destSheet.autoResizeColumns(1, 20);
  
  ui.alert('🎉 Success', 'All pivot tables successfully generated and spaced side-by-side!', ui.ButtonSet.OK);
}

/**
 * Helper function to match column index using flexible/cleansed target strings
 */
function findColumnIndex(sheet, targetKeys) {
  var headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
  for (var i = 0; i < headers.length; i++) {
    var cleanHeader = headers[i].toString().toLowerCase().replace(/[\s\._\-]/g, '');
    for (var j = 0; j < targetKeys.length; j++) {
      var cleanTarget = targetKeys[j].toLowerCase().replace(/[\s\._\-]/g, '');
      if (cleanHeader === cleanTarget) {
        return i + 1;
      }
    }
  }
  return null;
}
