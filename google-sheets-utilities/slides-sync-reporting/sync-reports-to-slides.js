// --- CONFIGURATION ---
// Replace with your Google Slides Presentation ID (taken from your URL)
var PRESENTATION_ID = "YOUR_PRESENTATION_ID";

function onOpen() {
  SpreadsheetApp.getUi()
    .createMenu('Security Ops Tools')
    .addItem('1. Generate Tables & Charts', 'generateProjectReports')
    .addItem('2. Sync Reports to Slides', 'syncToSlides')
    .addToUi();
}

// =========================================================================
// FUNCTION 1: GENERATE TABLES AND CHARTS
// =========================================================================
function generateProjectReports() {
  Logger.log(">>> [START] generateProjectReports execution initiated.");
  
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sourceSheet = ss.getActiveSheet();
  Logger.log("Active Sheet detected: " + sourceSheet.getName());
  
  // AUTOMATICALLY TARGET COLUMNS D:F INSTEAD OF ACTIVE SELECTION
  var lastRow = sourceSheet.getLastRow();
  if (lastRow < 2) {
    Logger.log("❌ ERROR: No data found on the active sheet.");
    SpreadsheetApp.getUi().alert('❗ No data found on this sheet. Please ensure you are on the sheet with the Pivot Table.');
    return;
  }
  
  // Capturing columns D through F automatically
  var range = sourceSheet.getRange("D1:F" + lastRow);
  Logger.log("Automatically targeted range: " + range.getA1Notation());

  var values = range.getValues();
  Logger.log("Total rows loaded from columns D:F: " + values.length);

  // --- 1. CONFIGURATION: TARGET PROD PROJECTS (IN EXACT ORDER) ---
  var targetProjects = [
    "awr-enable-prod",
    "awr-infosec-prod",
    "awr-connect-prod",
    "awr-prod-dw",
    "awr-chery-prod",
    "awr-dealeronline-prod",
    "awr-host-prod",
    "awr-prod-dataiku",
    "awr-dr-prod-project",
    "awr-atdgtl-prod",
    "awr-carbuyer-prod",
    "awr-corpwebsite-prod",
    "awr-github-enterprise"
  ];

  // --- 2. PARSE PIVOT TABLE DATA ---
  var projects = {};
  var lastProject = "";
  var startRow = (typeof values[0][2] === 'number') ? 0 : 1; 
  Logger.log("Parsing start row determined as: " + startRow + " (skipping header if string)");

  var matchingRowsCount = 0;
  for (var i = startRow; i < values.length; i++) {
    var row = values[i];
    var currentProject = row[0]; // Column D
    var finding = row[1];        // Column E
    var count = row[2];          // Column F

    // Handle standard blank pivot table rows for grouped project names
    if (currentProject && currentProject.toString().trim() !== "") {
      lastProject = currentProject;
    } else {
      currentProject = lastProject;
    }

    if (currentProject === "Total" || !finding || isNaN(count)) continue;
    if (targetProjects.indexOf(currentProject) === -1) continue;

    if (!projects[currentProject]) {
      projects[currentProject] = [];
    }
    projects[currentProject].push([finding, count]);
    matchingRowsCount++;
  }
  Logger.log("Successfully parsed " + matchingRowsCount + " sub-rows matching target production projects.");

  // --- 3. PREPARE OUTPUT SHEET ---
  var targetSheetName = "Project Reports";
  var targetSheet = ss.getSheetByName(targetSheetName);
  if (targetSheet) {
    Logger.log("Target sheet '" + targetSheetName + "' exists. Clearing old contents and charts...");
    targetSheet.clear(); 
    var existingCharts = targetSheet.getCharts();
    Logger.log("Found " + existingCharts.length + " existing charts to remove.");
    for (var k = 0; k < existingCharts.length; k++) {
      targetSheet.removeChart(existingCharts[k]);
    }
  } else {
    Logger.log("Target sheet '" + targetSheetName + "' not found. Creating a new one.");
    targetSheet = ss.insertSheet(targetSheetName);
  }

  var currentRow = 2; 

  // --- 4. GENERATION FUNCTION ---
  function createProjectBlock(projName, rawData) {
    Logger.log("Processing block layout for: " + projName);
    
    // HEADER
    var headerRange = targetSheet.getRange(currentRow, 1, 1, 2);
    headerRange.getCell(1, 1).setValue(projName);
    headerRange.merge(); 
    headerRange.setFontWeight("bold").setFontSize(12);
    headerRange.setBackground("white"); 
    headerRange.setBorder(true, true, true, true, null, null, "white", SpreadsheetApp.BorderStyle.SOLID);

    // CHECK IF DATA EXISTS
    if (!rawData || rawData.length === 0) {
      Logger.log("-> No findings listed for " + projName + ". Generating empty state block.");
      var noFindRange = targetSheet.getRange(currentRow + 1, 1, 1, 2);
      noFindRange.getCell(1,1).setValue("No Findings present");
      noFindRange.merge();
      noFindRange.setFontStyle("italic").setHorizontalAlignment("center");
      noFindRange.setBackground("white");
      noFindRange.setBorder(true, true, true, true, true, true, "white", SpreadsheetApp.BorderStyle.SOLID);
      currentRow += 3;
      return;
    }

    Logger.log("-> Found " + rawData.length + " finding types for " + projName + ". Building table and pie chart.");
    // Sort Descending by Count
    rawData.sort(function(a, b) {
      return b[1] - a[1];
    });

    var numRows = rawData.length;
    var formattedData = rawData.map(function(r) {
      return [r[0], r[1]]; 
    });

    // Write Data Table
    var tableRange = targetSheet.getRange(currentRow + 1, 1, numRows, 2);
    tableRange.setValues(formattedData);
    
    tableRange.setVerticalAlignment("middle");
    tableRange.setBackground("white"); 
    targetSheet.getRange(currentRow + 1, 1, numRows, 1).setWrap(true); 
    tableRange.setBorder(true, true, true, true, true, true, "white", SpreadsheetApp.BorderStyle.SOLID);
    
    // Create Chart
    var chartBuilder = targetSheet.newChart()
      .setChartType(Charts.ChartType.PIE)
      .addRange(tableRange) 
      .setOption('is3D', true)
      .setOption('title', projName)
      .setOption('pieSliceText', 'value')
      .setOption('width', 500)
      .setOption('height', 350)
      .setPosition(currentRow, 4, 0, 0); 

    targetSheet.insertChart(chartBuilder.build());

    var rowsUsed = Math.max(numRows, 18); 
    currentRow += rowsUsed + 4; 
  }

  targetProjects.forEach(function(pName) {
    var pData = projects[pName]; 
    createProjectBlock(pName, pData);
  });

  targetSheet.setColumnWidth(1, 350); 
  targetSheet.setColumnWidth(2, 50);  
  targetSheet.setColumnWidth(3, 20);  
  targetSheet.setHiddenGridlines(true);
  
  targetSheet.activate();
  Logger.log(">>> [SUCCESS] generateProjectReports finished successfully.");
  SpreadsheetApp.getUi().alert('✅ Report Generated strictly for specified Prod Projects.');
}

// =========================================================================
// FUNCTION 2: SYNC REPORTS TO SLIDES
// =========================================================================
function syncToSlides() {
  Logger.log(">>> [START] syncToSlides execution initiated.");
  
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName("Project Reports");
  
  if (!sheet) {
    Logger.log("❌ ERROR: 'Project Reports' sheet could not be located. Execution stopped.");
    SpreadsheetApp.getUi().alert("❌ 'Project Reports' sheet not found. Please run 'Generate Tables & Charts' first.");
    return;
  }

  // Get current dates for formatting
  var today = new Date();
  var timezone = ss.getSpreadsheetTimeZone();
  var bigDateStr = Utilities.formatDate(today, timezone, "MMMM d, yyyy");
  var monthYearStr = Utilities.formatDate(today, timezone, "MMMM yyyy");

  Logger.log("Attempting to connect to Google Slides ID: " + PRESENTATION_ID);
  var deck;
  try {
    deck = SlidesApp.openById(PRESENTATION_ID);
    Logger.log("Successfully connected to Presentation: " + deck.getName());
  } catch(e) {
    Logger.log("❌ ERROR: Failed to open Google Slide. Verify presentation ID and permissions. Details: " + e.message);
    SpreadsheetApp.getUi().alert("❌ Error opening presentation. Check the Execution Log.");
    return;
  }
  
  // 1. ADD A BIG DATE DIVIDER SLIDE AT THE END
  Logger.log("Appending Monthly Security Report Divider Slide...");
  var dividerSlide = deck.appendSlide(SlidesApp.PredefinedLayout.CENTERED_TITLE);
  var dividerTitle = dividerSlide.getPlaceholder(SlidesApp.PlaceholderType.CENTERED_TITLE).asShape();
  var dividerText = dividerTitle.getText();
  dividerText.setText("Monthly Security Report\n" + bigDateStr);
  dividerText.getTextStyle().setFontFamily("Google Sans").setBold(true);

  // 2. FETCH DATA & CHARTS FROM SHEET
  var data = sheet.getDataRange().getValues();
  var fontWeights = sheet.getDataRange().getFontWeights();
  var charts = sheet.getCharts();
  Logger.log("Loaded " + data.length + " data rows and " + charts.length + " charts from 'Project Reports' sheet.");
  
  // 3. PARSE SHEET BLOCKS & CREATE SLIDES
  var processedProjectsCount = 0;
  for (var i = 0; i < data.length; i++) {
    var cellValue = data[i][0];
    var fontWeight = fontWeights[i][0];
    
    // Detect a project block header (Bold text in Column A)
    if (fontWeight === "bold" && cellValue !== "") {
      var projName = cellValue;
      Logger.log("Found project block header: '" + projName + "' at Row " + (i + 1));
      
      // Collect table data underneath the header
      var tableData = [];
      var j = i + 1;
      while (j < data.length && data[j][0] !== "" && String(data[j][0]) !== "No Findings present") {
        tableData.push([data[j][0], data[j][1]]);
        j++;
      }
      
      // Check if "No findings" is flagged
      var hasFindings = tableData.length > 0;
      Logger.log("-> Findings evaluation for " + projName + ": hasFindings = " + hasFindings + " (Rows gathered: " + tableData.length + ")");
      
      // Create a Blank Slide appended to the end
      var slide = deck.appendSlide(SlidesApp.PredefinedLayout.BLANK);
      
      // Add Title text box (Top Left)
      var titleBox = slide.insertShape(SlidesApp.ShapeType.TEXT_BOX, 40, 30, 600, 50);
      var titleText = titleBox.getText();
      titleText.setText(projName + " | " + monthYearStr);
      titleText.getTextStyle().setFontFamily("Google Sans").setBold(true).setFontSize(22);
      
      // Add contents based on findings
      if (!hasFindings) {
        Logger.log("-> Writing 'No Findings' text block to slide.");
        var msgBox = slide.insertShape(SlidesApp.ShapeType.TEXT_BOX, 40, 100, 400, 50);
        msgBox.getText().setText("✅ No Findings present for this project.");
        msgBox.getText().getTextStyle().setFontFamily("Google Sans").setItalic(true).setFontSize(16);
      } else {
        Logger.log("-> Injecting data table into slide (Size: " + (tableData.length + 1) + "x2)");
        // Insert Table (X, Y, Width, Height)
        var table = slide.insertTable(tableData.length + 1, 2, 40, 100, 350, 50);
        
        // Format Table Header
        table.getCell(0, 0).getText().setText("Finding Category").getTextStyle().setFontFamily("Google Sans").setBold(true).setFontSize(12);
        table.getCell(0, 1).getText().setText("Count").getTextStyle().setFontFamily("Google Sans").setBold(true).setFontSize(12);
        
        // Populate Table Data
        for(var r = 0; r < tableData.length; r++) {
          table.getCell(r+1, 0).getText().setText(String(tableData[r][0])).getTextStyle().setFontFamily("Google Sans").setFontSize(10);
          table.getCell(r+1, 1).getText().setText(String(tableData[r][1])).getTextStyle().setFontFamily("Google Sans").setFontSize(10);
        }
        
        // Find matching Pie Chart and insert on the right
        var chartFound = false;
        Logger.log("-> Searching for matching sheet chart titled: '" + projName + "'");
        for (var c = 0; c < charts.length; c++) {
          var chart = charts[c];
          if (chart.getOptions().get('title') === projName) {
            Logger.log("--> Match found! Injecting chart into slide.");
            // Insert Chart (Chart Object, X, Y, Width, Height)
            slide.insertSheetsChart(chart, 420, 100, 300, 250);
            chartFound = true;
            break; 
          }
        }
        if (!chartFound) {
          Logger.log("⚠️ WARNING: No chart option matching '" + projName + "' was discovered in the charts array.");
        }
      }
      
      processedProjectsCount++;
      i = j; // Advance loop past this block to avoid reading the same data again
    }
  }
  
  Logger.log(">>> [SUCCESS] syncToSlides processed " + processedProjectsCount + " total project slides.");
  SpreadsheetApp.getUi().alert('✅ Success! Slides dynamically appended to the end of your presentation.');
}
