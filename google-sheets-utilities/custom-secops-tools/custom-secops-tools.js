/**
 * CLOUD SECURITY OPS TOOLKIT
 * --------------------------
 * 1. JSON Extractors
 * 2. Basic IP Batch (ipinfo.io)
 * 3. Advanced IP Kundli (RIPEstat + AbuseIPDB)
 */

function onOpen() {
  SpreadsheetApp.getUi()
      .createMenu('Custom Tools')
      // --- ORIGINAL TOOLS ---
      .addItem('Extract URIs', 'extractUrisFromSelection')
      .addItem('Extract HasDefaultPolicy', 'extractHasDefaultPolicyForSelection')
      .addItem('Extract SslPolicyName', 'extractSslPolicyNameForSelection')
      .addSeparator()
      .addItem('Get IP Country & Org (Batch)', 'getIpData')
      // --- NEW UPGRADE ---
      .addSeparator()
      .addItem('Get IP Advanced Kundli (Deep)', 'getAdvancedKundli')
      .addToUi();
}

// =================================================================================
// PART 1: JSON EXTRACTORS
// =================================================================================

function extractUrisFromSelection() {
  var spreadsheet = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = spreadsheet.getActiveSheet();
  var range = sheet.getActiveRange();
  for (var i = 0; i < range.getNumRows(); i++) {
    var row = range.getRow() + i;
    var cellA = sheet.getRange('A' + row);
    var cellB = sheet.getRange('B' + row);
    var jsonData = cellA.getValue();
    var uris = [];
    if (jsonData && typeof jsonData === 'string') {
      try {
        var data = JSON.parse(jsonData);
        if (Array.isArray(data)) {
          for (var j = 0; j < data.length; j++) {
            var item = data[j];
            if (item && typeof item === 'object' && item.hasOwnProperty('containers') && Array.isArray(item.containers)) {
              for (var k = 0; k < item.containers.length; k++) {
                var container = item.containers[k];
                if (container && typeof container === 'object' && container.hasOwnProperty('uri')) {
                  uris.push(container.uri);
                }
              }
            }
          }
        }
      } catch (e) {
        uris.push("Error parsing JSON: " + e.message);
      }
    } else if (jsonData) {
      uris.push("Cell A" + row + " does not contain a valid JSON string.");
    } else {
      uris.push("Cell A" + row + " is empty.");
    }
    if (uris.length > 0) {
      cellB.setValue(uris.join('\n'));
    } else {
      cellB.setValue("No URIs found in valid JSON.");
    }
  }
  SpreadsheetApp.getUi().alert('URI extraction complete for selected rows.');
}

function extractHasDefaultPolicyForSelection() {
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getActiveSheet();
  const selectedRange = sheet.getActiveRange();
  const sourceCells = selectedRange.getValues();
  const numRows = selectedRange.getNumRows();
  const numCols = selectedRange.getNumColumns();
  const startRow = selectedRange.getRow();
  const startCol = selectedRange.getColumn();
  const outputValues = [];
  for (let i = 0; i < numRows; i++) {
    const rowValues = [];
    for (let j = 0; j < numCols; j++) {
      const jsonString = sourceCells[i][j];
      let outputValue = '';
      if (jsonString && typeof jsonString === 'string') {
        try {
          const data = JSON.parse(jsonString);
          const policyObject = data.find(item => item.key === "HasDefaultPolicy");
          if (policyObject) {
            outputValue = `HasDefaultPolicy - ${policyObject.value}`;
          }
        } catch (e) {
          console.error(`Error parsing JSON in cell ${String.fromCharCode(65 + startCol + j - 1)}${startRow + i}: ${e.message}`);
        }
      }
      rowValues.push(outputValue);
    }
    outputValues.push(rowValues);
  }
  const targetRange = sheet.getRange(startRow, startCol + numCols, numRows, numCols);
  targetRange.setValues(outputValues);
}

function extractSslPolicyNameForSelection() {
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getActiveSheet();
  const selectedRange = sheet.getActiveRange();
  const sourceCells = selectedRange.getValues();
  const numRows = selectedRange.getNumRows();
  const numCols = selectedRange.getNumColumns();
  const startRow = selectedRange.getRow();
  const startCol = selectedRange.getColumn();
  const outputValues = [];
  for (let i = 0; i < numRows; i++) {
    const rowValues = [];
    for (let j = 0; j < numCols; j++) {
      const jsonString = sourceCells[i][j];
      let outputValue = '';
      if (jsonString && typeof jsonString === 'string') {
        try {
          const data = JSON.parse(jsonString);
          const policyObject = data.find(item => item.key === "SslPolicyName");
          if (policyObject) {
            outputValue = `SslPolicyName : ${policyObject.value}`;
          }
        } catch (e) {
          console.error(`Error parsing JSON in cell ${String.fromCharCode(65 + startCol + j - 1)}${startRow + i}: ${e.message}`);
        }
      }
      rowValues.push(outputValue);
    }
    outputValues.push(rowValues);
  }
  const targetRange = sheet.getRange(startRow, startCol + numCols, numRows, numCols);
  targetRange.setValues(outputValues);
}


// =================================================================================
// PART 2: BASIC IP BATCH (ipinfo.io)
// =================================================================================

function getIpData() {
  // --- CONFIGURATION ---
  const API_TOKEN = 'YOUR_IPINFO_API_TOKEN'; // Replace with your ipinfo.io API token
  // --------------------

  const countryCodeToName = {"AF":"Afghanistan","AX":"Aland Islands","AL":"Albania","DZ":"Algeria","AS":"American Samoa","AD":"Andorra","AO":"Angola","AI":"Anguilla","AQ":"Antarctica","AG":"Antigua and Barbuda","AR":"Argentina","AM":"Armenia","AW":"Aruba","AU":"Australia","AT":"Austria","AZ":"Azerbaijan","BS":"Bahamas","BH":"Bahrain","BD":"Bangladesh","BB":"Barbados","BY":"Belarus","BE":"Belgium","BZ":"Belize","BJ":"Benin","BM":"Bermuda","BT":"Bhutan","BO":"Bolivia","BQ":"Bonaire, Sint Eustatius and Saba","BA":"Bosnia and Herzegovina","BW":"Botswana","BV":"Bouvet Island","BR":"Brazil","IO":"British Indian Ocean Territory","BN":"Brunei Darussalam","BG":"Bulgaria","BF":"Burkina Faso","BI":"Burundi","CV":"Cabo Verde","KH":"Cambodia","CM":"Cameroon","CA":"Canada","KY":"Cayman Islands","CF":"Central African Republic","TD":"Chad","CL":"Chile","CN":"China","CX":"Christmas Island","CC":"Cocos (Keeling) Islands","CO":"Colombia","KM":"Comoros","CD":"Congo, Democratic Republic of the","CG":"Congo","CK":"Cook Islands","CR":"Costa Rica","CI":"Cote d'Ivoire","HR":"Croatia","CU":"Cuba","CW":"Curaçao","CY":"Cyprus","CZ":"Czechia","DK":"Denmark","DJ":"Djibouti","DM":"Dominica","DO":"Dominican Republic","EC":"Ecuador","EG":"Egypt","SV":"El Salvador","GQ":"Equatorial Guinea","ER":"Eritrea","EE":"Estonia","SZ":"Eswatini","ET":"Ethiopia","FK":"Falkland Islands (Malvinas)","FO":"Faroe Islands","FJ":"Fiji","FI":"Finland","FR":"France","GF":"French Guiana","PF":"French Polynesia","TF":"French Southern Territories","GA":"Gabon","GM":"Gambia","GE":"Georgia","DE":"Germany","GH":"Ghana","GI":"Gibraltar","GR":"Greece","GL":"Greenland","GD":"Grenada","GP":"Guadeloupe","GU":"Guam","GT":"Guatemala","GG":"Guernsey","GN":"Guinea","GW":"Guinea-Bissau","GY":"Guyana","HT":"Haiti","HM":"Heard Island and McDonald Islands","VA":"Holy See","HN":"Honduras","HK":"Hong Kong","HU":"Hungary","IS":"Iceland","IN":"India","ID":"Indonesia","IR":"Iran","IQ":"Iraq","IE":"Ireland","IM":"Isle of Man","IL":"Israel","IT":"Italy","JM":"Jamaica","JP":"Japan","JE":"Jersey","JO":"Jordan","KZ":"Kazakhstan","KE":"Kenya","KI":"Kiribati","KP":"Korea, Democratic People's Republic of","KR":"Korea, Republic of","KW":"Kuwait","KG":"Kyrgyzstan","LA":"Lao People's Democratic Republic","LV":"Latvia","LB":"Lebanon","LS":"Lesotho","LR":"Liberia","LY":"Libya","LI":"Liechtenstein","LT":"Lithuania","LU":"Luxembourg","MO":"Macao","MG":"Madagascar","MW":"Malawi","MY":"Malaysia","MV":"Maldives","ML":"Mali","MT":"Malta","MH":"Marshall Islands","MQ":"Martinique","MR":"Mauritania","MU":"Mauritius","YT":"Mayotte","MX":"Mexico","FM":"Micronesia","MD":"Moldova","MC":"Monaco","MN":"Mongolia","ME":"Montenegro","MS":"Montserrat","MA":"Morocco","MZ":"Mozambique","MM":"Myanmar","NA":"Namibia","NR":"Nauru","NP":"Nepal","NL":"Netherlands","NC":"New Caledonia","NZ":"New Zealand","NI":"Nicaragua","NE":"Niger","NG":"Nigeria","NU":"Niue","NF":"Norfolk Island","MK":"North Macedonia","MP":"Northern Mariana Islands","NO":"Norway","OM":"Oman","PK":"Pakistan","PW":"Palau","PS":"Palestine, State of","PA":"Panama","PG":"Papua New Guinea","PY":"Paraguay","PE":"Peru","PH":"Philippines","PN":"Pitcairn","PL":"Poland","PT":"Portugal","PR":"Puerto Rico","QA":"Qatar","RE":"Reunion","RO":"Romania","RU":"Russian Federation","RW":"Rwanda","BL":"Saint Barthelemy","SH":"Saint Helena, Ascension and Tristan da Cunha","KN":"Saint Kitts and Nevis","LC":"Saint Lucia","MF":"Saint Martin (French part)","PM":"Saint Pierre and Miquelon","VC":"Saint Vincent and the Grenadines","WS":"Samoa","SM":"San Marino","ST":"Sao Tome and Principe","SA":"Saudi Arabia","SN":"Senegal","RS":"Serbia","SC":"Seychelles","SL":"Sierra Leone","SG":"Singapore","SX":"Sint Maarten (Dutch part)","SK":"Slovakia","SI":"Slovenia","SB":"Solomon Islands","SO":"Somalia","ZA":"South Africa","GS":"South Georgia and the South Sandwich Islands","SS":"South Sudan","ES":"Spain","LK":"Sri Lanka","SD":"Sudan","SR":"Suriname","SJ":"Svalbard and Jan Mayen","SE":"Sweden","CH":"Switzerland","SY":"Syrian Arab Republic","TW":"Taiwan","TJ":"Tajikistan","TZ":"Tanzania","TH":"Thailand","TL":"Timor-Leste","TG":"Togo","TK":"Tokelau","TO":"Tonga","TT":"Trinidad and Tobago","TN":"Tunisia","TR":"Turkey","TM":"Turkmenistan","TC":"Turks and Caicos Islands","TV":"Tuvalu","UG":"Uganda","UA":"Ukraine","AE":"United Arab Emirates","GB":"United Kingdom","US":"United States","UM":"United States Minor Outlying Islands","UY":"Uruguay","UZ":"Uzbekistan","VU":"Vanuatu","VE":"Venezuela","VN":"Viet Nam","VG":"Virgin Islands (British)","VI":"Virgin Islands (U.S.)","WF":"Wallis and Futuna","EH":"Western Sahara","YE":"Yemen","ZM":"Zambia","ZW":"Zimbabwe"};
  const ui = SpreadsheetApp.getUi();

  if (!API_TOKEN || API_TOKEN === 'YOUR_IPINFO_API_TOKEN') {
    ui.alert('API Token Required', 'Please check your API_TOKEN variable.', ui.ButtonSet.OK);
    return;
  }
  
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getActiveSheet();
  const selectedRange = sheet.getActiveRange();

  if (!selectedRange) {
    ui.alert('Please select a column of cells containing IP addresses first.');
    return;
  }

  const ipAddresses = selectedRange.getValues().flat().filter(ip => ip && typeof ip === 'string' && ip.trim() !== '');

  if (ipAddresses.length === 0) {
    ui.alert('No valid IP addresses found in the selected range.');
    return;
  }

  const allResults = {};
  const chunkSize = 100;

  try {
    for (let i = 0; i < ipAddresses.length; i += chunkSize) {
      const chunk = ipAddresses.slice(i, i + chunkSize);
      const url = `https://ipinfo.io/batch?token=${API_TOKEN}`;
      const options = {
        'method': 'post',
        'contentType': 'application/json',
        'payload': JSON.stringify(chunk),
        'muteHttpExceptions': true
      };

      const response = UrlFetchApp.fetch(url, options);
      if (response.getResponseCode() === 200) {
        const batchData = JSON.parse(response.getContentText());
        Object.assign(allResults, batchData);
      }
    }

    const originalData = selectedRange.getValues();
    const outputData = originalData.map(row => {
      const ip = row[0] ? String(row[0]).trim() : '';
      if (ip && allResults[ip] && !allResults[ip].error) {
        const result = allResults[ip];
        const countryCode = result.country || 'N/A';
        const countryFullName = countryCodeToName[countryCode] || countryCode;
        const fullOrg = result.org || 'N/A';
        const orgParts = fullOrg.split(' ');
        const companyName = orgParts.length > 1 && orgParts[0].toUpperCase().startsWith('AS')
                              ? orgParts.slice(1).join(' ')
                              : fullOrg;
        return [countryFullName, companyName];
      } else {
        return ['', ''];
      }
    });

    const outputRange = selectedRange.offset(0, 1, outputData.length, 2);
    outputRange.setValues(outputData);
    ui.alert('Success!', `Finished fetching basic data for ${ipAddresses.length} IPs.`, ui.ButtonSet.OK);

  } catch (e) {
    ui.alert('Error', e.message, ui.ButtonSet.OK);
  }
}


// =================================================================================
// PART 3: ADVANCED KUNDLI FUNCTION (ADD-ON)
// Uses RIPEstat (Whois) + AbuseIPDB (Blacklist Count)
// =================================================================================

function getAdvancedKundli() {
  // --- CONFIGURATION ---
  const ABUSEIPDB_KEY = 'YOUR_ABUSEIPDB_API_KEY'; // Replace with your AbuseIPDB key
  // --------------------

  const ui = SpreadsheetApp.getUi();
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getActiveSheet();
  const selectedRange = sheet.getActiveRange();

  if (!ABUSEIPDB_KEY || ABUSEIPDB_KEY === 'YOUR_ABUSEIPDB_API_KEY') {
    ui.alert('Setup Required', 'Please get a free AbuseIPDB key and paste it into the script editor (ABUSEIPDB_KEY variable).', ui.ButtonSet.OK);
    return;
  }
  
  if (!selectedRange) {
    ui.alert('Please select a column of IPs first.');
    return;
  }

  const ipAddresses = selectedRange.getValues().flat().filter(ip => ip && typeof ip === 'string' && ip.trim() !== '');
  if (ipAddresses.length === 0) {
    ui.alert('No valid IPs found.');
    return;
  }

  // Add Headers for the new columns
  const headers = [['Detailed WHOIS (NetName/Addr)', 'Threat Intel (Counts)']];
  const headerRange = sheet.getRange(selectedRange.getRow() - 1, selectedRange.getColumn() + 1, 1, 2);
  if (selectedRange.getRow() > 1 && headerRange.getValue() === "") {
     headerRange.setValues(headers).setFontWeight("bold").setBackground("#e6f4ea");
  }

  const outputData = [];

  // Iterate IPs
  for (let i = 0; i < ipAddresses.length; i++) {
    const ip = ipAddresses[i].trim();
    let col1 = "Loading...";
    let col2 = "Loading...";

    try {
      // 1. RIPEstat (Get NetName, CIDR, Address)
      const whoisUrl = `https://stat.ripe.net/data/whois/data.json?resource=${ip}`;
      const whoisResp = UrlFetchApp.fetch(whoisUrl, { muteHttpExceptions: true });
      if (whoisResp.getResponseCode() === 200) {
        const records = JSON.parse(whoisResp.getContentText()).data.records;
        
        let netName = extractField(records, 'NetName');
        let cidr = extractField(records, 'CIDR');
        let org = extractField(records, 'Organization');
        let country = extractField(records, 'Country');
        let address = extractAddressBlock(records);

        if (cidr === '-') cidr = extractField(records, 'NetRange') || extractField(records, 'inetnum');

        col1 = `CIDR: ${cidr}\nNetName: ${netName}\nOrg: ${org}\nAddress:\n${address}`;
      } else {
        col1 = "Whois Error";
      }

      // 2. AbuseIPDB (Get Blacklist Count)
      const abuseUrl = `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`;
      const abuseResp = UrlFetchApp.fetch(abuseUrl, { 
        headers: { 'Key': ABUSEIPDB_KEY, 'Accept': 'application/json' },
        muteHttpExceptions: true 
      });

      if (abuseResp.getResponseCode() === 200) {
        const abuseData = JSON.parse(abuseResp.getContentText()).data;
        col2 = `Score: ${abuseData.abuseConfidenceScore}%\nListed Count: ${abuseData.totalReports}\nReporters: ${abuseData.numDistinctUsers}`;
      } else {
        col2 = "Abuse API Error";
      }

    } catch (e) {
      col1 = "Error: " + e.message;
    }
    
    outputData.push([col1, col2]);
    Utilities.sleep(250); // Respect API limits
  }

  const outputRange = selectedRange.offset(0, 1, outputData.length, 2);
  outputRange.setValues(outputData);
  outputRange.setWrapStrategy(SpreadsheetApp.WrapStrategy.WRAP);
  ui.alert('Advanced Kundli Complete', `Processed ${ipAddresses.length} IPs.`, ui.ButtonSet.OK);
}

// --- HELPERS FOR NEW FUNCTION ---
function extractField(records, key) {
  if (!records) return '-';
  for (let block of records) {
    for (let row of block) {
      if (row.key && row.key.toLowerCase() === key.toLowerCase()) return row.value;
    }
  }
  return '-';
}

function extractAddressBlock(records) {
  if (!records) return '-';
  let lines = [];
  for (let block of records) {
    for (let row of block) {
      if (row.key.toLowerCase() === 'address') lines.push(row.value);
    }
    if (lines.length > 0) break; // Use first block with address
  }
  return lines.join('\n');
}
