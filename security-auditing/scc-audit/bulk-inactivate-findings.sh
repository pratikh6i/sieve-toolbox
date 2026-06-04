#!/bin/bash

# Default input file to findings.txt if not provided as argument
FILE=${1:-"findings.txt"}

if [ ! -f "$FILE" ]; then
  echo "❌ Error: Input file '$FILE' not found."
  exit 1
fi

while IFS= read -r RAW_NAME || [[ -n "$RAW_NAME" ]]; do
  
  # 1. Skip empty lines
  if [[ -z "$RAW_NAME" ]]; then continue; fi

  # 2. Clean the string
  FINDING_NAME=$(echo "$RAW_NAME" | sed 's/,$//' | tr -d '\r' | xargs)
  
  echo -n "Checking: $FINDING_NAME ... "
  
  # 3. Extract the parent path
  PARENT=$(echo "$FINDING_NAME" | sed 's|/findings/.*||')
  
  # 4. Fetch the current state from GCP (Capturing errors just in case the list command fails too)
  CURRENT_STATE=$(gcloud scc findings list "$PARENT" --filter="name=\"$FINDING_NAME\"" --format="value(finding.state)" 2>/dev/null)
  
  # 5. Check if it is already INACTIVE
  if [[ "$CURRENT_STATE" == *"INACTIVE"* ]]; then
    echo "⏩ Already INACTIVE (Skipped)"
    continue
  fi
  
  # 6. If ACTIVE, generate event time
  EVENT_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  
  # 7. Run the update command and CAPTURE the output instead of hiding it
  UPDATE_OUTPUT=$(gcloud scc findings update "$FINDING_NAME" \
    --state="INACTIVE" \
    --event-time="$EVENT_TIME" 2>&1)
  
  # 8. Check if the update was successful
  if [ $? -eq 0 ]; then
    echo "✅ Successfully Updated to INACTIVE"
  else
    # Print the exact error message returned by Google Cloud
    echo "❌ Failed."
    echo "   ↳ ERROR DETAILS: $UPDATE_OUTPUT"
  fi

done < "$FILE"
