#!/usr/bin/env bash

PROJECT_IDS=(
  "YOUR_PROJECT_ID"
)
OUTPUT_CSV_FILE="gcp_tls_policy_report_$(date +%Y%m%d_%H%M%S).csv"

echo "\"Project ID\",\"Policy Name\",\"Profile\",\"Minimum TLS Version\",\"Enabled Features\",\"In Use By Resources\"" > "${OUTPUT_CSV_FILE}"

echo "Generating GCP TLS Policy Report..."
echo "Output will be saved to: ${OUTPUT_CSV_FILE}"
echo "--------------------------------------------------------------------------------"

for PROJECT_ID in "${PROJECT_IDS[@]}"; do
  echo "Processing Project: ${PROJECT_ID}..." # 

  gcloud config set project "${PROJECT_ID}" > /dev/null 2>&1
  if [ $? -ne 0 ]; then 
    echo "  ERROR: Failed to set project to '${PROJECT_ID}'. Please check project ID or permissions. Skipping this project."
    continue
  fi

  POLICY_NAMES=$(gcloud compute ssl-policies list --project "${PROJECT_ID}" --format="value(name)" 2>/dev/null)

  if [[ -z "${POLICY_NAMES}" ]]; then
    echo "  No TLS policies found in '${PROJECT_ID}'."
    continue
  fi

  for POLICY_NAME in ${POLICY_NAMES}; do
    POLICY_DETAILS=$(gcloud compute ssl-policies describe "${POLICY_NAME}" \
      --project "${PROJECT_ID}" \
      --format="json" 2>/dev/null)

    if [[ -z "${POLICY_DETAILS}" ]]; then
      echo "  ERROR: Could not retrieve details for policy '${POLICY_NAME}' in '${PROJECT_ID}'. Skipping."
      continue # Move to the next policy
    fi

    PROFILE=$(echo "${POLICY_DETAILS}" | jq -r '.profile')
    MIN_TLS_VERSION=$(echo "${POLICY_DETAILS}" | jq -r '.minTlsVersion')

    ENABLED_FEATURES_FORMATTED=$(echo "${POLICY_DETAILS}" | jq -r '.enabledFeatures[]' 2>/dev/null | paste -sd, -)
    if [[ -z "${ENABLED_FEATURES_FORMATTED}" ]]; then
      ENABLED_FEATURES_FORMATTED=""
    fi

    USING_RESOURCE_NAMES=()

    HTTPS_PROXIES=$(gcloud compute target-https-proxies list \
      --project "${PROJECT_ID}" \
      --filter="sslPolicy.basename()=${POLICY_NAME}" \
      --format="value(name)" 2>/dev/null)

    for PROXY in ${HTTPS_PROXIES}; do
      USING_RESOURCE_NAMES+=("${PROXY}")
    done

    SSL_PROXIES=$(gcloud compute target-ssl-proxies list \
      --project "${PROJECT_ID}" \
      --filter="sslPolicy.basename()=${POLICY_NAME}" \
      --format="value(name)" 2>/dev/null)

    for PROXY in ${SSL_PROXIES}; do
      USING_RESOURCE_NAMES+=("${PROXY}")
    done

    if [[ ${#USING_RESOURCE_NAMES[@]} -eq 0 ]]; then
      RESOURCES_FORMATTED=""
    else
      RESOURCES_FORMATTED=$(printf "%s," "${USING_RESOURCE_NAMES[@]}")
      RESOURCES_FORMATTED="${RESOURCES_FORMATTED%,}" # Remove the last comma
    fi
    
    printf "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n" \
      "${PROJECT_ID}" \
      "${POLICY_NAME}" \
      "${PROFILE}" \
      "${MIN_TLS_VERSION}" \
      "${ENABLED_FEATURES_FORMATTED}" \
      "${RESOURCES_FORMATTED}" >> "${OUTPUT_CSV_FILE}"

  done
done

echo "--------------------------------------------------------------------------------"
echo "Report generation complete. Data saved to: ${OUTPUT_CSV_FILE}"
echo "You can now open '${OUTPUT_CSV_FILE}' with your preferred spreadsheet software (e.g., Google Sheets)."
echo "In Google Sheets, use 'Data > Split text to columns' with ',' as the delimiter for 'Enabled Features' and 'In Use By Resources' columns."
