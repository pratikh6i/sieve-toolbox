#!/bin/bash
read -p "Enter the organization ID: " ORG_ID

log_file="icmp_only_rules.txt"
error_log="error_projects.txt"
> "$log_file"
> "$error_log"

projects=($(gcloud projects list --filter="parent.id=$ORG_ID" --format="value(projectId)"))

for PROJECT_ID in "${projects[@]}"; do
 echo "Processing project: $PROJECT_ID"

 API_STATUS=$(gcloud services list --project="$PROJECT_ID" --filter="config.name=compute.googleapis.com" --format="value(state)")

 if [[ "$API_STATUS" != "ENABLED" ]]; then
   echo "Compute API not enabled for project $PROJECT_ID. Skipping..." >> "$error_log"
   continue  # Move to the next project
 fi

 FIREWALL_RULES=$(gcloud compute firewall-rules list --project="$PROJECT_ID" --format="json" 2>/dev/null)
 echo "$FIREWALL_RULES" | jq -c '.[]' | while read -r RULE; do
   RULE_NAME=$(echo "$RULE" | jq -r '.name')
   ALLOWED_PROTOCOLS=$(echo "$RULE" | jq -c '.allowed')
   if [[ "$ALLOWED_PROTOCOLS" == '[{"IPProtocol":"icmp"}]' ]]; then
     echo "ICMP-only rule '$RULE_NAME' in project '$PROJECT_ID' would be deleted." >> "$log_file"
     echo "Preview: ICMP-only rule '$RULE_NAME' in project '$PROJECT_ID' would be deleted."

     # Uncomment below to delete the rule after testing, suppressing prompts
     # gcloud compute firewall-rules delete "$RULE_NAME" --project="$PROJECT_ID" -q --quiet

     # Uncomment below to just disable the firewall rule instead of deleting the rule
     # gcloud compute firewall-rules update "$RULE_NAME" --project="$PROJECT_ID" --disabled

   else
     echo "Skipping rule '$RULE_NAME' in project '$PROJECT_ID' as it includes other protocols." >> "$log_file"
   fi
 done
done
echo "Preview of ICMP-only rule cleanup completed. See '$log_file' for details."
echo "Projects with errors: See '$error_log' for details."
