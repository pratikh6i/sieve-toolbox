# List of target projects (customize this list or read from command-line arguments)
# PROJECTS=("YOUR_PROJECT_ID_1" "YOUR_PROJECT_ID_2" ...)
PROJECTS=("YOUR_PROJECT_ID")


#Global name for CA newly getting created
CA_POLICY="std-armor-policy"

#initializing empty list for error projects
ERROR_PROJECTS=()

#looping projects in list
for PROJECT in "${PROJECTS[@]}"
do
  echo "Applying Cloud Armor policy to $PROJECT"

  # Create the security policy
  gcloud compute security-policies create $CA_POLICY --project=$PROJECT --description "Policy created by Searce using the Script"
  sleep 30
  gcloud compute security-policies update $CA_POLICY --enable-layer7-ddos-defense



    POLICY_STATUS=$?
    if [[ $POLICY_STATUS -ne 0 ]]; then
        echo "Error creating policy in project:--- $PROJECT ---. ERROR CREATING POLICY"
        ERROR_PROJECTS+=("$PROJECT")
        continue #i need the execution to stop and go to next item(project-id) in list
    fi



  # Cloud Armor Rule
  gcloud compute security-policies rules create 100 \
    --security-policy $CA_POLICY \
    --description "Prevention from SQL injection attack" \
    --expression "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 1})" \
    --action deny-403 \
    --preview

    RULE_STATUS=$?
    if [[ $RULE_STATUS -ne 0 ]]; then
        echo "Error creating rule 100 in project:--- $PROJECT ---. Likely quota issue or Policy doesn't exist"
        ERROR_PROJECTS+=("$PROJECT")
        continue #i need the execution to stop and go to next item(project-id) in list
    fi

  # Cloud Armor Rule
  gcloud compute security-policies rules create 101 \
    --security-policy $CA_POLICY \
    --description "Prevention from cross site scripting attack" \
    --expression "evaluatePreconfiguredWaf('xss-v33-stable')" \
    --action deny-403 \
    --preview

    RULE_STATUS=$?
    if [[ $RULE_STATUS -ne 0 ]]; then
        echo "Error creating rule 101 in project:--- $PROJECT ---. Likely quota issue or Policy doesn't exist"
        ERROR_PROJECTS+=("$PROJECT")
        continue #i need the execution to stop and go to next item(project-id) in list
    fi


  # Cloud Armor Rule
  gcloud compute security-policies rules create 102 \
    --security-policy $CA_POLICY \
    --description "Prevention from local file inclusion attack" \
    --expression "evaluatePreconfiguredWaf('lfi-v33-stable')" \
    --action deny-403 \
    --preview

    RULE_STATUS=$?
    if [[ $RULE_STATUS -ne 0 ]]; then
        echo "Error creating rule 102 in project:--- $PROJECT ---. Likely quota issue or Policy doesn't exist"
        ERROR_PROJECTS+=("$PROJECT")
        continue #i need the execution to stop and go to next item(project-id) in list
    fi


  # Cloud Armor Rule
  gcloud compute security-policies rules create 103 \
    --security-policy $CA_POLICY \
    --description "Prevention from Remote Code Execution attack" \
    --expression "evaluatePreconfiguredWaf('rce-v33-stable')" \
    --action deny-403 \
    --preview

    RULE_STATUS=$?
    if [[ $RULE_STATUS -ne 0 ]]; then
        echo "Error creating rule 103 in project:--- $PROJECT ---. Likely quota issue or Policy doesn't exist"
        ERROR_PROJECTS+=("$PROJECT")
        continue #i need the execution to stop and go to next item(project-id) in list
    fi


  # Cloud Armor Rule
  gcloud compute security-policies rules create 104 \
    --security-policy $CA_POLICY \
    --description "Prevention from Remote File Inclusion attack" \
    --expression "evaluatePreconfiguredWaf('rfi-v33-stable')" \
    --action deny-403 \
    --preview

    RULE_STATUS=$?
    if [[ $RULE_STATUS -ne 0 ]]; then
        echo "Error creating rule 104 in project:--- $PROJECT ---. Likely quota issue or Policy doesn't exist"
        ERROR_PROJECTS+=("$PROJECT")
        continue #i need the execution to stop and go to next item(project-id) in list
    fi


  # Cloud Armor Rule
  gcloud compute security-policies rules create 105 \
    --security-policy $CA_POLICY \
    --description "Prevention from Session based attack" \
    --expression "evaluatePreconfiguredWaf('sessionfixation-v33-stable')" \
    --action deny-403 \
    --preview

    RULE_STATUS=$?
    if [[ $RULE_STATUS -ne 0 ]]; then
        echo "Error creating rule 105 in project:--- $PROJECT ---. Likely quota issue or Policy doesn't exist"
        ERROR_PROJECTS+=("$PROJECT")
        continue #i need the execution to stop and go to next item(project-id) in list
    fi


  # Cloud Armor Rule
  gcloud compute security-policies rules create 106 \
    --security-policy $CA_POLICY \
    --description "Prevention from reconnaissance technique" \
    --expression "evaluatePreconfiguredWaf('scannerdetection-v33-stable')" \
    --action deny-403 \
    --preview

    RULE_STATUS=$?
    if [[ $RULE_STATUS -ne 0 ]]; then
        echo "Error creating rule 106 in project:--- $PROJECT ---. Likely quota issue or Policy doesn't exist"
        ERROR_PROJECTS+=("$PROJECT")
        continue #i need the execution to stop and go to next item(project-id) in list
    fi


  # Cloud Armor Rule
  gcloud compute security-policies rules create 107 \
    --security-policy $CA_POLICY \
    --description "Prevention from Protocol based attack" \
    --expression "evaluatePreconfiguredWaf('protocolattack-v33-stable')" \
    --action deny-403 \
    --preview

    RULE_STATUS=$?
    if [[ $RULE_STATUS -ne 0 ]]; then
        echo "Error creating rule 107 in project:--- $PROJECT ---. Likely quota issue or Policy doesn't exist"
        ERROR_PROJECTS+=("$PROJECT")
        continue #i need the execution to stop and go to next item(project-id) in list
    fi


  # Cloud Armor Rule
  gcloud compute security-policies rules create 108 \
    --security-policy $CA_POLICY \
    --description "Prevention from PHP based attack" \
    --expression "evaluatePreconfiguredWaf('php-v33-stable', {'sensitivity': 1})" \
    --action deny-403 \
    --preview

    RULE_STATUS=$?
    if [[ $RULE_STATUS -ne 0 ]]; then
        echo "Error creating rule 108 in project:--- $PROJECT ---. Likely quota issue or Policy doesn't exist"
        ERROR_PROJECTS+=("$PROJECT")
        continue #i need the execution to stop and go to next item(project-id) in list
    fi


  # Cloud Armor Rule
  gcloud compute security-policies rules create 109 \
    --security-policy $CA_POLICY \
    --description "Prevention from attack on API methods" \
    --expression "evaluatePreconfiguredWaf('methodenforcement-v33-stable')" \
    --action deny-403 \
    --preview

    RULE_STATUS=$?
    if [[ $RULE_STATUS -ne 0 ]]; then
        echo "Error creating rule 109 in project:--- $PROJECT ---. Likely quota issue or Policy doesn't exist"
        ERROR_PROJECTS+=("$PROJECT")
        continue #i need the execution to stop and go to next item(project-id) in list
    fi


  # Cloud Armor Rule
  gcloud compute security-policies rules create 110 \
    --security-policy $CA_POLICY \
    --description "Blocking the malicious IPs, tor related IP and detected CVE signatures" \
    --expression "evaluateThreatIntelligence('iplist-known-malicious-ips') || evaluateThreatIntelligence('iplist-tor-exit-nodes') || evaluatePreconfiguredExpr('cve-canary') || evaluateThreatIntelligence('iplist-crypto-miners')" \
    --action deny-403 \
    --preview

    RULE_STATUS=$?
    if [[ $RULE_STATUS -ne 0 ]]; then
        echo "Error creating rule 110 in project:--- $PROJECT ---. Likely quota issue or Policy doesn't exist"
        ERROR_PROJECTS+=("$PROJECT")
        continue #i need the execution to stop and go to next item(project-id) in list
    fi


  # Cloud Armor Rule
  gcloud compute security-policies rules create 111 \
    --security-policy $CA_POLICY \
    --description "Blocking the crawlers IP" \
    --expression "evaluateThreatIntelligence('iplist-search-engines-crawlers')" \
    --action deny-403 \
    --preview

    RULE_STATUS=$?
    if [[ $RULE_STATUS -ne 0 ]]; then
        echo "Error creating rule 111 in project:--- $PROJECT ---. Likely quota issue or Policy doesn't exist"
        ERROR_PROJECTS+=("$PROJECT")
        continue #i need the execution to stop and go to next item(project-id) in list
    fi


  # Cloud Armor Rule
  gcloud compute security-policies rules create 112 \
    --security-policy $CA_POLICY \
    --description "Prevention from Java Based Attack" \
    --expression "evaluatePreconfiguredWaf('java-v33-stable')" \
    --action deny-403 \
    --preview

    RULE_STATUS=$?
    if [[ $RULE_STATUS -ne 0 ]]; then
        echo "Error creating rule 112 in project:--- $PROJECT ---. Likely quota issue or Policy doesn't exist"
        ERROR_PROJECTS+=("$PROJECT")
        continue #i need the execution to stop and go to next item(project-id) in list
    fi


  # Cloud Armor Rule
  gcloud compute security-policies rules create 113 \
    --security-policy $CA_POLICY \
    --description "Prevention from Node Based Attack" \
    --expression "evaluatePreconfiguredWaf('nodejs-v33-stable')" \
    --action deny-403 \
    --preview

    RULE_STATUS=$?
    if [[ $RULE_STATUS -ne 0 ]]; then
        echo "Error creating rule 113 in project:--- $PROJECT ---. Likely quota issue or Policy doesn't exist"
        ERROR_PROJECTS+=("$PROJECT")
        continue #i need the execution to stop and go to next item(project-id) in list
    fi


  # Cloud Armor Rule
  gcloud compute security-policies rules create 114 \
    --security-policy $CA_POLICY \
    --description "Prevention from WAF bypass by appending JSON syntax to SQL injection payloads." \
    --expression "evaluatePreconfiguredWaf('json-sqli-canary')" \
    --action deny-403 \
    --preview

    RULE_STATUS=$?
    if [[ $RULE_STATUS -ne 0 ]]; then
        echo "Error creating rule 114 in project:--- $PROJECT ---. Likely quota issue or Policy doesn't exist"
        ERROR_PROJECTS+=("$PROJECT")
        continue #i need the execution to stop and go to next item(project-id) in list
    fi

done

if [[ ${#ERROR_PROJECTS[@]} -gt 0 ]]; then
  echo "Projects with errors:"
  for PROJECT_ID in "${ERROR_PROJECTS[@]}"; do
    echo "$PROJECT_ID"
  done
else
  echo "Done! added New policies where possible."
fi
 
