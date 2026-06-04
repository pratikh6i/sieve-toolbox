#!/bin/bash

# Ensure jq is installed. If not, install it using: sudo apt-get install jq (Debian/Ubuntu) or brew install jq (macOS)
if ! command -v jq &> /dev/null
then
    echo "jq could not be found. Please install it to use this script (e.g., sudo apt-get install jq or brew install jq)."
    exit 1
fi

# Check if at least one instance name is provided as an argument
if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <instance_name_1> <instance_name_2> ... <instance_name_N>"
    echo "Example: $0 my-sql-instance-1 my-sql-prod-db my-dev-sql-cluster"
    exit 1
fi

echo "Analyzing network configurations for specified Cloud SQL instances:"

for INSTANCE_NAME in "$@"; do
  echo "--------------------------------------------------------"
  echo "Instance: $INSTANCE_NAME"

  # Get detailed information about the instance in JSON format
  INSTANCE_DETAILS=$(gcloud sql instances describe "$INSTANCE_NAME" --format=json 2>/dev/null)

  # Check if the instance exists
  if [ $? -ne 0 ]; then
    echo "  Error: Instance '$INSTANCE_NAME' not found or you don't have permissions to access it."
    continue # Skip to the next instance
  fi

  # Check for Public IP and Authorized Networks
  PUBLIC_IP_ENABLED=$(echo "$INSTANCE_DETAILS" | jq -r '.settings.ipConfiguration.ipv4Enabled // "false"') # Default to "false" if field is missing

  if [ "$PUBLIC_IP_ENABLED" = "true" ]; then
    echo "  Connectivity Type: Public IP"
    AUTHORIZED_NETWORKS=$(echo "$INSTANCE_DETAILS" | jq -r '.settings.ipConfiguration.authorizedNetworks[]?.value')

    if [ -n "$AUTHORIZED_NETWORKS" ]; then
      echo "  Authorized Networks:"
      ALL_OPEN=false
      for NETWORK in $AUTHORIZED_NETWORKS; do
        echo "    - $NETWORK"
        if [ "$NETWORK" = "0.0.0.0/0" ] || [ "$NETWORK" = "::/0" ]; then
          echo "      -> WARNING: This instance is open to all public IPs. This is a significant security risk!"
          ALL_OPEN=true
        fi
      done
      if [ "$ALL_OPEN" = "false" ]; then
        echo "      -> Only specific IPs are authorized for public access."
      fi
    else
      echo "  Authorized Networks: None specified. Public IP is enabled but no authorized networks configured, meaning it's likely inaccessible via public IP from the internet."
    fi
  else # Private IP (VPC)
    echo "  Connectivity Type: Private IP (VPC)"
    VPC_NETWORK_FULL_PATH=$(echo "$INSTANCE_DETAILS" | jq -r '.settings.ipConfiguration.privateNetwork // "N/A"')

    if [ "$VPC_NETWORK_FULL_PATH" != "N/A" ] && [ "$VPC_NETWORK_FULL_PATH" != "null" ]; then
      # Extract just the VPC network name from the full path
      VPC_NETWORK_NAME=$(basename "$VPC_NETWORK_FULL_PATH")
      echo "  VPC Network: $VPC_NETWORK_NAME"
      echo "  Private Service Access is configured."
      
      DATABASE_VERSION=$(echo "$INSTANCE_DETAILS" | jq -r '.databaseVersion // "UNKNOWN"')
      DB_PORT=""
      if [[ "$DATABASE_VERSION" == *"MYSQL"* ]]; then
        DB_PORT="3306"
      elif [[ "$DATABASE_VERSION" == *"POSTGRES"* ]]; then
        DB_PORT="5432"
      elif [[ "$DATABASE_VERSION" == *"SQLSERVER"* ]]; then
        DB_PORT="1433"
      fi

      echo "  Typical Database Port: ${DB_PORT:-Default (check documentation for specific database type: $DATABASE_VERSION)}"
      echo "  Access is controlled by VPC network peering and your VPC's firewall rules for network '$VPC_NETWORK_NAME'."
      echo "  Analyzing Firewall Rules for Network '$VPC_NETWORK_NAME' (Ingress rules only, relevant to incoming connections):"
      echo "  --------------------------------------------------------"

      # Fetch firewall rules for the associated VPC network
      # Filter for ingress rules, and those that allow connections
      FIREWALL_RULES=$(gcloud compute firewall-rules list \
        --filter="network:\"$VPC_NETWORK_NAME\" AND direction=INGRESS AND allowed:* AND disabled=false" \
        --format=json 2>/dev/null)

      if [ -n "$FIREWALL_RULES" ] && [ "$(echo "$FIREWALL_RULES" | jq 'length')" -gt 0 ]; then
        echo "$FIREWALL_RULES" | jq -r '
          .[] |
          "    Rule Name: \(.name)",
          "      Priority: \(.priority)",
          "      Action: \(.action)",
          "      Source IP Ranges: \([.sourceRanges[]?])",
          "      Source Tags: \([.sourceTags[]?])",
          "      Target Tags: \([.targetTags[]?])",
          "      Target Service Accounts: \([.targetServiceAccounts[]?])",
          "      Allowed Protocols/Ports: \(
              if .allowed | length > 0 then
                  ([.allowed[] | "\(.IPProtocol):\(if .ports then .ports[] else "All" end)"] | join(", "))
              else
                  "None"
              end
          )",
          (if ([.sourceRanges[]?]) | contains(["0.0.0.0/0"]) then "      -> WARNING: This firewall rule allows traffic from ALL IP addresses (0.0.0.0/0)!" else "" end),
          "--------------------------------------------------------"
        '
      else
        echo "    No active, allowing ingress firewall rules found for this VPC network that could affect Cloud SQL access."
        echo "    This instance might be isolated, or access is implicitly allowed (e.g., within the same network/subnet without explicit rules)."
      fi
    else
      echo "  VPC Network: Not configured for Private IP. This instance might not be publicly accessible or has no network configuration set (unusual for an active instance)."
    fi
  fi
  echo "" # Add a newline for better readability between instances
done

echo "--------------------------------------------------------"
echo "Summary Complete."
echo "Remember that the interpretation of firewall rules requires understanding your VPC topology, including subnets, routing, and other services connecting to the Cloud SQL instance." 
