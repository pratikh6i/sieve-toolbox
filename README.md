# Sieve Toolbox

A systematically organized repository of cloud security scripts, automations, and architectural systems.

## Repository Blueprint

This repository is organized by function to ensure scalability and ease of navigation:

*   **`security-auditing/`**: Security assessment, vulnerability scanning, and auditing configurations (e.g., WAF testing, compute instance security, Cloud Armor policies).
*   **`network-security/`**: Scripts and configurations for network security controls (e.g., Firewall rules, SSL policies).
*   **`iam-management/`**: Identity and Access Management configurations, role bindings, and permission processors.
*   **`storage/`**: Secure cloud storage configurations and access policies.
*   **`cloud-run/`**: Serverless security scanning and container/service configuration audits.
*   **`google-sheets-utilities/`**: Automation scripts and helpers interacting with Google Sheets for reporting and tracking.

## Operational Workflow

1.  **Duplicate Check & Merge (90% Similarity Rule)**: All incoming scripts are checked against existing ones. Updates or optimizations are merged into the existing files.
2.  **Clean & Rename**: Filenames are kept lowercase, hyphenated, and professional (e.g., `disable-icmp-org.sh`).
3.  **Sanitization**: Hardcoded secrets, project IDs, and personal domains are replaced with obvious placeholders (e.g., `YOUR_PROJECT_ID`).
4.  **Documentation**: Every script or subdirectory contains a concise `README.md` detailing its purpose, prerequisites, usage, and variables to change.
