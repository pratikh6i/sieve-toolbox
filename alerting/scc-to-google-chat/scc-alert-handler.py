import base64
import json
import requests

# ─── CONFIGURATION ───────────────────────────────────────────────────────────
# Set the webhook URL for each severity level.
# Get your webhook URL from: Google Chat Space → Apps & Integrations → Webhooks
WEBHOOK_URLS = {
    "CRITICAL": "YOUR_GOOGLE_CHAT_WEBHOOK_URL_FOR_CRITICAL",
    "HIGH":     "YOUR_GOOGLE_CHAT_WEBHOOK_URL_FOR_HIGH",
    # "MEDIUM":  "YOUR_GOOGLE_CHAT_WEBHOOK_URL_FOR_MEDIUM",
    # "LOW":     "YOUR_GOOGLE_CHAT_WEBHOOK_URL_FOR_LOW",
}
# ─────────────────────────────────────────────────────────────────────────────


def send_message(message: dict, webhook_url: str) -> None:
    """Posts a message payload to a Google Chat webhook URL."""
    headers = {'Content-Type': 'application/json; charset=UTF-8'}
    response = requests.post(webhook_url, headers=headers, json=message)
    response.raise_for_status()


def prepare_message(incident_json: dict) -> str:
    """Formats an SCC finding notification into a Google Chat message string."""
    project_id = incident_json['resource']['gcpMetadata']['projectDisplayName']
    finding_category = incident_json['finding']['category']
    html_finding_category = finding_category.replace(" ", "%20")

    # Deep-link to SCC Findings console filtered to this specific category
    findings_link = (
        f"https://console.cloud.google.com/security/command-center/findingsv2"
        f";filter=state%3D%22ACTIVE%22%0AAND%20NOT%20mute%3D%22MUTED%22"
        f"%0AAND%20resource.gcp_metadata.project_display_name%3D%22{project_id}%22"
        f"%0AAND%20category%3D%22{html_finding_category}%22"
        f";timeRange=P7D?project={project_id}&supportedpurview=organizationId,folder,project"
    )

    return (
        f"\nProject ID: {project_id}\n\n"
        f"Resource: {incident_json['resource']['displayName']}\n\n"
        f"Finding Category: {finding_category}\n\n"
        f"Severity: {incident_json['finding']['severity']}\n\n"
        f"Description: {incident_json['finding']['description']}\n\n"
        f"Link to finding: {findings_link}"
    )


def hello_pubsub(event, context):
    """
    Cloud Function entry point.
    Triggered by a Pub/Sub message published by an SCC notification config.
    """
    pubsub_message = base64.b64decode(event['data']).decode('utf-8')
    incident_json = json.loads(pubsub_message)
    finding_severity = incident_json['finding']['severity']

    webhook_url = WEBHOOK_URLS.get(finding_severity)
    if webhook_url:
        message = {"text": prepare_message(incident_json)}
        send_message(message, webhook_url)
