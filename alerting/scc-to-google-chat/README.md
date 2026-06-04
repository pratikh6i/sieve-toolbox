# SCC to Google Chat Alerter

A Google Cloud Function that subscribes to an SCC (Security Command Center) Pub/Sub notification topic and forwards new findings to a Google Chat space via webhook.

## Purpose

Delivers real-time SCC security alerts to a Google Chat space, filtered by severity (CRITICAL/HIGH). Each message includes project ID, resource, category, severity, description, and a deep-link to the SCC findings console.

## Architecture

```
SCC Finding (ACTIVE)
        │
        ▼
Pub/Sub Notification Config
        │
        ▼
Cloud Function (hello_pubsub)
        │
        ▼
Google Chat Webhook → Chat Space
```

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| GCP Project | Cloud Functions enabled |
| SCC Notification Config | Configured to publish to a Pub/Sub topic |
| Google Chat Webhook | Created in target Chat space |

## Configuration

Edit the `WEBHOOK_URLS` dictionary at the top of `scc-alert-handler.py`:

```python
WEBHOOK_URLS = {
    "CRITICAL": "https://chat.googleapis.com/v1/spaces/YOUR_SPACE_ID/messages?key=...&token=...",
    "HIGH":     "https://chat.googleapis.com/v1/spaces/YOUR_SPACE_ID/messages?key=...&token=...",
}
```

You can set different webhook URLs for different severity levels to route alerts to different spaces.

## Deployment

```bash
# Create the Pub/Sub topic
gcloud pubsub topics create scc-findings

# Create SCC notification config
gcloud scc notifications create scc-findings-notif \
  --organization YOUR_ORG_ID \
  --pubsub-topic projects/YOUR_PROJECT_ID/topics/scc-findings \
  --filter "state=ACTIVE AND severity=CRITICAL"

# Deploy Cloud Function
gcloud functions deploy scc-alert-handler \
  --runtime python311 \
  --entry-point hello_pubsub \
  --trigger-topic scc-findings \
  --region YOUR_REGION
```

## Requirements

```bash
pip install requests
```

Add to your Cloud Function's `requirements.txt`:
```
requests>=2.31.0
```
