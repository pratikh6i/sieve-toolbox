import requests
import google.auth
from google.auth.transport.requests import Request

# ─── CONFIGURATION ───────────────────────────────────────────────────────────
# Your Google Apps Script Web App URL (obtained after deploying as web app)
APPS_SCRIPT_URL = "https://script.google.com/macros/s/YOUR_DEPLOYMENT_ID/exec"

# A shared secret key used by the Apps Script to validate incoming requests
AUTH_KEY = "YOUR_AUTH_KEY"

EMAIL_RECIPIENT = "recipient@example.com"
EMAIL_SUBJECT = "Automated Email from GCP"
EMAIL_BODY = "This email was sent using native Google Auth libraries, not gcloud CLI."
# ─────────────────────────────────────────────────────────────────────────────

# 1. Get the credentials from the environment (Standard GCP ADC)
credentials, project = google.auth.default()

# 2. Refresh the token to ensure it's valid
credentials.refresh(Request())
token = credentials.token

payload = {
    "auth_key": AUTH_KEY,
    "recipient": EMAIL_RECIPIENT,
    "subject": EMAIL_SUBJECT,
    "body": EMAIL_BODY
}

headers = {
    "Authorization": f"Bearer {token}"
}

# 3. Send the request to the Apps Script endpoint
try:
    response = requests.post(APPS_SCRIPT_URL, json=payload, headers=headers)
    print("Status:", response.status_code)
    # Check for success (200) or Redirect (302 — Apps Script sometimes redirects)
    if response.status_code in [200, 302]:
        print("Email Sent Successfully")
    else:
        print("Error:", response.text)
except Exception as e:
    print(f"Exception: {e}")
