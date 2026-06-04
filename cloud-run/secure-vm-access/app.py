from flask import Flask
import requests 
import os       

app = Flask(__name__)

# These will be set by Cloud Run later. Defaults are for if you test elsewhere.
TARGET_VM_IP = os.environ.get("TARGET_VM_IP", "YOUR_VM_INTERNAL_IP") # IMPORTANT: Cloud Run will set this from env variables
TARGET_VM_PORT = os.environ.get("TARGET_VM_PORT", "80")
TARGET_FILE_PATH = os.environ.get("TARGET_FILE_PATH", "index.html")

TARGET_URL = f"http://{TARGET_VM_IP}:{TARGET_VM_PORT}/{TARGET_FILE_PATH}"

@app.route('/')
def home():
    return f"Cloud Run App is running. It will try to fetch from: {TARGET_URL} when you visit /fetch_vm_file"

@app.route('/fetch_vm_file') # This is the specific URL you'll visit on your Cloud Run app
def fetch_vm_file_from_target():
    try:
        response = requests.get(TARGET_URL, timeout=10)
        response.raise_for_status() 
        return response.text, 200, {'Content-Type': response.headers.get('Content-Type', 'text/html')}
    except requests.exceptions.RequestException as e:
        return f"Error connecting to or getting file from Target VM: {str(e)}<br/>Tried to fetch: {TARGET_URL}", 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port)
