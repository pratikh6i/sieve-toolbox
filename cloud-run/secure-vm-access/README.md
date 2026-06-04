# Securely Accessing VM Resources from Cloud Run using Internal IP

## Purpose
This guide and Proof of Concept (PoC) application demonstrate how to configure secure, private outbound communication from a serverless Google Cloud Run service to a Compute Engine virtual machine (VM) instance using its internal (RFC 1918) IP address.

By routing outbound traffic through a Serverless VPC Access connector or Direct VPC Egress, Cloud Run service requests bypass the public internet when reaching internal VPC resources.

---

## Target Variables to Change
*   **Artifact Registry Image URI**: Update the project and repository details in your build and push commands:
    *   `us-central1-docker.pkg.dev/YOUR_PROJECT_ID/YOUR_REPOSITORY/YOUR_IMAGE_NAME:TAG`
*   **Environment Variables** (Configured on the Cloud Run service):
    *   `TARGET_VM_IP`: Set to your internal VM IP (e.g., `10.x.x.x`).
    *   `TARGET_VM_PORT`: Port VM web server is listening on (defaults to `80`).
    *   `TARGET_FILE_PATH`: Target resource to fetch (defaults to `index.html`).
*   **Service URL**: Use your generated Cloud Run URL to verify (e.g., `https://YOUR-CLOUD-RUN-URL.a.run.app`).

---

## Prerequisites
*   **CLI Tools**: `gcloud` SDK and `docker` CLI.
*   **IAM Roles**:
    *   `Artifact Registry Writer` to push images.
    *   `Cloud Run Developer` to deploy the service.
    *   `Serverless VPC Access User` / `Compute Network User` to configure VPC egress.

---

## Deployment and Configuration Steps

### 1. Network Setup
1. Create a Virtual Private Cloud (VPC) network.
2. Configure ingress firewall rules to allow:
    *   SSH traffic (TCP port 22) for VM management.
    *   HTTP traffic (TCP port 80) from the Cloud Run VPC connector or subnet range.

### 2. Virtual Machine (VM) Setup
1. Create a new Compute Engine VM instance in your VPC.
2. Connect to the VM via SSH and install Apache2:
   ```bash
   sudo apt-get update
   sudo apt-get install -y apache2
   ```
3. Create a basic HTML file:
   ```bash
   echo '<html><body><h1>Hello From VM</h1></body></html>' | sudo tee /var/www/html/index.html
   ```

### 3. Artifact Registry Setup
1. Create a Docker repository in Artifact Registry.
2. Authenticate Docker locally:
   ```bash
   gcloud auth configure-docker us-central1-docker.pkg.dev
   ```
3. Build the Docker image from this directory:
   ```bash
   docker build -t us-central1-docker.pkg.dev/YOUR_PROJECT_ID/YOUR_REPOSITORY/secure-vm-client:v1 .
   ```
4. Push the image:
   ```bash
   docker push us-central1-docker.pkg.dev/YOUR_PROJECT_ID/YOUR_REPOSITORY/secure-vm-client:v1
   ```

### 4. Cloud Run Setup
1. Create a Cloud Run service (2nd Generation) using the pushed image.
2. Set the environment variables on the service:
   *   `TARGET_VM_IP` = `<your_vm_internal_ip>`
   *   `TARGET_VM_PORT` = `80`
   *   `TARGET_FILE_PATH` = `index.html`
3. Under **Network settings**:
   *   Select **Connect to a VPC for outbound traffic**.
   *   Select **Send traffic directly to a VPC** (Direct VPC Egress) or configure a VPC Access Connector.
   *   Assign the same network and subnet as the VM.

### 5. Testing the Integration
1. Retrieve an identity token for authentication:
   ```bash
   TOKEN=$(gcloud auth print-identity-token)
   ```
2. Send an authenticated request to the Cloud Run endpoint:
   ```bash
   curl -H "Authorization: Bearer ${TOKEN}" https://YOUR-CLOUD-RUN-URL.run.app/fetch_vm_file
   ```
   **Expected Response**: `Hello From VM`
